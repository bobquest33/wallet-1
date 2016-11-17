/*
 * Copyright (c) 2016, Shinya Yagyu
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package node

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"time"

	"github.com/monarj/wallet/behex"
	"github.com/monarj/wallet/block"
	"github.com/monarj/wallet/bloom"
	"github.com/monarj/wallet/key"
	"github.com/monarj/wallet/msg"
	"github.com/monarj/wallet/myself"
	"github.com/monarj/wallet/params"
	"github.com/monarj/wallet/tx"
)

//ReadMessage read a message packet from buf and returns
//cmd and payload.
func (n *Node) readMessage() (string, *bytes.Buffer, error) {
	var message msg.Message
	if err := msg.Unpack(n.conn, &message); err != nil {
		log.Println(err)
		return "", nil, err
	}
	h := sha256.Sum256(message.Payload)
	h = sha256.Sum256(h[:])
	if !bytes.Equal(message.Magic, params.PacketMagic) {
		return "", nil, fmt.Errorf("magic unmatch %x %x", message.Magic, params.PacketMagic)
	}
	if !bytes.Equal(message.CheckSum, h[:4]) {
		return "", nil, fmt.Errorf("checksum unmatch %x %x", message.CheckSum, h[:4])
	}
	return message.GetCommand(), bytes.NewBuffer(message.Payload), nil
}

//writeMessage writes payload in message packet.
func (n *Node) writeMessage(cmd string, payload interface{}) error {
	var buf bytes.Buffer
	if err := msg.Pack(&buf, payload); err != nil {
		return err
	}
	dat := buf.Bytes()
	h := sha256.Sum256(dat)
	h = sha256.Sum256(h[:])
	message := msg.Message{
		Magic:    params.PacketMagic,
		Command:  []byte(cmd),
		Length:   uint32(len(dat)),
		CheckSum: h[:4],
		Payload:  dat,
	}
	return msg.Pack(n.conn, message)
}

//parseVersion makes and returs version struct from payload with checking it.
func (n *Node) parseVersion(payload io.Reader) (*msg.Version, error) {
	version := msg.Version{}
	if err := msg.Unpack(payload, &version); err != nil {
		return nil, err
	}
	if version.Version < params.ProtocolVersion {
		return nil, errors.New("Version is old")
	}
	n.LastBlock = version.StartHeight
	myself.SetIP(version.AddrRecv.IPv6)
	return &version, nil
}

//writeVersion createsand send a verson packet.
func (n *Node) writeVersion() error {
	nonce := uint64(rand.Int63())
	r, err := msg.NewNetAddr(n.conn.RemoteAddr().String(), 0)
	if err != nil {
		return err
	}
	f, err := msg.NewNetAddr(myself.Get().String(), 0)
	if err != nil {
		return err
	}
	ver := msg.Version{
		Version:     params.ProtocolVersion,
		Service:     0, // NODE_NETWORK
		Timestamp:   uint64(time.Now().Unix()),
		AddrRecv:    *r,
		AddrFrom:    *f,
		Nonce:       nonce,
		UserAgent:   params.UserAgent,
		StartHeight: 0,
		Relay:       0,
	}
	return n.writeMessage("version", ver)
}

func (n *Node) pongAfterReadPing(payload io.Reader) error {
	p := msg.Ping{}
	if err := msg.Unpack(payload, &p); err != nil {
		return err
	}
	po := msg.Pong{Nonce: p.Nonce}
	err := n.writeMessage("pong", po)
	log.Println("ponged err=", err)
	return err
}

func (n *Node) writePing() error {
	n.lastPing = uint64(rand.Int63())
	po := msg.Ping{Nonce: n.lastPing}
	err := n.writeMessage("ping", po)
	log.Println("sended ping")
	return err
}

func (n *Node) readPong(payload io.Reader) error {
	p := msg.Pong{}
	if err := msg.Unpack(payload, &p); err != nil {
		return err
	}
	if p.Nonce != n.lastPing {
		return errors.New("nonce unmatched in pong")
	}
	return nil
}

func (n *Node) writeGetheaders() error {
	h := block.LocatorHash()
	po := msg.Getheaders{
		Version:   params.ProtocolVersion,
		HashCount: msg.VarInt(len(h)),
		LocHashes: h,
		HashStop:  nil,
	}
	err := n.writeMessage("getheaders", po)
	log.Println("sended getheaders")
	return err
}

func (n *Node) writeFilterload() error {
	bf := bloom.New()
	klist := key.Get()
	for _, k := range klist {
		_, adr := k.Address()
		bf.Insert(k.PublicKey.Serialize())
		bf.Insert(adr)
	}
	aa := make([]byte, 512)
	for i := 0; i < 512; i++ {
		aa[i] = 0xff
	}
	po := msg.FilterLoad{
		NFilter: msg.VarInt(bloom.Bytelen),
		//Filter:  []byte(bf),
		Filter: aa,

		NhashFuncs: bloom.HashFuncs,
		NTweak:     bloom.Tweak,
		Nflags:     1,
	}
	err := n.writeMessage("filterload", po)
	log.Println("sended filterload")
	return err
}

func (n *Node) readInv(payload io.Reader) error {
	p := msg.Inv{}
	if err := msg.Unpack(payload, &p); err != nil {
		return err
	}
	for _, inv := range p.Inventory {
		log.Printf("msgtx %s", behex.EncodeToString(inv.Hash))
		switch inv.Type {
		case msg.MsgTX:
			//ignore because we cannot check the validity
		case msg.MsgBlock:
			if err := n.writeGetheaders(); err != nil {
				return err
			}
		case msg.MsgFilterdBlock:
		//can do nothing because of SPV.
		default:
			return fmt.Errorf("unknown inv type %d", inv.Type)
		}
	}
	return nil
}

func makeInv(t uint32, hash [][]byte) msg.Inv {
	vec := make([]msg.InvVec, len(hash))
	for i, h := range hash {
		vec[i].Type = t
		vec[i].Hash = h
	}
	return msg.Inv{
		Count:     msg.VarInt(len(hash)),
		Inventory: vec,
	}
}

func (n *Node) writeInv(t uint32, hash [][]byte) error {
	po := makeInv(t, hash)
	err := n.writeMessage("inv", po)
	log.Println("sended inv")
	return err
}

func (n *Node) writeGetdata(t uint32, hash [][]byte) error {
	po := makeInv(t, hash)
	err := n.writeMessage("getdata", po)
	log.Println("sended getdata")
	return err
}

func (n *Node) readHeaders(payload io.Reader) error {
	p := msg.Headers{}
	if err := msg.Unpack(payload, &p); err != nil {
		return err
	}
	hashes, err := block.Add(p)
	if err != nil {
		return err
	}
	if err := n.writeGetdata(msg.MsgFilterdBlock, hashes); err != nil {
		return err
	}
	return nil
}

func (n *Node) readTx(payload io.Reader, txs []msg.Hash, height int) error {
	p := msg.Tx{}
	if err := msg.Unpack(payload, &p); err != nil {
		return err
	}
	ok := false
	for _, tx := range txs {
		if bytes.Equal(p.Hash(), tx.Hash) {
			ok = true
			break
		}
	}
	if !ok {
		return errors.New("no hash in txs")
	}
	err := tx.Add(&p, height)
	return err
}

func (n *Node) readMerkle(payload io.Reader) error {
	p := msg.Merkleblock{}
	if err := msg.Unpack(payload, &p); err != nil {
		return err
	}
	log.Println(behex.EncodeToString(p.Hash()))
	txs, err := p.FilteredTx()
	if err != nil {
		return err
	}
	if len(txs) == 0 {
		return nil
	}
	height := block.Height(p.Hash())
	if height < 0 {
		return errors.New("no merkle hash in the chain." + behex.EncodeToString(p.Hash()))
	}
	log.Println(len(txs), len(p.Hashes))
	for i := 0; i < len(txs); i++ {
		cmd, payload, err := n.readMessage()
		if err != nil {
			return err
		}
		if cmd != "tx" {
			return errors.New("cannot recieve tx packets")
		}
		if err = n.readTx(payload, txs, height); err != nil {
			return err
		}
	}
	log.Println("read merkle")
	return nil
}
