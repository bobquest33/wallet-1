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

	"golang.org/x/crypto/ripemd160"

	"github.com/monarj/wallet/block"
	"github.com/monarj/wallet/bloom"
	"github.com/monarj/wallet/key"
	"github.com/monarj/wallet/msg"
	"github.com/monarj/wallet/myself"
	"github.com/monarj/wallet/params"
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

func (n *Node) writeGetblocks() error {
	h := block.LocatorHash()
	po := msg.Getblocks{
		Version:   params.ProtocolVersion,
		HashCount: msg.VarInt(len(h)),
		LocHashes: h,
		HashStop:  nil,
	}
	err := n.writeMessage("getblocks", po)
	log.Println("sended getblocks")
	return err
}

func (n *Node) writeFilterload() error {
	bf := bloom.New()
	klist := key.Get()
	h := ripemd160.New()
	for _, k := range klist {
		_, adr := k.Pub.GetAddress()
		bf.Insert(adr)
		if _, err := h.Write(adr); err != nil {
			return err
		}
		bf.Insert(h.Sum(nil))
		h.Reset()
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
		log.Printf("%d %x\n", inv.Type, reverse(inv.Hash))
	}
	return nil
}

func reverse(bs []byte) []byte {
	for i := 0; i < len(bs)/2; i++ {
		bs[i], bs[len(bs)-1-i] = bs[len(bs)-1-i], bs[i]
	}
	return bs
}
