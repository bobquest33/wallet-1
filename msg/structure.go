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

package msg

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"time"

	"golang.org/x/crypto/scrypt"

	"encoding/binary"

	"github.com/monarj/wallet/behex"
	"github.com/monarj/wallet/params"
)

//Object types for inv_vec.
const (
	MsgError uint32 = iota
	MsgTX
	MsgBlock
	MsgFilterdBlock
	MsgCmpctBlock
)

//Message is the header of message.
type Message struct {
	Magic    []byte `len:"4"`
	Command  []byte `len:"12"`
	Length   uint32
	CheckSum []byte `len:"4"`
	Payload  []byte `len:"var"`
}

//GetCommand converts Command field to string.
func (m *Message) GetCommand() string {
	return string(bytes.TrimRight(m.Command, "\x00"))
}

//InvVec are used for notifying other nodes about objects
//they have or data which is being requested.
type InvVec struct {
	Type uint32
	Hash []byte `len:"32"`
}

//HBlockHeader is header of block header.
type HBlockHeader struct {
	Version   uint32
	Prev      []byte `len:"32"`
	Merkle    []byte `len:"32"`
	Timestamp uint32
	Bits      uint32
	Nonce     []byte `len:"4"`
}

//BlockHeader are sent in a headers packet in response to a getheaders message.
type BlockHeader struct {
	HBlockHeader
	TxnCount byte
}

func (b *HBlockHeader) scrypt() []byte {
	var buf bytes.Buffer
	if err := Pack(&buf, *b); err != nil {
		log.Fatal(err)
	}
	bs := buf.Bytes()
	converted, err := scrypt.Key(bs, bs, 1024, 1, 1, 32)
	if err != nil {
		log.Fatal(err)
	}
	return converted
}

//Hash returns hash of the block.
func (b *HBlockHeader) Hash() []byte {
	return hash(*b)
}

func hash(b interface{}) []byte {
	var buf bytes.Buffer
	if err := Pack(&buf, b); err != nil {
		log.Fatal(err)
	}
	bs := buf.Bytes()
	h := sha256.Sum256(bs)
	h = sha256.Sum256(h[:])
	return h[:]
}

//target returns hash target by converting nBits.
func (b *HBlockHeader) target() []byte {
	bits := make([]byte, 4)
	binary.LittleEndian.PutUint32(bits, b.Bits)
	target := make([]byte, 32)
	target[bits[3]-1] = bits[2]
	target[bits[3]-2] = bits[1]
	target[bits[3]-3] = bits[0]
	return target
}

//IsOK returns error is something in header is wrong.
func (b *HBlockHeader) IsOK() error {
	sc := b.scrypt()
	if b.Bits > params.ProofOfWorkLimit {
		return fmt.Errorf("PoW limits is too easy %x > %x", b.Bits, params.ProofOfWorkLimit)
	}
	if b.Timestamp > uint32(time.Now().Unix()) {
		return errors.New("future packet")
	}
	if behex.Compare(b.target(), sc) < 0 {
		return errors.New("hash doesn't match target")
	}
	return nil
}

//Version is a version info nodes send first.
type Version struct {
	Version     uint32
	Service     uint64
	Timestamp   uint64
	AddrRecv    NetAddr
	AddrFrom    NetAddr
	Nonce       uint64
	UserAgent   string
	StartHeight uint32
	Relay       byte
}

//Inv allows a node to advertise its knowledge of one or more objects
type Inv struct {
	Count     VarInt
	Inventory []InvVec `len:"var"`
}

//Getdata is used in response to inv, to retrieve the content of a
//specific object, and is usually sent after receiving an inv packet.
type Getdata Inv

//NotFound is a response to a getdata,
//sent if any requested data items could not be relayed
type NotFound Inv

//Hash represents hash.
type Hash struct {
	Hash []byte `len:"32"`
}

//Getblocks returns an inv packet containing the list of blocks
//starting right after the last known hash in the block locator object,
//up to hash_stop or 500 blocks, whichever comes first.
type Getblocks struct {
	Version   uint32
	HashCount VarInt
	LocHashes []Hash `len:"var"`
	HashStop  []byte `len:"32"`
}

//Getheaders Return a headers packet containing the headers of blocks
//starting right after the last known hash in the block locator object
//, up to hash_stop or2 000 blocks, whichever comes first.
type Getheaders Getblocks

//Ping message is sent primarily to confirm that the TCP/IP connection is still valid
type Ping struct {
	Nonce uint64
}

//Pong message is sent in response to a ping message.
type Pong Ping

//Headers packet returns block headers in response to a getheaders packet.
type Headers struct {
	Count     VarInt
	Inventory []BlockHeader `len:"var"`
}

//TxIn is the info of input transaction.
type TxIn struct {
	Hash      []byte `len:"32"`
	Index     uint32
	ScriptLen VarInt
	Script    []byte `len:"var"`
	Seq       uint32
}

//TxOut is the info of output transaction.
type TxOut struct {
	Value     uint64
	ScriptLen VarInt
	Script    []byte `len:"var"`
}

//Tx describes a bitcoin transaction,
type Tx struct {
	Version  uint32
	InCount  VarInt
	TxIn     []TxIn `len:"var"`
	OutCount VarInt
	TxOut    []TxOut `len:"var"`
	Locktime uint32
}

//Hash returns hash of the tx.
func (b *Tx) Hash() []byte {
	return hash(*b)
}

//Addr provides information on known nodes of the network
type Addr struct {
	Count VarInt
	Addr  []NetAddrTime `len:"var"`
}

//NetAddr represents network addres. for now it's just a dummy.
type NetAddr struct {
	Service uint64
	IPv6    []byte `len:"16"`
	Port    uint16
}

//TCPAddr converts net.TCPAddr struct
func (a *NetAddr) TCPAddr() (*net.TCPAddr, error) {
	str := fmt.Sprintf("%s:%d", net.IP(a.IPv6).String(), a.Port)
	return net.ResolveTCPAddr("tcp", str)
}

//NewNetAddr returns NetAddr struct.
func NewNetAddr(adr string, s uint64) (*NetAddr, error) {
	a, err := net.ResolveTCPAddr("tcp", adr)
	if err != nil {
		return nil, err
	}
	return &NetAddr{
		Service: s,
		IPv6:    []byte(a.IP),
		Port:    uint16(a.Port),
	}, nil
}

//NetAddrTime is NetAddr with time.
type NetAddrTime struct {
	Time uint32
	Addr NetAddr
}

//Merkleblock represents a filtered block.
type Merkleblock struct {
	HBlockHeader
	Total  uint32
	Nhash  VarInt
	Hashes []Hash `len:"var"`
	NFlags VarInt
	Flags  []byte `len:"var"`
}

type merkle struct {
	height int
	hashes []Hash
	flags  *big.Int
	mask   int
	nHash  int
	tx     []Hash
	nleaf  int
	total  uint32
}

func (m *merkle) hash(stair int) (Hash, error) {
	m.mask++
	if stair == m.height {
		m.nleaf++
		if m.total&0x1 == 1 && m.nleaf == int(m.total+1) {
			return m.hashes[m.nHash-1], nil
		}
		if m.nleaf > int(m.total) {
			return Hash{}, errors.New("illegal merkle")
		}
	}
	if m.flags.Bit(m.mask-1) == 0 {
		m.nHash++
		return m.hashes[m.nHash-1], nil
	}
	if stair == m.height {
		m.tx = append(m.tx, m.hashes[m.nHash])
		m.nHash++
		return m.hashes[m.nHash-1], nil
	}
	hleft, err := m.hash(stair + 1)
	if err != nil {
		return Hash{}, nil
	}
	hright, err := m.hash(stair + 1)
	if err != nil {
		return Hash{}, nil
	}
	conc := append(hleft.Hash, hright.Hash...)
	sum := sha256.Sum256(conc)
	sum = sha256.Sum256(sum[:])
	return Hash{Hash: sum[:]}, nil
}

//FilteredTx checks merkleblock and returns filtered txs.
func (m *Merkleblock) FilteredTx() ([]Hash, error) {
	var height, count int
	//faster than log2?
	for height, count = 0, 1; count < int(m.Total); height++ {
		count *= 2
	}
	f := new(big.Int)
	f.SetBytes(m.Flags)
	me := merkle{
		height: height,
		hashes: m.Hashes,
		flags:  f,
		total:  m.Total,
	}
	mmm, err := me.hash(0)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(m.Merkle, mmm.Hash) {
		err = fmt.Errorf("merkle not match %s,%s",
			behex.EncodeToString(m.Merkle), behex.EncodeToString(mmm.Hash))
		return me.tx, err
	}
	if int(m.Nhash) != me.nHash {
		err = fmt.Errorf("not use all hashes %d %d", m.Nhash, me.nHash)
	}
	return me.tx, err
}

//FilterLoad sets the current Bloom filter on the connection
type FilterLoad struct {
	NFilter    VarInt
	Filter     []byte `len:"var"`
	NhashFuncs uint32
	NTweak     uint32
	Nflags     byte
}

//FilterAdd adds the given data element to the connections
//current filter without requiring a completely new one to be set
type FilterAdd struct {
	Ndata VarInt
	Data  []byte `len:"var"`
}
