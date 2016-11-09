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
	"io"
	"log"
	"math/rand"
	"time"

	"github.com/monarj/wallet/params"
)

//Message is the header of message.
type Message struct {
	Magic    []byte `len:"4"`
	Command  []byte `len:"12"`
	Length   uint32
	CheckSum []byte `len:"4"`
	Payload  []byte `loc_of_len:"2"`
}

//ReadMessage read a message packet from buf and returns
//cmd and payload.
func ReadMessage(buf io.Reader) (string, *bytes.Buffer, error) {
	var message Message
	if err := Unpack(buf, &message); err != nil {
		return "", nil, err
	}
	h := sha256.Sum256(message.Payload)
	h = sha256.Sum256(h[:])
	if !bytes.Equal(message.CheckSum, h[:4]) {
		return "", nil, errors.New("checksum unmatch")
	}
	if !bytes.Equal(message.Magic, params.PacketMagic) {
		return "", nil, errors.New("magic unmatch")
	}
	str := bytes.TrimRight(message.Command, string([]byte{0}))
	return string(str), bytes.NewBuffer(message.Payload), nil
}

//WriteMessage writes payload in message packet.
func WriteMessage(conn io.Writer, cmd string, payload interface{}) error {
	var buf bytes.Buffer
	if err := Pack(&buf, payload); err != nil {
		return err
	}
	dat := buf.Bytes()
	h := sha256.Sum256(dat)
	h = sha256.Sum256(h[:])
	log.Println(h[:4])
	message := Message{
		params.PacketMagic,
		[]byte(cmd),
		uint32(len(dat)),
		h[:4],
		dat,
	}
	return Pack(conn, message)
}

//InvVec are used for notifying other nodes about objects
//they have or data which is being requested.
type InvVec struct {
	Type uint32
	Hash []byte `len:"32"`
}

//BlockHeaders are sent in a headers packet in response to a getheaders message.
type BlockHeaders struct {
	Version   uint32
	Prev      []byte `len:"32"`
	Merkle    []byte `len:"32"`
	Timestamp uint32
	Bits      []byte `len:"4"`
	Nonce     []byte `len:"4"`
	TxnCount  byte
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

//NewVersion makes and returs version struct from payload with checking it.
func NewVersion(payload io.Reader) (*Version, error) {
	version := Version{}
	if err := Unpack(payload, &version); err != nil {
		return nil, err
	}
	if version.Version < params.ProtocolVersion {
		return nil, errors.New("Version is old")
	}
	return &version, nil
}

//WriteVersion createsand send a verson packet.
func WriteVersion(buf io.Writer) error {
	nonce := uint64(rand.Int63())

	ver := Version{
		params.ProtocolVersion,
		0, // NODE_NETWORK
		uint64(time.Now().Unix()),
		NetAddr{},
		NetAddr{},
		nonce,
		params.UserAgent,
		0,
		0,
	}
	return WriteMessage(buf, "version", ver)
}

//Inv allows a node to advertise its knowledge of one or more objects
type Inv struct {
	Count     VarInt
	Inventory []InvVec `loc_of_len:"0"`
}

//GetData is used in response to inv, to retrieve the content of a
//specific object, and is usually sent after receiving an inv packe
type GetData Inv

//NotFound is a response to a getdata,
//sent if any requested data items could not be relayed
type NotFound Inv

//Hash represents hash.
type Hash struct {
	Hash []byte `len:"32"`
}

//Getblocks Return an inv packet containing the list of blocks
//starting right after the last known hash in the block locator object,
//up to hash_stop or 500 blocks, whichever comes first.
type Getblocks struct {
	Version   uint32
	HashCount VarInt
	LocHashes Hash   `loc_of_len:"0"`
	HashStop  []byte `len:"32"`
}

//GetHeaders Return a headers packet containing the headers of blocks
//starting right after the last known hash in the block locator object
//, up to hash_stop or2 000 blocks, whichever comes first.
type GetHeaders Getblocks

//Ping message is sent primarily to confirm that the TCP/IP connection is still valid
type Ping struct {
	Nonce uint64
}

//Pong message is sent in response to a ping message.
type Pong Ping

//Headers packet returns block headers in response to a getheaders packet.
type Headers struct {
	Count     VarInt
	Inventory []BlockHeaders `loc_of_len:"0"`
}

//TxIn is the info of input transaction.
type TxIn struct {
	Hash      []byte `len:"32"`
	Index     uint32
	ScriptLen VarInt
	Script    []byte `loc_of_len:"1"`
	Seq       uint32
}

//TxOut is the info of output transaction.
type TxOut struct {
	Value     uint64
	ScriptLen VarInt
	Script    []byte `loc_of_len:"1"`
}

//Tx describes a bitcoin transaction,
type Tx struct {
	Version  uint32
	InCount  VarInt
	TxIn     []TxIn `loc_of_len:"1"`
	OutCount VarInt
	TxOut    []TxOut `loc_of_len:"3"`
	Locktime uint32
}

//Addr provides information on known nodes of the network
type Addr struct {
	Count VarInt
	Dummy []NetAddrTime `loc_of_len:"0"`
}

//NetAddr represents network addres. for now it's just a dummy.
type NetAddr struct {
	Dummy []byte `len:"26"`
}

//NetAddrTime is NetAddr with time.
type NetAddrTime struct {
	Time  uint32
	Dummy []byte `len:"26"`
}

//BlockHeaders are sent in a headers packet in response to a getheaders message.
type Merkleblock struct {
	Version   uint32
	Prev      []byte `len:"32"`
	Merkle    []byte `len:"32"`
	Timestamp uint32
	Bits      []byte `len:"4"`
	Nonce     []byte `len:"4"`
	Total     uint32
	Nhash     byte
	Hashes    []Hash `loc_of_len:"7"`
	Nflags    byte
	Flags     []byte `loc_of_len:"9"`
}

//FilterLoad sets the current Bloom filter on the connection
type FilterLoad struct {
	Nfilter    byte
	Filter     []byte `loc_of_len:"0"`
	NhashFuncs uint32
	NTweak     uint32
	Nflags     byte
}

//FilterAdd adds the given data element to the connections
//current filter without requiring a completely new one to be set
type FilterAdd struct {
	Ndata byte
	Data  []byte `loc_of_len:"0"`
}
