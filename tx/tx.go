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

package tx

import (
	"errors"
	"log"
	"sync"

	"bytes"

	"fmt"

	"github.com/monarj/wallet/key"
	"github.com/monarj/wallet/msg"
)

var (
	coins = make(map[string]Coins)
	mutex sync.RWMutex
)

//Coins is array of coins.
type Coins []*Coin

//Len returns len of coins.
func (c Coins) Len() int {
	return len(c)
}

//Less returns true if coins[i]<coins[j]
func (c Coins) Less(i, j int) bool {
	return c[i].Value < c[j].Value
}

//Swap swaps c[i] and c[j]
func (c Coins) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
}

//Coin represents an available transaction.
type Coin struct {
	Addr    []byte
	TxHash  []byte
	TxIndex uint32
	Value   uint64
}

func add(pub *key.PublicKey, tx *msg.Tx, index uint32) {
	mutex.Lock()
	defer mutex.Unlock()
	a := pub.Serialize()
	c := &Coin{
		Addr:    a,
		TxHash:  tx.Hash(),
		TxIndex: index,
		Value:   tx.TxOut[index].Value,
	}
	coins[string(a)] = append(coins[string(a)], c)
}

func remove(pub *key.PublicKey, hash []byte, index uint32) {
	mutex.Lock()
	defer mutex.Unlock()
	a := string(pub.Serialize())
	coin := coins[a]
	for i, c := range coin {
		if bytes.Equal(c.TxHash, hash) && c.TxIndex == index {
			copy(coin[i:], coin[:i+1])
			coin[len(coin)-1] = nil
			coin = coin[:len(coin)-1]
		}
	}
}

//ScriptSig is the default scriptsig this program supports.
type ScriptSig struct {
	SigLength byte
	Prefix30  byte
	RSLength  byte
	PrefixR02 byte
	RLength   byte
	R         []byte `len:"var"`
	PrefixL02 byte
	LLength   byte
	L         []byte `len:"var"`
	Postfix01 byte
	PubLength byte
	Pubkey    []byte `len:"var"`
}

//Script the default out scrip this program supports.
type Script struct {
	Dup        byte
	Hash160    byte
	HashLength byte
	PubHash    []byte `len:"20"`
	Equal      byte
	CheckSig   byte
}

func parse(s interface{}, data []byte) error {
	buf := bytes.NewBuffer(data)
	if err := msg.Unpack(buf, &s); err != nil {
		return fmt.Errorf("this tx is not supported")
	}
	if buf.Len() != 0 {
		return fmt.Errorf("this tx is not supported")
	}
	return nil
}

//Add adds or removes transanctions from a tx packet.
func Add(mtx *msg.Tx) error {
	if mtx.Locktime != 0xffffffff {
		return errors.New("locktime is not supported")
	}
	for _, in := range mtx.TxIn {
		s := ScriptSig{}
		if err := parse(&s, in.Script); err != nil {
			log.Println(err, mtx.Hash())
			continue
		}
		pubkey, err := checkTxin(&s)
		if err != nil {
			return err
		}
		remove(pubkey, in.Hash, in.Index)

	}
	for i, in := range mtx.TxOut {
		s := Script{}
		if err := parse(&s, in.Script); err != nil {
			log.Println(err, mtx.Hash())
			continue
		}
		pubkey, err := checkTxout(&s)
		if err != nil {
			log.Println(err, mtx.Hash())
			continue
		}
		add(pubkey, mtx, uint32(i))
	}
	return nil
}

func checkTxin(s *ScriptSig) (*key.PublicKey, error) {
	switch {
	case s.Prefix30 != 0x30:
		fallthrough
	case s.PrefixR02 != 0x02:
		fallthrough
	case s.PrefixL02 != 0x02:
		fallthrough
	case s.Postfix01 != 0x01:
		return nil, errors.New("unsuported scriptsig")
	}
	pubkey, err := key.GetPublicKey(s.Pubkey)
	if err != nil {
		return nil, err
	}
	if key.HasPubkey(pubkey) {
		return nil, errors.New("not concerened address")
	}
	return pubkey, nil
}

func checkTxout(s *Script) (*key.PublicKey, error) {
	switch {
	case s.Dup != opDUP:
		fallthrough
	case s.Hash160 != opHASH160:
		fallthrough
	case s.HashLength != 0x14:
		fallthrough
	case s.Equal != opEQUAL:
		fallthrough
	case s.CheckSig != opCHECKSIG:
		return nil, errors.New("unsuported scriptsig")
	}
	pubkey, has := key.HasPubHash(s.PubHash)
	if !has {
		return nil, errors.New("not concerened address")
	}
	return pubkey, nil
}
