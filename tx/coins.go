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
	"bytes"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"

	"github.com/monarj/wallet/behex"
	"github.com/monarj/wallet/key"
	"github.com/monarj/wallet/msg"
)

var (
	coins  = make(map[string]Coins)
	notify = make(map[string]chan *msg.Tx)
	mutex  sync.RWMutex
)

//AddNotify adds pubscript to be notified.
func AddNotify(pubscr []byte) chan *msg.Tx {
	ch := make(chan *msg.Tx)
	mutex.Lock()
	defer mutex.Unlock()
	notify[string(pubscr)] = ch
	return ch
}

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

//SortedCoins returns value-sorted coins that cointans all address.
func SortedCoins() Coins {
	mutex.RLock()
	defer mutex.RUnlock()
	var c Coins
	for _, v := range coins {
		c = append(c, v...)
	}
	sort.Sort(c)
	return c
}

//Coin represents an available transaction.
type Coin struct {
	Pubkey   []byte
	TxHash   []byte
	Value    uint64
	Ttype    int
	Height   int
	Script   []byte
	TxIndex  uint32
	Coinbase bool
}

func add(pub *key.PublicKey, tx *msg.Tx, index uint32,
	ttype int, height int, coinbase bool, script []byte) {
	mutex.Lock()
	defer mutex.Unlock()
	a := pub.Serialize()
	c := &Coin{
		Pubkey:   a,
		TxHash:   tx.Hash(),
		TxIndex:  index,
		Value:    tx.TxOut[index].Value,
		Ttype:    ttype,
		Height:   height,
		Coinbase: coinbase,
		Script:   script,
	}
	coins[string(a)] = append(coins[string(a)], c)
}

func remove(pub *key.PublicKey, hash []byte, index uint32) error {
	mutex.Lock()
	defer mutex.Unlock()
	a := string(pub.Serialize())
	coin := coins[a]
	for i, c := range coin {
		if bytes.Equal(c.TxHash, hash) && c.TxIndex == index {
			coin[i] = coin[len(coin)-1]
			coin[len(coin)-1] = nil
			coin = coin[:len(coin)-1]
			coins[a] = coin
			return nil
		}
	}
	return errors.New("coin was not found")
}

//ScriptSigH is the header of scriptsig this program supports.
type ScriptSigH struct {
	SigLength byte
	Prefix30  byte
	RSLength  byte
	PrefixR02 byte
	RLength   byte
	R         []byte `len:"var"`
	PrefixL02 byte
	SLength   byte
	S         []byte `len:"var"`
}

//ScriptSigT is the tail of  scriptsig this program supports.
type ScriptSigT struct {
	Postfix01 byte
	Length    byte
	Pubkey    []byte `len:"var"`
}

//Script the default out scrip this program supports.
type Script struct {
	Dup         byte
	Hash160     byte
	HashLength  byte
	PubHash     []byte `len:"20"`
	EqualVerify byte
	CheckSig    byte
}

//Script2 is P2SH script.
type Script2 struct {
	Length   byte
	Pubkey   []byte `len:"var"`
	CheckSig byte
}

func parse(s interface{}, data []byte) error {
	buf := bytes.NewBuffer(data)
	if err := msg.Unpack(buf, s); err != nil {
		return fmt.Errorf("this tx is not supported(unknown format) %s", err)
	}
	if buf.Len() != 0 {
		return fmt.Errorf("this tx is not supported")
	}
	return nil
}

func parseScriptsigH(data []byte) (*bytes.Buffer, error) {
	s := ScriptSigH{}
	buf := bytes.NewBuffer(data)
	if err := msg.Unpack(buf, &s); err != nil {
		return nil, errors.New("this tx is not supported(unknown format)")
	}
	if buf.Len() == 0 {
		return nil, errors.New("old type of scriptsig, ignoring")
	}
	switch {
	case s.Prefix30 != 0x30:
		fallthrough
	case s.PrefixR02 != 0x02:
		fallthrough
	case s.PrefixL02 != 0x02:
		return nil, errors.New("unsuported scriptsig")
	}
	return buf, nil
}

func parseScriptsigT(buf *bytes.Buffer, data []byte) (*ScriptSigT, error) {
	s := ScriptSigT{}
	if err := msg.Unpack(buf, &s); err != nil {
		return nil, errors.New("this tx is not supported(unknown format)")
	}
	if buf.Len() != 0 {
		return nil, fmt.Errorf("this tx is not supported")
	}
	return &s, nil
}

//Add adds or removes transanctions from a tx packet.
func Add(mtx *msg.Tx, height int) error {
	coinbase := false
	for _, in := range mtx.TxIn {
		zero := make([]byte, 32)
		if bytes.Equal(in.Hash, zero) && in.Index == 0xffffffff {
			log.Println("coinbase")
			coinbase = true
			break
		}
		buf, err := parseScriptsigH(in.Script)
		if err != nil {
			log.Println(err)
			continue
		}
		s, err := parseScriptsigT(buf, in.Script)
		if err != nil {
			log.Println(err)
			continue
		}
		pubkey, err := checkTxin(s)
		if err != nil {
			log.Println(err)
			continue
		}
		if err := remove(pubkey, in.Hash, in.Index); err != nil {
			log.Println(err)
		}
	}
	for i, in := range mtx.TxOut {
		for k, v := range notify {
			if bytes.Equal(in.Script, []byte(k)) {
				delete(notify, k)
				v <- mtx
			}
		}
		s1 := Script{}
		err1 := parse(&s1, in.Script)
		s2 := Script2{}
		err2 := parse(&s2, in.Script)

		var pubkey *key.PublicKey
		var err error
		var ttype int
		switch {
		case err1 == nil:
			log.Println("pubkeyhash scriptsig")
			pubkey, err = checkTxout(&s1)
			ttype = 0
		case err2 == nil:
			log.Println("pubkey scriptsig")
			pubkey, err = checkTxout2(&s2)
			ttype = 1
		default:
			log.Println(err1, err2)
			err = fmt.Errorf("This txout is not supproted")
		}
		if err != nil {
			log.Println(err, behex.EncodeToString(mtx.Hash()))
			continue
		}
		add(pubkey, mtx, uint32(i), ttype, height, coinbase, in.Script)
	}
	return nil
}

func checkTxin(s *ScriptSigT) (*key.PublicKey, error) {
	if s.Postfix01 != 0x01 {
		return nil, errors.New("unsuported scriptsig")
	}
	pubkey, err := key.NewPublicKey(s.Pubkey)
	if err != nil {
		return nil, err
	}
	if key.Find(pubkey) == nil {
		adr, _ := pubkey.Address()
		return nil, errors.New("not concerened address " + adr)
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
	case s.EqualVerify != opEQUALVERIFY:
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

func checkTxout2(s *Script2) (*key.PublicKey, error) {
	if s.CheckSig != opCHECKSIG {
		return nil, errors.New("unsuported scriptsig")
	}
	pubkey, err := key.NewPublicKey(s.Pubkey)
	if err != nil {
		return nil, err
	}
	if key.Find(pubkey) != nil {
		adr, _ := pubkey.Address()
		return nil, errors.New("not concerened address" + adr)
	}
	return pubkey, nil
}
