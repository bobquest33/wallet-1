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

	"github.com/boltdb/bolt"
	"github.com/monarj/wallet/behex"
	"github.com/monarj/wallet/db"
	"github.com/monarj/wallet/key"
	"github.com/monarj/wallet/msg"
)

var (
	notifyTX = make(map[string]chan *msg.Tx)
	mutex    sync.RWMutex
)

//AddNotify adds pubscript to be notified.
func AddNotify(pubscr []byte) chan *msg.Tx {
	ch := make(chan *msg.Tx)
	mutex.Lock()
	defer mutex.Unlock()
	notifyTX[string(pubscr)] = ch
	return ch
}

//Coins is array of coins.
type Coins []*Coin

func (c Coins) Len() int           { return len(c) }
func (c Coins) Less(i, j int) bool { return c[i].Value < c[j].Value }
func (c Coins) Swap(i, j int)      { c[i], c[j] = c[j], c[i] }

//GetCoins get coin list.
func GetCoins(pub *key.PublicKey) (Coins, error) {
	var coins Coins
	err := db.DB.Batch(func(tx *bolt.Tx) error {
		var errr error
		coins, errr = getCoins(tx, pub)
		return errr
	})
	return coins, err
}

func getCoins(tx *bolt.Tx, pub *key.PublicKey) (Coins, error) {
	var coins Coins
	var spub []byte
	if pub != nil {
		spub = pub.Serialize()
	}
	bucket := tx.Bucket([]byte("coin"))
	if bucket == nil {
		return nil, nil
	}
	c := bucket.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		l := &Coin{}
		errr := msg.Unpack(bytes.NewBuffer(v), l)
		if errr != nil {
			return nil, errr
		}
		if spub == nil || bytes.Equal(l.Pubkey, spub) {
			coins = append(coins, l)
		}
	}
	return coins, nil
}

//SortedCoins returns value-sorted coins that cointans all address.
func SortedCoins() Coins {
	var coins Coins
	err := db.DB.View(func(tx *bolt.Tx) error {
		var errr error
		coins, errr = getCoins(tx, nil)
		return errr
	})
	if err != nil {
		log.Fatal(err)
	}
	sort.Sort(coins)
	return coins
}

func (c *Coin) save() error {
	spent := false
	err := db.DB.Batch(func(tx *bolt.Tx) error {
		if db.HasKey(tx, "spend", c.TxHash) {
			spent = true
			return db.Del(tx, "spend", c.TxHash)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if spent {
		return nil
	}

	dat := bytes.Buffer{}
	if err := msg.Pack(&dat, *c); err != nil {
		return err
	}
	k := db.ToKey(c.TxHash, c.TxIndex)
	return db.Batch("coin", k, dat.Bytes())
}

//Coin represents an available transaction.
type Coin struct {
	Pubkey   []byte `len:"prev"`
	TxHash   []byte `len:"32"`
	Value    uint64
	Block    []byte `len:"32"`
	Script   []byte `len:"prev"`
	TxIndex  uint32
	Coinbase bool
	Ttype    byte
}

//RemoveKey removes coins associated with pub.
func RemoveKey(pub *key.PublicKey) error {
	return db.DB.Batch(func(tx *bolt.Tx) error {
		coin, err := getCoins(tx, pub)
		if err != nil {
			return err
		}
		for _, c := range coin {
			if errr := db.Del(tx, "coin", db.ToKey(c.TxHash, c.TxIndex)); err != nil {
				return errr
			}
		}
		return nil
	})
}

//remove removes one tx.
func remove(hash []byte, index uint32) error {
	return db.DB.Batch(func(tx *bolt.Tx) error {
		coin, err := getCoins(tx, nil)
		if err != nil {
			return err
		}
		for _, c := range coin {
			if bytes.Equal(c.TxHash, hash) && c.TxIndex == index {
				return db.Del(tx, "coin", db.ToKey(c.TxHash, c.TxIndex))
			}
		}
		return db.Put(tx, "spent", db.ToKey(hash, index), hash)
	})
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

func parseScriptsigHT(data []byte) (*ScriptSigT, error) {
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

	st := ScriptSigT{}
	if err := msg.Unpack(buf, &st); err != nil {
		return nil, errors.New("this tx is not supported(unknown format)")
	}
	if buf.Len() != 0 {
		return nil, fmt.Errorf("this tx is not supported")
	}
	return &st, nil
}

//Add adds or removes transanctions from a tx packet.
func Add(mtx *msg.Tx, hash []byte) error {
	coinbase := false
	zero := make([]byte, 32)
	for _, in := range mtx.TxIn {
		if bytes.Equal(in.Hash, zero) && in.Index == 0xffffffff {
			log.Println("coinbase")
			coinbase = true
			break
		}
		s, err := parseScriptsigHT(in.Script)
		if err != nil {
			log.Println(err)
			continue
		}
		if _, err = checkTxin(s); err != nil {
			log.Println(err)
			continue
		}
		if err := remove(in.Hash, in.Index); err != nil {
			log.Println(err)
		}
	}
	for i, in := range mtx.TxOut {
		pubkey, ttype, err := parseTXout(in.Script)
		if err != nil {
			log.Println(err, behex.EncodeToString(mtx.Hash()))
			continue
		}
		c := &Coin{
			Pubkey:   pubkey.Serialize(),
			TxHash:   mtx.Hash(),
			TxIndex:  uint32(i),
			Value:    mtx.TxOut[i].Value,
			Ttype:    ttype,
			Block:    hash,
			Coinbase: coinbase,
			Script:   in.Script,
		}
		if err = c.save(); err != nil {
			return err
		}
		notify(mtx, in.Script)
	}
	return nil
}

func notify(mtx *msg.Tx, inscript []byte) {
	for k, v := range notifyTX {
		if bytes.Equal(inscript, []byte(k)) {
			delete(notifyTX, k)
			v <- mtx
		}
	}
}

func parseTXout(inscript []byte) (*key.PublicKey, byte, error) {
	s1 := Script{}
	err1 := parse(&s1, inscript)
	s2 := Script2{}
	err2 := parse(&s2, inscript)

	var pubkey *key.PublicKey
	var err error
	var ttype byte
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
	return pubkey, ttype, err
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
	return key.FromPubHash(s.PubHash)
}

func checkTxout2(s *Script2) (*key.PublicKey, error) {
	if s.CheckSig != opCHECKSIG {
		return nil, errors.New("unsuported scriptsig")
	}
	pubkey, err := key.NewPublicKey(s.Pubkey)
	if err != nil {
		return nil, err
	}
	if key.Find(pubkey) == nil {
		adr, _ := pubkey.Address()
		return nil, errors.New("not concerened address" + adr)
	}
	return pubkey, nil
}
