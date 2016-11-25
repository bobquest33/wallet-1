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

package block

import (
	"bytes"
	"errors"
	"log"

	"github.com/boltdb/bolt"
	"github.com/monarj/wallet/behex"
	"github.com/monarj/wallet/db"
	"github.com/monarj/wallet/msg"
	"github.com/monarj/wallet/params"
)

func init() {
	log.SetFlags(log.Ldate | log.Lshortfile | log.Ltime)

	dbexist := false
	err := db.DB.View(func(tx *bolt.Tx) error {
		if bu := tx.Bucket([]byte("block")); bu != nil {
			dbexist = true
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	if dbexist {
		return
	}
	g := msg.BlockHeader{
		HBlockHeader: msg.HBlockHeader{
			Version:   params.GenesisVersion,
			Merkle:    params.GenesisMerkle,
			Timestamp: params.GenesisTime,
			Bits:      params.GenesisBits,
			Nonce:     params.GenesisNonce,
		},
		TxnCount: 0,
	}
	hg := g.Hash()
	if !bytes.Equal(hg, params.GenesisHash) {
		log.Fatal("illegal hash of genesis block.", behex.EncodeToString(hg))
	}
	genesis := &Block{
		block:  &g,
		Height: 0,
	}
	err = db.DB.Update(func(tx *bolt.Tx) error {
		return addDB(genesis, nil, tx)
	})
	if err != nil {
		log.Fatal(err)
	}
}

//Ancestor is a pointer to ancestor refered in
//https://ipfs.io/ipfs/QmTtqKeVpgQ73KbeoaaomvLoYMP7XKemhTgPNjasWjfh9b/
type Ancestor struct {
	Hash   []byte `len:"32"`
	Offset uint64
}

//List  is an "Object chain ancestor links prototype" reffed in
//https://ipfs.io/ipfs/QmTtqKeVpgQ73KbeoaaomvLoYMP7XKemhTgPNjasWjfh9b/
type List struct {
	Ancestors []Ancestor `len:"prev"`
}

func saveBlock(tx *bolt.Tx, hash []byte, l *List) error {
	dat := bytes.Buffer{}
	if err := msg.Pack(&dat, *l); err != nil {
		return err
	}
	log.Println("saved", behex.EncodeToString(hash))
	err := db.Put(tx, "block", hash, dat.Bytes())
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func loadBlock(tx *bolt.Tx, hash []byte) (*List, error) {
	var dat []byte
	var err error
	if dat, err = db.Get(tx, "block", hash, nil); err != nil {
		return nil, err
	}
	l := &List{}
	err = msg.Unpack(bytes.NewBuffer(dat), l)
	return l, err
}

func bucketNo(n uint64) int {
	for i := 1; i <= 64; i++ {
		if n >>= 1; n == 0 {
			return i
		}
	}
	//never occur
	return -1
}

func updateAncestor(prev *List, hprev []byte) {
	ans := prev.Ancestors
	for i := 0; i < len(ans); i++ {
		ans[i].Offset++
	}
	ans = append(ans, Ancestor{
		Hash:   hprev,
		Offset: 1,
	})
	bno := 0
	for i := 0; i < len(ans); i++ {
		no := bucketNo(ans[i].Offset)
		if no == bno {
			copy(ans[i:], ans[i+1:])
			ans = ans[:len(ans)-1]
		}
		bno = no
	}
	prev.Ancestors = ans
}

func addDB(b *Block, prev *List, tx *bolt.Tx) error {
	if prev != nil {
		updateAncestor(prev, b.block.Prev)
	} else {
		prev = &List{Ancestors: []Ancestor{}}
	}
	h := b.block.Hash()
	if err := saveBlock(tx, h, prev); err != nil {
		return err
	}
	if err := db.Put(tx, "tail", h, db.MustTob(b.Height)); err != nil {
		return err
	}
	if err := db.Del(tx, "tail", b.block.Prev); err != nil {
		log.Println(err)
	}
	_, last := lastblock(tx)
	c := tx.Bucket([]byte("tail")).Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		var height uint64
		if err := db.B2v(v, &height); err != nil {
			return err
		}
		if height+params.Nconfirmed < last {
			if err := c.Delete(); err != nil {
				return err
			}
			if err := db.Del(tx, "block", k); err != nil {
				return err
			}
		}
	}
	return nil
}

//Lastblock returns hash and height of the last block.
func Lastblock() ([]byte, uint64) {
	var height uint64
	var hash []byte
	err := db.DB.View(func(tx *bolt.Tx) error {
		hash, height = lastblock(tx)
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	return hash, height
}
func lastblock(tx *bolt.Tx) ([]byte, uint64) {
	var last uint64
	var hash []byte
	c := tx.Bucket([]byte("tail")).Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		var height uint64
		if err := db.B2v(v, &height); err != nil {
			log.Fatal(err)
		}
		if height > last {
			last = height
			hash = k
		}
	}
	return hash, last
}

//Height returns height of block whose hash is hash.
func Height(hash []byte) (uint64, error) {
	var height uint64
	err := db.DB.View(func(tx *bolt.Tx) error {
		l, err := loadBlock(tx, hash)
		if err != nil {
			return err
		}
		if len(l.Ancestors) > 0 {
			height = l.Ancestors[0].Offset
		}
		return err
	})
	return height, err
}

//Block is block header with height.
type Block struct {
	block  *msg.BlockHeader
	Height uint64
}

//Add adds blocks to the chain and returns hashes of these.
//We must add blocks in height order.
func Add(mbs msg.Headers) ([][]byte, error) {
	hashes := make([][]byte, 0, len(mbs.Inventory))
	errr := db.DB.Update(func(tx *bolt.Tx) error {
		for i, b := range mbs.Inventory {
			h := b.Hash()
			has, err := db.HasKey(tx, "block", h)
			if err != nil {
				return err
			}
			if has {
				continue
			}
			log.Println(behex.EncodeToString(b.Prev))
			list, err := loadBlock(tx, b.Prev)
			if err != nil {
				log.Print(i, err)
				err = errors.New("orphan block " + behex.EncodeToString(b.Prev))
				return err
			}
			var height uint64
			if len(list.Ancestors) > 0 {
				height = list.Ancestors[0].Offset
			}
			if err = b.IsOK(height + 1); err != nil {
				return err
			}
			block := Block{
				block: &b,
			}
			block.Height = height + 1
			if c, ok := params.CheckPoints[block.Height]; ok {
				if !bytes.Equal(c, h) {
					err = errors.New("didn't match checkpoint hash")
					return err
				}
			}
			err = addDB(&block, list, tx)
			if err != nil {
				return err
			}
			hashes = append(hashes, h)
		}
		return nil
	})
	if errr != nil {
		return nil, errr
	}
	return hashes, nil
}

func search(tx *bolt.Tx, l *List, offset uint64) ([]byte, *List, error) {
	for _, a := range l.Ancestors {
		if a.Offset > offset {
			continue
		}
		ll, err := loadBlock(tx, a.Hash)
		if err != nil {
			return nil, nil, err
		}
		if a.Offset < offset {
			return search(tx, ll, offset-a.Offset)
		}
		if a.Offset == offset {
			return a.Hash, ll, nil
		}
	}
	return nil, nil, errors.New("not found")
}

//LocatorHash is processed by a node in the order as they appear in the message.
func LocatorHash() []msg.Hash {
	var step uint64 = 1
	var indexes []msg.Hash
	var h []byte
	err := db.DB.View(func(tx *bolt.Tx) error {
		index, _ := lastblock(tx)
		l, err := loadBlock(tx, index)
		if err != nil {
			return err
		}
		indexes = append(indexes, msg.Hash{Hash: index})
		for l.Ancestors[0].Offset > step {
			h, l, err = search(tx, l, step)
			if err != nil {
				return err
			}
			indexes = append(indexes, msg.Hash{Hash: h})
			if len(indexes) >= 10 {
				step *= 2
			}
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(indexes[len(indexes)-1].Hash, params.GenesisHash) {
		indexes = append(indexes, msg.Hash{Hash: params.GenesisHash})
	}
	return indexes
}
