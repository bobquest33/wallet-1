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

	"encoding/binary"

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
		return addDB(genesis, tx)
	})
	if err != nil {
		log.Fatal(err)
	}
}

type blockdb struct {
	hash   []byte
	prev   []byte
	height uint64
}

func loadBlock(tx *bolt.Tx, hash []byte) (*blockdb, error) {
	var dat []byte
	var err error
	if dat, err = db.Get(tx, "block", hash, nil); err != nil {
		return nil, err
	}
	height := binary.LittleEndian.Uint64(dat[:8])
	return &blockdb{
		hash:   hash,
		prev:   dat[8:],
		height: height,
	}, nil
}

func addDB(b *Block, tx *bolt.Tx) error {
	hash := b.block.Hash()
	err := db.Put(tx, "block", hash, b.packWithPrev())
	if err != nil {
		return err
	}
	log.Print(behex.EncodeToString(hash))
	err = db.Put(tx, "status", []byte("lastblock"), b.packWithHash())
	if err != nil {
		return err
	}
	prev, err := goback(tx, hash, 5)
	if err != nil {
		return err
	}
	if prev != nil {
		err = db.Put(tx, "blockheight", db.MustTob(prev.height), prev.hash)
	}

	return err
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
	dat, err := db.Get(tx, "status", []byte("lastblock"), nil)
	if err != nil {
		log.Fatal(err)
	}
	height := binary.LittleEndian.Uint64(dat[:8])
	return dat[8:], height
}

//GetHashes get a block hash whose height is height.
//block must be confirmed, i.e. whose hwight is more than Nconfirmed(5).
func GetHashes(height uint64, n uint64) ([][]byte, error) {
	hashes := make([][]byte, n)
	errr := db.DB.View(func(tx *bolt.Tx) error {
		var i uint64
		for i = 0; i < n; i++ {
			hash, err := db.Get(tx, "blockheight", db.ToKey(height+i), nil)
			if err != nil {
				return err
			}
			hashes[i] = hash
		}
		return nil
	})
	return hashes, errr
}

//Height returns height of block whose hash is hash.
func Height(hash []byte) (uint64, error) {
	var bdb *blockdb
	errr := db.DB.View(func(tx *bolt.Tx) error {
		var err error
		bdb, err = loadBlock(tx, hash)
		return err
	})
	if errr != nil {
		return 0, errr
	}
	return bdb.height, nil
}

//Block is block header with height.
type Block struct {
	block  *msg.BlockHeader
	Height uint64
}

func (b *Block) packWithHash() []byte {
	out := make([]byte, 8+32)
	binary.LittleEndian.PutUint64(out[:8], b.Height)
	copy(out[8:], b.block.Hash())
	return out
}

func (b *Block) packWithPrev() []byte {
	out := make([]byte, 8+32)
	binary.LittleEndian.PutUint64(out[:8], b.Height)
	copy(out[8:], b.block.Prev)
	return out
}

//Add adds blocks to the chain and returns hashes of these.
//We must add blocks in height order.
func Add(mbs msg.Headers) error {
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
			previous, err := loadBlock(tx, b.Prev)
			if err != nil {
				log.Print(i, err)
				err = errors.New("orphan block " + behex.EncodeToString(b.Prev))
				return err
			}
			if err = b.IsOK(previous.height + 1); err != nil {
				return err
			}
			block := &Block{
				block:  &b,
				Height: previous.height + 1,
			}
			if c, ok := params.CheckPoints[block.Height]; ok {
				if !bytes.Equal(c, h) {
					err = errors.New("didn't match checkpoint hash")
					return err
				}
			}
			err = addDB(block, tx)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if errr != nil {
		return errr
	}
	log.Print(len(mbs.Inventory), " blocks were added")
	return nil
}

func goback(tx *bolt.Tx, hash []byte, n int) (*blockdb, error) {
	bdb, err := loadBlock(tx, hash)
	if err != nil {
		return nil, err
	}
	for i := 0; i < n && bdb.height > 0; i++ {
		bdb, err = loadBlock(tx, bdb.prev)
		if err != nil {
			return nil, err
		}
	}
	return bdb, nil
}

//LocatorHash is processed by a node in the order as they appear in the message.
func LocatorHash() ([]msg.Hash, error) {
	var indexes []msg.Hash
	index, _ := Lastblock()
	err := db.DB.View(func(tx *bolt.Tx) error {
		bdb, err := loadBlock(tx, index)
		if err != nil {
			return err
		}
		indexes = append(indexes, msg.Hash{Hash: bdb.hash})
		for i := 0; i < 10 && bdb.height > 0; i++ {
			bdb, err = loadBlock(tx, bdb.prev)
			if err != nil {
				return err
			}
			indexes = append(indexes, msg.Hash{Hash: bdb.hash})
			log.Print(behex.EncodeToString(bdb.hash))
		}
		if bdb.height < 2 {
			return nil
		}
		var step uint64 = 2
		for height := bdb.height - step; ; height -= step {
			h, err := db.Get(tx, "blockheight", db.ToKey(height), nil)
			if err != nil {
				return err
			}
			indexes = append(indexes, msg.Hash{Hash: h})
			step <<= 1
			if height < step {
				break
			}
		}
		return nil
	})
	if !bytes.Equal(indexes[len(indexes)-1].Hash, params.GenesisHash) {
		indexes = append(indexes, msg.Hash{Hash: params.GenesisHash})
	}
	return indexes, err
}
