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
	"sort"

	"encoding/binary"

	"github.com/boltdb/bolt"
	"github.com/monarj/wallet/behex"
	"github.com/monarj/wallet/db"
	"github.com/monarj/wallet/msg"
	"github.com/monarj/wallet/params"
)

// UInt64Slice attaches the methods of Interface to []int, sorting in increasing order.
type UInt64Slice []uint64

func (p UInt64Slice) Len() int           { return len(p) }
func (p UInt64Slice) Less(i, j int) bool { return p[i] < p[j] }
func (p UInt64Slice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

var (
	zero        = make([]byte, 32)
	checkpoints = make(UInt64Slice, len(params.CheckPoints))
	genesis     *Block
)

func init() {
	log.SetFlags(log.Ldate | log.Lshortfile | log.Ltime)
	i := 0
	for k := range params.CheckPoints {
		checkpoints[i] = k
		i++
	}
	sort.Sort(checkpoints)

	genesis = &Block{
		Hash:   params.GenesisHash,
		Height: 0,
		Prev:   params.Prevs[0],
	}

	err := db.DB.Update(func(tx *bolt.Tx) error {
		for k, v := range params.CheckPoints {
			b := &Block{
				Hash:   v,
				Height: k,
				Prev:   params.Prevs[k],
			}
			if errr := b.addDB(tx); errr != nil {
				return errr
			}
			if errr := db.Put(tx, "blockheight", db.MustTob(k), v); errr != nil {
				return errr
			}
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
}

//Block is block info for database.
type Block struct {
	Hash   []byte
	Prev   []byte
	Height uint64
}

func (b *Block) packHeightPrev() []byte {
	out := make([]byte, 8+32)
	binary.LittleEndian.PutUint64(out[:8], b.Height)
	copy(out[8:], b.Prev)
	return out
}

//LoadBlock loads and returns Block struct from hash.
func LoadBlock(hash []byte) (*Block, error) {
	var b *Block
	err := db.DB.View(func(tx *bolt.Tx) error {
		var err error
		b, err = loadBlock(tx, hash)
		return err
	})
	return b, err
}

func loadBlock(tx *bolt.Tx, hash []byte) (*Block, error) {
	var dat []byte
	var err error
	if dat, err = db.Get(tx, "block", hash, nil); err != nil {
		return nil, err
	}
	height := binary.LittleEndian.Uint64(dat[:8])
	return &Block{
		Hash:   hash,
		Prev:   dat[8:],
		Height: height,
	}, nil
}

func (b *Block) addDB(tx *bolt.Tx) error {
	err := db.Put(tx, "block", b.Hash, b.packHeightPrev())
	if err != nil {
		return err
	}
	if _, ok := params.CheckPoints[b.Height]; ok {
		bdb := b
		var i uint64
		for i = 0; i < params.Nconfirmed; i++ {
			bdb, err = loadBlock(tx, bdb.Prev)
			if err != nil {
				break
			}
			err = db.Put(tx, "blockheight", db.MustTob(bdb.Height), bdb.Hash)
			if err != nil {
				return err
			}
		}
		return nil
	}
	prev, err := goback(tx, b.Hash, params.Nconfirmed)
	if err != nil {
		return nil
	}
	if prev != nil {
		err = db.Put(tx, "blockheight", db.MustTob(prev.Height), prev.Hash)
	}
	return err
}

//Lastblocks returns last blocks in blocks.
func Lastblocks() []*Block {
	var b []*Block
	err := db.DB.View(func(tx *bolt.Tx) error {
		b = lastblocks(tx)
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	return b
}

//Confirmed returns true if hash is confirmed.
func Confirmed(b *Block) bool {
	confirmed := false
	err := db.DB.View(func(tx *bolt.Tx) error {
		if db.HasKey(tx, "blockheight", db.ToKey(b.Height)) {
			confirmed = true
		}
		return nil
	})
	if err != nil {
		return false
	}
	return confirmed
}

//Lastblock returns the last block.
func Lastblock() *Block {
	var lastb *Block
	err := db.DB.View(func(tx *bolt.Tx) error {
		for i := 0; i < len(checkpoints); i++ {
			var end uint64
			if i == len(checkpoints)-1 {
				end = 0x8000000000000000
			} else {
				end = checkpoints[i+1]
			}
			last := findLast(tx, checkpoints[i], end)
			if last == end-1 {
				continue
			}
			log.Print(last)
			hash, err := db.Get(tx, "blockheight", db.ToKey(last), nil)
			if err != nil {
				return err
			}
			lastb, err = loadBlock(tx, hash)
			if err != nil {
				return err
			}
			break
		}
		return nil
	})
	if err != nil {
		log.Print(err)
		return genesis
	}
	return lastb
}

func findLast(tx *bolt.Tx, start, end uint64) uint64 {
	var height uint64
	for height = (start + end) / 2; height != start; height = (start + end) / 2 {
		has := db.HasKey(tx, "blockheight", db.ToKey(height))
		if !has {
			end = height
		} else {
			start = height
		}
	}
	return height
}

func lastblocks(tx *bolt.Tx) []*Block {
	lasts := make([]*Block, 0, len(checkpoints))
	for i := 0; i < len(checkpoints); i++ {
		var end uint64
		if i == len(checkpoints)-1 {
			end = 0x8000000000000000
		} else {
			end = checkpoints[i+1]
		}
		last := findLast(tx, checkpoints[i], end)
		if last == end-1 {
			continue
		}
		hash, err := db.Get(tx, "blockheight", db.ToKey(last), nil)
		if err != nil {
			log.Fatal(err)
		}
		b, err := loadBlock(tx, hash)
		if err != nil {
			log.Fatal(err)
		}
		lasts = append(lasts, b)
	}
	return lasts
}

//DownloadedBlockNumber returns downloaded block number.
func DownloadedBlockNumber() uint64 {
	var num uint64
	err := db.DB.View(func(tx *bolt.Tx) error {
		for i := 0; i < len(checkpoints); i++ {
			var end uint64
			if i == len(checkpoints)-1 {
				end = 0x8000000000000000
			} else {
				end = checkpoints[i+1]
			}
			last := findLast(tx, checkpoints[i], end)
			num += (last - checkpoints[i])
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	return num
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

//AddMerkle adds a merkle block to the chain.
func AddMerkle(mbs *msg.Merkleblock) (bool, error) {
	headers := msg.Headers{
		Inventory: make([]msg.BlockHeader, 1),
	}
	headers.Inventory[0] = msg.BlockHeader{
		HBlockHeader: mbs.HBlockHeader,
		TxnCount:     0,
	}
	return Add(headers)
}

//Add adds blocks to the chain.
//We must add blocks in height order.
func Add(mbs msg.Headers) (bool, error) {
	finished := false
	errr := db.DB.Update(func(tx *bolt.Tx) error {
		for i, b := range mbs.Inventory {
			h := b.Hash()
			if db.HasKey(tx, "block", h) {
				continue
			}
			previous, err := loadBlock(tx, b.Prev)
			if err != nil {
				log.Print(i, err)
				err = errors.New("orphan block " + behex.EncodeToString(b.Prev))
				return err
			}
			block := &Block{
				Hash:   h,
				Prev:   b.Prev,
				Height: previous.Height + 1,
			}
			if c, ok := params.CheckPoints[block.Height]; ok {
				if !bytes.Equal(c, h) {
					err = errors.New("didn't match checkpoint hash")
					return err
				}
				finished = true
				return nil
			}
			if err = b.IsOK(block.Height); err != nil {
				return err
			}
			if err = block.addDB(tx); err != nil {
				return err
			}
		}
		return nil
	})
	if errr != nil {
		return false, errr
	}
	log.Print(len(mbs.Inventory), " blocks were added")
	return finished, nil
}

func goback(tx *bolt.Tx, hash []byte, n uint64) (*Block, error) {
	bdb, err := loadBlock(tx, hash)
	if err != nil {
		log.Fatal(err)
	}
	var i uint64
	for i = 0; i < n; i++ {
		bdb, err = loadBlock(tx, bdb.Prev)
		if err != nil {
			break
		}
	}
	if i != n {
		return nil, errors.New("cannot goback")
	}
	return bdb, nil
}

//LocatorHash is processed by a node in the order as they appear in the message.
func LocatorHash(lasthash []byte) ([]msg.Hash, error) {
	var indexes []msg.Hash
	err := db.DB.View(func(tx *bolt.Tx) error {
		bdb, err := loadBlock(tx, lasthash)
		if err != nil {
			log.Print(err)
			return err
		}
		indexes = append(indexes, msg.Hash{Hash: bdb.Hash})
		for i := 0; i < 10 && bdb.Height > 0 && !bytes.Equal(zero, bdb.Prev); i++ {
			bdb2, errr := loadBlock(tx, bdb.Prev)
			if errr != nil || bdb2 == nil {
				break
			}
			indexes = append(indexes, msg.Hash{Hash: bdb2.Hash})
			bdb = bdb2
		}
		if bdb.Height < 2 {
			return nil
		}
		var step uint64 = 2
		for height := bdb.Height - step; ; height -= step {
			h, err := db.Get(tx, "blockheight", db.ToKey(height), nil)
			if err == nil {
				indexes = append(indexes, msg.Hash{Hash: h})
			}
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
