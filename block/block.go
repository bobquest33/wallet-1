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
	"errors"
	"log"

	"sync"

	"bytes"

	"github.com/monarj/wallet/behex"
	"github.com/monarj/wallet/msg"
	"github.com/monarj/wallet/params"
)

var (
	genesis   *Block
	tails     = make(map[string]*Block)
	blocks    = make(map[string]*Block)
	lastBlock = genesis
	mutex     sync.RWMutex
)

func init() {
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
	genesis = &Block{
		block:  &g,
		Height: 0,
	}
	lastBlock = genesis
	tails[string(hg)] = genesis
	blocks[string(hg)] = genesis
}

//Last returns last block.
func Last() *Block {
	mutex.RLock()
	defer mutex.RUnlock()

	return lastBlock
}

//Height returns height of block whose hash is hash.
//it returns.-1 if no block.
func Height(hash []byte) int {
	mutex.RLock()
	defer mutex.RUnlock()
	b, ok := blocks[string(hash)]
	if !ok {
		return -1
	}
	return b.Height
}

//Block is block header with height.
type Block struct {
	block  *msg.BlockHeader
	Height int
}

//Add adds blocks to the chain and returns hashes of these.
//We must add blocks in height order.
func Add(mbs msg.Headers) ([][]byte, error) {
	hashes := make([][]byte, 0, len(mbs.Inventory))
	mutex.Lock()
	defer mutex.Unlock()
	for i, b := range mbs.Inventory {
		p, ok := blocks[string(b.Prev)]
		if !ok {
			log.Print(i)
			return hashes, errors.New("orphan block " + behex.EncodeToString(b.Prev))
		}
		if err := b.IsOK(p.Height + 1); err != nil {
			return hashes, err
		}
		h := b.Hash()
		if _, exist := blocks[string(h)]; exist {
			continue
		}
		block := Block{
			block: &b,
		}
		block.Height = p.Height + 1
		if c, ok := params.CheckPoints[block.Height]; ok {
			if !bytes.Equal(c, h) {
				return hashes, errors.New("didn't match checkpoint hash")
			}
		}
		blocks[string(h)] = &block
		tails[string(h)] = &block
		hashes = append(hashes, h)
		updateTails(&block)
	}
	return hashes, nil
}

func updateTails(block *Block) {
	for k := range tails {
		if k == string(block.block.Prev) {
			delete(tails, k)
		}
	}
	if lastBlock.Height < block.Height {
		lastBlock = block
	}
	for k, v := range tails {
		if v.Height < lastBlock.Height-params.Nconfirmed {
			delete(tails, k)
		}
	}
}

//LocatorHash is processed by a node in the order as they appear in the message.
func LocatorHash() []msg.Hash {
	mutex.RLock()
	defer mutex.RUnlock()
	step := 1
	var indexes []msg.Hash
	ok := true
	for index := lastBlock; ok; {
		indexes = append(indexes, msg.Hash{Hash: index.block.Hash()})
		if len(indexes) >= 10 {
			step *= 2
		}
		for i := 0; ok && i < step; index, ok = blocks[string(index.block.Prev)] {
			i++
		}
	}
	if !bytes.Equal(indexes[len(indexes)-1].Hash, params.GenesisHash) {
		indexes = append(indexes, msg.Hash{Hash: params.GenesisHash})
	}
	return indexes
}
