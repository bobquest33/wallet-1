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
	"encoding/hex"
	"log"
	"testing"

	"bytes"

	"github.com/monarj/wallet/behex"
	"github.com/monarj/wallet/msg"
)

var sheaders = []string{
	"02000000b68b8c410d2ea4afd74fb56e370bfc1bedf929e1453896c9e79dd116011c9fffb9c39c20b4baf3b84cd72349300833086d686db142c51b26a196cdabbe7a0610d45ac352f0ff0f1e0010bb7500",
	"020000008bd2106797e90cb3ed7e99c5226cc0c6ef2bc73771356071870ae001a6b778a3fc4430aa92e002ed08fd8d2d91c7fe536454c14aaf9b36b8ad06f8aa999d50f9de5ac352f0ff0f1e00062d6700",
	"020000008246054e53a0f5338b7b3d82fd2c067af5bffcf7b16cd29e3d02c03f23b5288c7dde82951b1040a2368cbb2c36f811d44c78bd660171b97af35cfda298004cf0fc5ac352f0ff0f1e0007397d00",
}
var shash = []string{
	"a378b7a601e00a877160357137c72befc6c06c22c5997eedb30ce9976710d28b",
	"8c28b5233fc0023d9ed26cb1f7fcbff57a062cfd823d7b8b33f5a0534e054682",
	"36a3b7235aa7a05d654a2afe7b3b3faade820e99a70db0262b5afd2d624412e9",
}
var (
	hs   []msg.BlockHeader
	hash [][]byte
)

func init() {
	hs = make([]msg.BlockHeader, len(sheaders))
	for i, h := range sheaders {
		ha, err := hex.DecodeString(h)
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewBuffer(ha)
		h := msg.BlockHeader{}
		if err := msg.Unpack(buf, &h); err != nil {
			log.Fatal(err)
		}
		hs[i] = h
	}
	var err error
	hash = make([][]byte, len(shash))
	for i, h := range shash {
		hash[i], err = behex.DecodeString(h)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func TestBlock(t *testing.T) {
	tails = make(map[string]*Block)
	blocks = make(map[string]*Block)
	lastBlock = genesis
	tails[string(genesis.block.Hash())] = genesis
	blocks[string(genesis.block.Hash())] = genesis
	headers := msg.Headers{
		Count:     msg.VarInt(3),
		Inventory: hs,
	}
	var err error

	hashh, err := Add(headers)
	if err != nil {
		t.Fatal(err)
	}
	for i, hh := range hashh {
		if !bytes.Equal(hash[i], hh) {
			t.Fatal("hash unmatch", i)
		}
	}
	if tails[string(hash[len(hash)-1])].Height != len(hash) {
		t.Fatalf("illegal tail height")
	}
	if len(blocks) != len(hash)+1 {
		t.Fatalf("illegal block number")
	}
}

func TestBlock2(t *testing.T) {
	tails = make(map[string]*Block)
	blocks = make(map[string]*Block)
	lastBlock = genesis
	tails[string(genesis.block.Hash())] = genesis
	blocks[string(genesis.block.Hash())] = genesis

	hss := append(hs[:1], hs[2:]...)
	headers := msg.Headers{
		Count:     msg.VarInt(len(hs)),
		Inventory: hss,
	}
	var err error
	hashh, err := Add(headers)
	log.Println(err)
	if err == nil {
		t.Fatal("cannot detect orphan block")
	}
	log.Println(len(hashh))
	for i, hh := range hashh {
		if !bytes.Equal(hash[i], hh) {
			t.Fatal("hash unmatch", i)
		}
	}
	if _, ok := tails[string(hash[0])]; !ok {
		t.Fatalf("illegal tail")
	}
	if len(blocks) != 2 {
		t.Fatalf("illegal block number %d", len(blocks))
	}
}
