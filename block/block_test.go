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
	"encoding/hex"
	"log"
	"testing"

	"github.com/boltdb/bolt"
	"github.com/monarj/wallet/behex"
	"github.com/monarj/wallet/db"
	"github.com/monarj/wallet/msg"
	"github.com/monarj/wallet/params"
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
	log.SetFlags(log.Ldate | log.Lshortfile | log.Ltime)

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

func TestBlock2(t *testing.T) {
	headers := msg.Headers{
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
	height, err := Height(hash[len(hash)-1])
	if err != nil {
		t.Fatal(err)
	}
	if height != uint64(len(hash)) {
		t.Fatalf("illegal tail height %d", height)
	}
	var l *List
	err = db.DB.View(func(tx *bolt.Tx) error {
		var errr error
		l, errr = loadBlock(tx, hash[2])
		return errr
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Ancestors) != 2 {
		t.Fatal("illegal len of ancestors", len(l.Ancestors))
	}
	if !bytes.Equal(l.Ancestors[0].Hash, params.GenesisHash) {
		t.Error("illegal ancestors[0]")
	}
	if !bytes.Equal(l.Ancestors[1].Hash, hash[1]) {
		t.Error("illegal ancestors[1]")
	}
	last, lheight := Lastblock()
	if !bytes.Equal(last, hash[len(hash)-1]) {
		t.Error("tail unmatched")
	}
	if lheight != uint64(len(hash)) {
		t.Error("illegal lastblock")
	}

	err = db.DB.Update(func(tx *bolt.Tx) error {
		for _, h := range hash {
			err = db.Del(tx, "block", h)
			if err != nil {
				log.Print(err)
			}
			err = db.Del(tx, "tail", h)
			if err != nil {
				log.Print(err)
			}
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
}

func TestBlock1(t *testing.T) {
	log.SetFlags(log.Ldate | log.Lshortfile | log.Ltime)
	hss := make([]msg.BlockHeader, 2)
	hss[0] = hs[0]
	hss[1] = hs[2]
	headers := msg.Headers{
		Inventory: hss,
	}
	_, err := Add(headers)
	log.Println(err)
	if err == nil {
		t.Fatal("cannot detect orphan block")
	}
	err = db.DB.Update(func(tx *bolt.Tx) error {
		for _, h := range hash {
			err = db.Del(tx, "block", h)
			if err != nil {
				log.Print(err)
			}
			err = db.Del(tx, "tail", h)
			if err != nil {
				log.Print(err)
			}
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
}

//need to test locatorhash more
func TestLocator(t *testing.T) {
	headers := msg.Headers{
		Inventory: hs,
	}
	var err error

	_, err = Add(headers)
	if err != nil {
		t.Fatal(err)
	}
	h := LocatorHash()
	if len(h) != 4 {
		t.Fatal("illegal length of locator", len(h))
	}
	for i, lh := range hash {
		if !bytes.Equal(h[len(h)-i-2].Hash, lh) {
			t.Fatal("illegal locator", i)
		}
	}
	if !bytes.Equal(h[len(h)-1].Hash, params.GenesisHash) {
		t.Fatal("illegal locator")
	}
	err = db.DB.Update(func(tx *bolt.Tx) error {
		for _, h := range hash {
			err = db.Del(tx, "block", h)
			if err != nil {
				log.Print(err)
			}
			err = db.Del(tx, "tail", h)
			if err != nil {
				log.Print(err)
			}
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
}
