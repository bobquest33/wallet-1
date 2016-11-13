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
	"math/big"

	"crypto/sha256"
	"log"

	"github.com/monarj/wallet/msg"
)

var zero = new(big.Int)

type merkle struct {
	height int
	hashes []msg.Hash
	nHash  int
	tx     []msg.Hash
	flags  *big.Int
	mask   *big.Int
}

func (m *merkle) ope(stair int) msg.Hash {
	tmp := new(big.Int)
	switch tmp.And(m.flags, m.mask).Cmp(zero) == 0 {
	case true:
		m.nHash++
		return m.hashes[m.nHash-1]
	default:
		if stair == m.height {
			m.tx = append(m.tx, m.hashes[m.nHash])
			m.nHash++
			return m.hashes[m.nHash-1]
		}
		m.mask.Lsh(m.mask, 1)
		hleft := m.ope(stair + 1)
		m.mask.Lsh(m.mask, 1)
		hright := m.ope(stair + 1)
		h := sha256.New()
		if _, err := h.Write(hleft.Hash); err != nil {
			log.Fatal(err)
		}
		if _, err := h.Write(hright.Hash); err != nil {
			log.Fatal(err)
		}
		s := h.Sum(nil)
		return msg.Hash{Hash: s[:]}
	}
}

//MerkleRoot returns root hash of merkle.
func MerkleRoot(n uint32, hashes []msg.Hash, flags []byte) []byte {
	var height, count int
	//faster than log2?
	for height, count = 0, 1; count < int(n); height++ {
		count *= 2
	}
	f := new(big.Int)
	f.SetBytes(flags)
	mm := make([]byte, len(flags))
	mm[0] = 0x80
	mask := new(big.Int)
	mask.SetBytes(mm)
	tmp := new(big.Int)
	for ; tmp.And(f, mask).Cmp(zero) == 0; mask.Lsh(mask, 1) {
	}
	m := merkle{
		height: height,
		hashes: hashes,
		flags:  f,
		mask:   mask,
	}
	return m.ope(0).Hash
}
