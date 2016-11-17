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
	"math"

	"bytes"

	"crypto/sha256"

	"github.com/monarj/wallet/block"
	"github.com/monarj/wallet/key"
	"github.com/monarj/wallet/msg"
	"github.com/monarj/wallet/params"
)

//Send is information about addrress and amount to send.
type Send struct {
	Addr   string
	Amount uint64
}

func p2pkTtxouts(send *Send) (*msg.TxOut, error) {
	addr, err := key.DecodeAddress(send.Addr)
	if err != nil {
		return nil, err
	}
	script := make([]byte, 0, len(addr)+4)
	script = append(script, opDUP, opHASH160)
	script = append(script, addr...)
	script = append(script, opEQUALVERIFY, opCHECKSIG)
	return &msg.TxOut{
		Value:     send.Amount,
		ScriptLen: msg.VarInt(len(script)),
		Script:    script,
	}, nil
}

func newTxins(total uint64) ([]msg.TxIn, []*key.PrivateKey, uint64, error) {
	var txins []msg.TxIn
	var amount uint64
	coins := SortedCoins()
	var privs []*key.PrivateKey
	for i := 0; i < len(coins) && amount < total; i++ {
		c := coins[i]
		amount += c.Value
		height := block.Last().Height
		if c.Coinbase && height-c.Height < params.SpendableCoinbaseDepth {
			continue
		}
		if height-c.Height < params.Nconfirmed {
			continue
		}
		txins = append(txins, msg.TxIn{
			Hash:      c.TxHash,
			Index:     c.TxIndex,
			ScriptLen: msg.VarInt(len(c.Script)),
			Script:    c.Script, //pubscript to be hashed.
			Seq:       math.MaxUint32,
		})
		pub, err := key.NewPublicKey(c.Pubkey)
		if err != nil {
			return nil, nil, 0, err
		}
		privs = append(privs, key.Find(pub))
	}
	if amount < total {
		return nil, nil, 0, errors.New("shortage of coin")
	}
	return txins, privs, amount - total, nil
}

func createTx(result *msg.Tx, privs []*key.PrivateKey) error {
	var buf bytes.Buffer
	if err := msg.Pack(&buf, *result); err != nil {
		return err
	}
	beforeb := buf.Bytes()
	beforeb = append(beforeb, 0x01, 0, 0, 0) //hash code type
	h := sha256.Sum256(beforeb)
	h = sha256.Sum256(h[:])
	for i, p := range privs {
		s, err := p.Sign(h[:])
		if err != nil {
			return err
		}
		s = append(s, 0x1)
		scr := result.TxIn[i].Script[:0]
		scr = append(scr, byte(len(s)))
		scr = append(scr, s...)
		pub := p.PublicKey.Serialize()
		scr = append(scr, byte(len(pub)))
		scr = append(scr, pub...)
		result.TxIn[i].Script = scr
		result.TxIn[i].ScriptLen = msg.VarInt(len(scr))
	}
	return nil
}

//NewTx creates msg.Tx from send infos.
func NewTx(sends ...*Send) (*msg.Tx, error) {
	total := params.Fee
	txouts := make([]msg.TxOut, len(sends))
	for i, send := range sends {
		total += send.Amount
		txout, err := p2pkTtxouts(send)
		if err != nil {
			return nil, err
		}
		txouts[i] = *txout
	}
	txins, privs, remain, err := newTxins(total)
	if err != nil {
		return nil, err
	}
	myadr, _ := privs[0].Address()
	if remain > 0 {
		s := Send{
			Addr:   myadr,
			Amount: remain,
		}
		mto, err := p2pkTtxouts(&s)
		if err != nil {
			return nil, err
		}
		txouts = append(txouts, *mto)
	}
	result := msg.Tx{
		Version:  1,
		InCount:  msg.VarInt(len(txins)),
		TxIn:     txins,
		OutCount: msg.VarInt(len(txouts)),
		TxOut:    txouts,
		Locktime: 0,
	}
	createTx(&result, privs)

	return &result, nil
}
