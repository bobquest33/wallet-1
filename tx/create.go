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
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"math"

	"github.com/StorjPlatform/gocoin/btcec"
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

func p2pkTtxout(send *Send) (*msg.TxOut, error) {
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

func p2pkTxouts(sends ...*Send) ([]msg.TxOut, uint64, error) {
	total := params.Fee
	txouts := make([]msg.TxOut, len(sends))
	for i, send := range sends {
		total += send.Amount
		txout, err := p2pkTtxout(send)
		if err != nil {
			return nil, 0, err
		}
		txouts[i] = *txout
	}
	return txouts, total, nil
}

func newTxins(total uint64) ([]msg.TxIn, []*key.PrivateKey, *msg.TxOut, error) {
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
			return nil, nil, nil, err
		}
		privs = append(privs, key.Find(pub))
	}
	remain := amount - total
	if remain < 0 {
		return nil, nil, nil, errors.New("shortage of coin")
	}
	var mto *msg.TxOut
	var err error
	if remain > 0 {
		myadr, _ := privs[0].Address()
		s := Send{
			Addr:   myadr,
			Amount: remain,
		}
		mto, err = p2pkTtxout(&s)
	}
	return txins, privs, mto, err
}
func signTx(result *msg.Tx, privs []*key.PrivateKey) ([][]byte, error) {
	var buf bytes.Buffer
	if err := msg.Pack(&buf, *result); err != nil {
		return nil, err
	}
	beforeb := buf.Bytes()
	beforeb = append(beforeb, 0x01, 0, 0, 0) //hash code type
	h := sha256.Sum256(beforeb)
	h = sha256.Sum256(h[:])
	sign := make([][]byte, len(privs))
	var err error
	for i, p := range privs {
		sign[i], err = p.Sign(h[:])
		if err != nil {
			return nil, err
		}
	}
	return sign, nil
}
func fillSign(result *msg.Tx, privs []*key.PrivateKey) error {
	signs, err := signTx(result, privs)
	if err != nil {
		return err
	}
	for i, s := range signs {
		s = append(s, 0x1)
		scr := result.TxIn[i].Script[:0]
		scr = append(scr, byte(len(s)))
		scr = append(scr, s...)
		pub := privs[i].PublicKey.Serialize()
		scr = append(scr, byte(len(pub)))
		scr = append(scr, pub...)
		result.TxIn[i].Script = scr
		result.TxIn[i].ScriptLen = msg.VarInt(len(scr))
	}
	return nil
}

//NewP2PK creates msg.Tx from send infos.
func NewP2PK(sends ...*Send) (*msg.Tx, error) {
	total := params.Fee
	txouts, total, err := p2pkTxouts(sends...)
	if err != nil {
		return nil, err
	}
	txins, privs, mto, err := newTxins(total)
	if err != nil {
		return nil, err
	}
	if mto != nil {
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
	fillSign(&result, privs)

	return &result, nil
}

//PubInfo is infor of public key in M of N multisig.
type PubInfo struct {
	Pubs   []*key.PublicKey
	Amount uint64
	Prev   *msg.Tx
	M      byte
}

func (p *PubInfo) redeemScript() []byte {
	scr := make([]byte, 0, 3+len(p.Pubs)*btcec.PubKeyBytesLenUncompressed)
	scr = append(scr, op1+(p.M-1))
	for _, pu := range p.Pubs {
		ser := pu.Serialize()
		scr = append(scr, byte(len(ser)))
		scr = append(scr, ser...)
	}
	scr = append(scr, op1+(byte(len(p.Pubs)-1)))
	return append(scr, opCHECKMULTISIG)
}

//MultisigOut creates multisig output.
func (p *PubInfo) MultisigOut() (*msg.Tx, error) {
	txouts := make([]msg.TxOut, 1, 2)
	script := make([]byte, 23)
	script = append(script, opHASH160)
	script = append(script, p.redeemScript()...)
	script = append(script, opEQUAL)
	txouts[0] = msg.TxOut{
		Value:     p.Amount,
		ScriptLen: msg.VarInt(len(script)),
		Script:    script,
	}
	txins, privs, mto, err := newTxins(p.Amount + params.Fee)
	if err != nil {
		return nil, err
	}
	if mto != nil {
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
	fillSign(&result, privs)

	return &result, nil
}

func (p *PubInfo) searchTxout() (uint32, error) {
	redeem := p.redeemScript()
	for i, out := range p.Prev.TxOut {
		if bytes.Equal(out.Script, redeem) {
			return uint32(i), nil
		}
	}
	return 0, errors.New("not found")
}

func (p *PubInfo) txForSign(seq, locktime uint32, sends ...*Send) (*msg.Tx, error) {
	total := params.Fee
	txouts, total, err := p2pkTxouts(sends...)
	if err != nil {
		return nil, err
	}
	if p.Amount < total {
		return nil, errors.New("total coins of output must be less than one of input")
	}
	log.Printf("fee %d", p.Amount-total)
	index, err := p.searchTxout()
	if err != nil {
		return nil, err
	}
	script := p.Prev.TxOut[index].Script
	mtxin := msg.TxIn{
		Hash:      p.Prev.Hash(),
		Index:     index,
		ScriptLen: msg.VarInt(len(script)),
		Script:    script,
		Seq:       seq,
	}
	mtx := msg.Tx{
		Version:  1,
		InCount:  1,
		TxIn:     []msg.TxIn{mtxin},
		OutCount: msg.VarInt(len(txouts)),
		TxOut:    txouts,
		Locktime: locktime,
	}

	return &mtx, nil
}

func (p *PubInfo) verify(mtx *msg.Tx, sign []byte, i int) error {
	var buf bytes.Buffer
	if err := msg.Pack(&buf, *mtx); err != nil {
		return err
	}
	beforeb := buf.Bytes()
	beforeb = append(beforeb, 0x01, 0, 0, 0) //hash code type
	h := sha256.Sum256(beforeb)
	h = sha256.Sum256(h[:])
	return p.Pubs[i].Verify(sign, h[:])
}

//SignMultisig signs multisig transaction by priv.
func (p *PubInfo) SignMultisig(priv *key.PrivateKey,
	seq, locktime uint32, sends ...*Send) ([]byte, error) {
	mtx, err := p.txForSign(seq, locktime, sends...)
	if err != nil {
		return nil, err
	}
	signs, err := signTx(mtx, []*key.PrivateKey{priv})
	if err != nil {
		return nil, err
	}
	return signs[0], nil
}

//MultisigIn creates multisig in Tx from send infos.
//Prev in PubInfo must be filled.
func (p *PubInfo) MultisigIn(seq, locktime uint32, sigs [][]byte, sends ...*Send) (*msg.Tx, error) {
	if len(sigs) == 0 || p.Prev == nil {
		return nil, errors.New("must fill sigs and prev in pubinfo")
	}
	mtx, err := p.txForSign(seq, locktime, sends...)
	if err != nil {
		return nil, err
	}
	redeem := p.redeemScript()
	script2 := make([]byte, 0, 33*len(sigs)+len(redeem)+1)
	for i, s := range sigs {
		if s == nil {
			pri := key.Find(p.Pubs[i])
			if pri == nil {
				return nil, fmt.Errorf("no private key from pubkey %d", i)
			}
			signs, err := signTx(mtx, []*key.PrivateKey{pri})
			if err != nil {
				return nil, err
			}
			s = signs[0]
		} else {
			if err := p.verify(mtx, s, i); err != nil {
				return nil, fmt.Errorf("%s at %d", err, i)
			}
		}
		script2 = append(script2, byte(len(s)))
		script2 = append(script2, s...)
	}
	script2 = append(script2, byte(len(redeem)))
	script2 = append(script2, redeem...)
	mtx.TxIn[0].ScriptLen = msg.VarInt(len(script2))
	mtx.TxIn[0].Script = script2

	return mtx, nil
}
