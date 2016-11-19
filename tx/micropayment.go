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
	"crypto/sha256"
	"errors"
	"log"

	"math"

	"github.com/monarj/wallet/key"
	"github.com/monarj/wallet/msg"
	"github.com/monarj/wallet/params"
	"golang.org/x/crypto/ripemd160"
)

//MicroPayer is struct for payer of micropayment.
type MicroPayer struct {
	*PubInfo
	priv *key.PrivateKey
}

//MicroPayee is struct for payee of micropayment.
type MicroPayee struct {
	*PubInfo
	priv *key.PrivateKey
}

//NewMicroPayer returns struct for payer.
func NewMicroPayer(payer *key.PrivateKey, payee []byte, amount uint64) (*MicroPayer, error) {
	var err error
	pk := make([]*key.PublicKey, 2)
	pk[0] = payer.PublicKey
	pk[1], err = key.NewPublicKey(payee)
	if err != nil {
		return nil, err
	}
	return &MicroPayer{
		PubInfo: &PubInfo{
			Pubs:   pk,
			Amount: amount,
			M:      2,
		},
		priv: payer,
	}, nil
}

//NewMicroPayee returns struct for payee.
func NewMicroPayee(payer []byte, payee *key.PrivateKey, amount uint64) (*MicroPayee, error) {
	var err error
	pk := make([]*key.PublicKey, 2)
	pk[0], err = key.NewPublicKey(payer)
	if err != nil {
		return nil, err
	}
	pk[1] = payee.PublicKey
	return &MicroPayee{
		PubInfo: &PubInfo{
			Pubs:   pk,
			Amount: amount,
			M:      2,
		},
		priv: payee,
	}, nil
}

func sendstruct(m *PubInfo, amount uint64) ([]*Send, error) {
	payer, _ := m.Pubs[0].Address()
	payee, _ := m.Pubs[1].Address()
	sends := make([]*Send, 0, 2)
	switch {
	case m.Amount-params.Fee-amount < 0:
		return nil, errors.New("negative amount for payer")
	case m.Amount-params.Fee-amount == 0:
	default:
		sends = append(sends, &Send{
			Addr:   payer,
			Amount: m.Amount - params.Fee - amount,
		})
	}
	switch {
	case amount < 0:
		return nil, errors.New("negative amount for payee")
	case amount == 0:
	default:
		sends = append(sends, &Send{
			Addr:   payee,
			Amount: amount,
		})
	}
	return sends, nil
}

//SignRefund sings refund tx.
func (m *MicroPayee) SignRefund(seq, locktime uint32) ([]byte, error) {
	sends, err := sendstruct(m.PubInfo, 0)
	if err != nil {
		return nil, err
	}
	return m.SignMultisig(m.priv, seq, locktime, sends...)
}

//CreateBond returns bond and refunc tx.
func (m *MicroPayer) CreateBond(seq, locktime uint32, sign []byte) (*msg.Tx, *msg.Tx, error) {
	bond, err := m.MultisigOut()
	if err != nil {
		return nil, nil, err
	}
	m.Prev = bond
	sends, err := sendstruct(m.PubInfo, 0)
	if err != nil {
		return nil, nil, err
	}
	refund, err := m.MultisigIn(seq, locktime, [][]byte{nil, sign}, sends...)
	if err != nil {
		return nil, nil, err
	}
	return bond, refund, nil
}

//Filter returns redeem script and its hash, which payee should wait for..
func (m *MicroPayee) Filter() ([]byte, []byte) {
	r := m.redeemScript()
	h := sha256.Sum256(r)
	ripeHash := ripemd160.New()
	if _, err := ripeHash.Write(h[:]); err != nil {
		log.Fatal(err)
	}
	ripeHashedBytes := ripeHash.Sum(nil)
	return r, ripeHashedBytes
}

//SignIncremented signs incremented tx..
func (m *MicroPayer) SignIncremented(amount uint64) ([]byte, error) {
	sends, err := sendstruct(m.PubInfo, amount)
	if err != nil {
		return nil, err
	}
	return m.SignMultisig(m.priv, math.MaxUint32, 0, sends...)
}

//IncrementedTx returns an incremented tx..
func (m *MicroPayee) IncrementedTx(amount uint64, sign []byte) (*msg.Tx, error) {
	sends, err := sendstruct(m.PubInfo, amount)
	if err != nil {
		return nil, err
	}
	return m.MultisigIn(math.MaxUint32, 0, [][]byte{sign, nil}, sends...)
}
