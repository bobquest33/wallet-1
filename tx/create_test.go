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
	"encoding/binary"
	"encoding/hex"
	"log"
	"testing"

	"math"

	"bytes"

	"github.com/boltdb/bolt"
	"github.com/monarj/wallet/behex"
	"github.com/monarj/wallet/db"
	"github.com/monarj/wallet/key"
	"github.com/monarj/wallet/msg"
	"github.com/monarj/wallet/params"
)

func setup() {
	err := db.DB.Update(func(tx *bolt.Tx) error {
		out := make([]byte, 8+32)
		binary.LittleEndian.PutUint64(out[:8], 100)
		return db.Put(tx, "status", []byte("lastblock"), out)
	})
	if err != nil {
		log.Fatal(err)
	}
}

func TestCreate2(t *testing.T) {
	setup()
	log.SetFlags(log.Ldate | log.Lshortfile | log.Ltime)

	//MTi4x2NtDpdyXSwEvwU3aZ1Uronz1JBNC3
	pkey, err := key.FromWIF("T81eGkQ2nrQZGvkcSKCtV1tZJ4WrsKhRsBA1jCgyfMdDjmn5TwGn")
	if err != nil {
		t.Fatal(err)
	}
	key.Add(pkey)

	//MAQnZ4FJ8rXPtRTZ9zwbwBmxaz9h9DTYxg
	pkey2, err := key.FromWIF("T4MzbNi83oaNzi8Yid22ZeNqHzaFhLqQkKmkffuQ58jR4ytz9QG2")
	if err != nil {
		t.Fatal(err)
	}
	//MWd1DJDeuXrdYD5dPpdUvoxHKvxVvAE8cs
	pkey3, err := key.FromWIF("T9QEmRobyTDTJe4qzSEu2mD1SMu6Wtzun6xkawnwRpBX5brimeCN")
	if err != nil {
		t.Fatal(err)
	}

	txhashes := []string{
		"12c2f61d839b2b38146715e4dfc0fd914906253920480298816f108513e53e5c",
		"12c2f61d839b2b38146715e4dfc0fd988806253920480298816f108513e53e5c",
	}

	script, err := hex.DecodeString("76a914d94987ba89c258372030bc9d610f89547757896488ac")
	if err != nil {
		t.Fatal(err)
	}
	redeem, err := hex.DecodeString("52210235dad6f5b0655e5ec633e71c3d8e0acee49a314c76a2650f6d60bc291d631c9d2103bd9b94f58dd51233a1380accd944aa44d9846fab673497ca4de794f79ecdbccd210373f0f5d4488616b20537810f5281ea27dd65213fa40be696086c6d2c3319419e53ae")
	if err != nil {
		t.Fatal(err)
	}
	hashout, err := hex.DecodeString("938fec7fa5ab2d7d3f5febe71bc295bfaa4b8fdf2cf414c3d7e5fccd56942364")
	if err != nil {
		t.Fatal(err)
	}
	values := []uint64{100 * params.Unit, 150 * params.Unit}

	for i, h := range txhashes {
		var ha []byte
		ha, err = behex.DecodeString(h)
		if err != nil {
			t.Fatal(err)
		}
		coin := &Coin{
			Pubkey:   pkey.PublicKey.Serialize(),
			TxHash:   ha,
			Value:    values[i],
			Ttype:    0,
			Block:    params.GenesisHash,
			Script:   script,
			TxIndex:  uint32(i + 1),
			Coinbase: false,
		}
		if err = coin.save(); err != nil {
			t.Fatal(err)
		}
	}
	pi := &PubInfo{
		Pubs:   []*key.PublicKey{pkey2.PublicKey, pkey3.PublicKey, pkey.PublicKey},
		Amount: 200 * params.Unit,
		M:      2,
	}

	txout, err := pi.MultisigOut()
	if err != nil {
		t.Fatal(err)
	}
	log.Print("!")
	if !bytes.Equal(redeem, pi.redeemScript()) {
		t.Fatal("redeem script is illegal")
	}
	log.Println(hex.EncodeToString(txout.Hash()))
	log.Println(hex.EncodeToString(txout.TxOut[0].Script))
	log.Println(hex.EncodeToString(pi.redeemScript()))

	var buf bytes.Buffer
	if err = msg.Pack(&buf, *txout); err != nil {
		t.Fatal(err)
	}
	byt := buf.Bytes()
	log.Println(hex.EncodeToString(byt))
	for _, in := range txout.TxIn {
		slen := in.Script[0]
		script = in.Script[1:slen]
		//in.Script[slen]=0x01,in.Script[slen+1]=length of pubkey
		var pubk *key.PublicKey
		pubk, err = key.NewPublicKey(in.Script[slen+2:])
		if err != nil {
			t.Fatal(err)
		}
		if err = pubk.Verify(script, hashout); err != nil {
			t.Error("illegal tx")
		}
	}

	//for test
	scr := "483045022100902c0effe741979fd353a038897ab7eee17e1bea3ea8987298e52539de9a70f20220458310b9129b1123a72b22f0206857bec67b71d1e3df3502c8adef93f37818e801210373f0f5d4488616b20537810f5281ea27dd65213fa40be696086c6d2c3319419e"
	txhash := "1eb8d0cfd1963d6295fcb5a76800fb8ae0a0c5332c349131d9bdf3d340f57eed"
	scrb, err := hex.DecodeString(scr)
	if err != nil {
		t.Fatal(err)
	}
	pi.Prev.TxIn[0].Script = scrb
	pi.Prev.TxIn[1].Script = scrb
	txhashb, err := behex.DecodeString(txhash)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pi.Prev.Hash(), txhashb) {
		t.Fatal("tx unamtches")
	}
	hashin, err := hex.DecodeString("c19a154a97e2fbc86f1b647f4e610a74932c33144a09f16b400c6354a7258090")
	if err != nil {
		t.Fatal(err)
	}

	send := &Send{
		Addr:   "MTi4x2NtDpdyXSwEvwU3aZ1Uronz1JBNC3",
		Amount: 200*params.Unit - params.Fee,
	}
	sig2, err := pi.SignMultisig(pkey2, math.MaxUint32, 0, send)
	if err != nil {
		t.Fatal(err)
	}

	tx, err := pi.MultisigIn(math.MaxUint32, 0, [][]byte{sig2, nil, nil}, send)
	if err != nil {
		t.Fatal(err)
	}

	var buf2 bytes.Buffer
	if err = msg.Pack(&buf2, *tx); err != nil {
		t.Fatal(err)
	}
	byt = buf2.Bytes()
	log.Println(hex.EncodeToString(byt))
	slen := tx.TxIn[0].Script[1]
	script = tx.TxIn[0].Script[2 : slen+2]
	if err = pkey2.PublicKey.Verify(script, hashin); err != nil {
		t.Error("illegal tx")
	}
	slen2 := tx.TxIn[0].Script[slen+2]
	script = tx.TxIn[0].Script[slen+3 : slen+slen2+3]
	if err = pkey.PublicKey.Verify(script, hashin); err != nil {
		t.Error("illegal tx")
	}
}

func TestCreate1(t *testing.T) {
	setup()
	log.SetFlags(log.Ldate | log.Lshortfile | log.Ltime)

	//MTi4x2NtDpdyXSwEvwU3aZ1Uronz1JBNC3
	pkey, err := key.FromWIF("T81eGkQ2nrQZGvkcSKCtV1tZJ4WrsKhRsBA1jCgyfMdDjmn5TwGn")
	if err != nil {
		t.Fatal(err)
	}
	ad, _ := pkey.Address()
	log.Println(ad)
	txhashes := []string{
		"12c2f61d839b2b38146715e4dfc0fd914906253920480298816f108513e53e5c",
		"12c2f61d839b2b38146715e4dfc0fd988806253920480298816f108513e53e5c",
	}
	script, err := hex.DecodeString("76a914d94987ba89c258372030bc9d610f89547757896488ac")
	if err != nil {
		t.Fatal(err)
	}
	values := []uint64{100 * params.Unit, 150 * params.Unit}
	hashresult, err := hex.DecodeString("54d2f42aa370fea481145a699a86191f625b01e0160427062bb01fca91cb644c")
	if err != nil {
		t.Fatal(err)
	}

	key.Add(pkey)

	for i, h := range txhashes {
		var ha []byte
		ha, err = behex.DecodeString(h)
		if err != nil {
			t.Fatal(err)
		}
		coin := &Coin{
			Pubkey:   pkey.PublicKey.Serialize(),
			TxHash:   ha,
			Value:    values[i],
			Ttype:    0,
			Block:    params.GenesisHash,
			Script:   script,
			TxIndex:  uint32(i + 1),
			Coinbase: false,
		}
		if err = coin.save(); err != nil {
			log.Fatal(err)
		}
	}
	send := &Send{
		Addr:   "MS43dMzRKfEs99Q931zFECfUhdvtWmbsPt",
		Amount: 200 * params.Unit,
	}
	tx, err := NewP2PK(send)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err = msg.Pack(&buf, *tx); err != nil {
		t.Fatal(err)
	}
	byt := buf.Bytes()
	log.Println(hex.EncodeToString(byt))
	for _, in := range tx.TxIn {
		slen := in.Script[0]
		script := in.Script[1:slen]
		//in.Script[slen]=0x01,in.Script[slen+1]=length of pubkey
		pubk, err := key.NewPublicKey(in.Script[slen+2:])
		if err != nil {
			t.Fatal(err)
		}
		if err = pubk.Verify(script, hashresult); err != nil {
			t.Error("illegal tx")
		}
	}
}
