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

package key

import (
	"encoding/hex"
	"log"
	"testing"

	"github.com/monarj/wallet/btcec"
)

func TestKeys2(t *testing.T) {
	key, err := Generate()
	if err != nil {
		t.Errorf(err.Error())
	}
	adr, _ := key.Address()
	log.Println("address=", adr)
	wif := key.WIFAddress()
	log.Println("wif=", wif)

	key2, err := FromWIF(wif)
	if err != nil {
		t.Errorf(err.Error())
	}
	adr2, _ := key2.Address()
	log.Println("address2=", adr2)

	if adr != adr2 {
		t.Errorf("key unmatched")
	}
}

func TestKeys(t *testing.T) {
	key, err := Generate()
	if err != nil {
		t.Errorf(err.Error())
	}
	adr, _ := key.Address()
	log.Println("address=", adr)
	wif := key.WIFAddress()
	log.Println("wif=", wif)

	key2, err := FromWIF(wif)
	if err != nil {
		t.Errorf(err.Error())
	}
	adr2, _ := key2.Address()
	log.Println("address2=", adr2)

	if adr != adr2 {
		t.Errorf("key unmatched")
	}
}

func TestKeys3(t *testing.T) {
	seed := make([]byte, 32)
	_, err := hex.Decode(seed, []byte("3954e0c9a3ce58a8dca793e214232e569ff0cb9da79689ca56d0af614227d540"))
	if err != nil {
		t.Fatal(err)
	}
	s256 := btcec.S256()
	priv, pub := btcec.PrivKeyFromBytes(s256, seed)
	public := PublicKey{
		PublicKey:    pub,
		isCompressed: false,
	}
	private := PrivateKey{
		PrivateKey: priv,
		PublicKey:  &public,
	}
	wif := private.WIFAddress()
	if wif != "6ySkrpLpwm6gKsWo2aS6EL1SZxidZNdJkKqsKRNjXzv9WSrpHjR" {
		t.Errorf("wif not match %s", wif)
	}
	adr, _ := public.Address()
	if adr != "MB3D45ngvaWRcACUmAFUf6fzcdXR8bVM6k" {
		t.Errorf("address not match %s", adr)
	}
	log.Println(adr, wif)

	data := []byte("test data")
	sig, err := private.Sign(data)
	if err != nil {
		t.Fatal(err)
	}
	if err = private.PublicKey.Verify(sig, data); err != nil {
		t.Error(err)
	}
	data2 := []byte("invalid test data")
	if err = private.PublicKey.Verify(sig, data2); err == nil {
		t.Error("cannot verify")
	}
	log.Println(err)
}
