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
	"crypto/sha256"
	"errors"
	"fmt"
	"log"

	"github.com/monarj/wallet/base58check"
	"github.com/monarj/wallet/btcec"
	"github.com/monarj/wallet/params"
	"golang.org/x/crypto/ripemd160"
)

//PublicKey represents public key for bitcoin
type PublicKey struct {
	*btcec.PublicKey
	isCompressed bool
}

//PrivateKey represents private key for bitcoin
type PrivateKey struct {
	*btcec.PrivateKey
	PublicKey *PublicKey
}

//NewPublicKey returns PublicKey struct using public key hex string.
func NewPublicKey(pubKeyByte []byte) (*PublicKey, error) {
	secp256k1 := btcec.S256()
	key, err := btcec.ParsePubKey(pubKeyByte, secp256k1)
	if err != nil {
		return nil, err
	}
	isCompressed := false
	if len(pubKeyByte) == btcec.PubKeyBytesLenCompressed {
		isCompressed = true
	}
	return &PublicKey{PublicKey: key, isCompressed: isCompressed}, nil
}

//FromWIF gets PublicKey and PrivateKey from private key of WIF format.
func FromWIF(wif string) (*PrivateKey, error) {
	secp256k1 := btcec.S256()
	pb, err := base58check.Decode(wif)
	if err != nil {
		return nil, err
	}

	if pb[0] != params.DumpedPrivateKeyHeader && pb[0] != params.DumpedPrivateKeyHeaderAlt {
		return nil, errors.New("private key is not for " + params.ID)
	}
	isCompressed := false
	if len(pb) == btcec.PrivKeyBytesLen+2 && pb[btcec.PrivKeyBytesLen+1] == 0x01 {
		pb = pb[:len(pb)-1]
		isCompressed = true
		log.Println("compressed")
	}

	//Get the raw public
	priv, pub := btcec.PrivKeyFromBytes(secp256k1, pb[1:])
	return &PrivateKey{
		PrivateKey: priv,
		PublicKey: &PublicKey{
			PublicKey:    pub,
			isCompressed: isCompressed,
		},
	}, nil
}

//Generate generates random PublicKey and PrivateKey.
func Generate() (*PrivateKey, error) {
	secp256k1 := btcec.S256()
	prikey, err := btcec.NewPrivateKey(secp256k1)
	if err != nil {
		return nil, err
	}
	key := &PrivateKey{
		PublicKey: &PublicKey{
			PublicKey:    prikey.PubKey(),
			isCompressed: true,
		},
		PrivateKey: prikey,
	}

	//Print the keys
	log.Println("Your private key in WIF is")
	log.Println(key.WIFAddress())

	log.Println("Your address is")
	log.Println(key.PublicKey.Address())

	return key, nil
}

//Sign sign data.
func (priv *PrivateKey) Sign(hash []byte) ([]byte, error) {
	sig, err := priv.PrivateKey.Sign(hash)
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}

//WIFAddress returns WIF format string from PrivateKey
func (priv *PrivateKey) WIFAddress() string {
	p := priv.Serialize()
	if priv.PublicKey.isCompressed {
		p = append(p, 0x1)
	}
	return base58check.Encode(params.DumpedPrivateKeyHeader, p)
}

//Serialize serializes public key depending on isCompressed.
func (pub *PublicKey) Serialize() []byte {
	if pub.isCompressed {
		return pub.SerializeCompressed()
	}
	return pub.SerializeUncompressed()
}

//Address returns bitcoin address from PublicKey
func (pub *PublicKey) Address() (string, []byte) {
	//Next we get a sha256 hash of the public key generated
	//via ECDSA, and then get a ripemd160 hash of the sha256 hash.
	shadPublicKeyBytes := sha256.Sum256(pub.Serialize())

	ripeHash := ripemd160.New()
	if _, err := ripeHash.Write(shadPublicKeyBytes[:]); err != nil {
		log.Fatal(err)
	}
	ripeHashedBytes := ripeHash.Sum(nil)

	publicKeyEncoded := base58check.Encode(params.AddressHeader,
		ripeHashedBytes)
	return publicKeyEncoded, ripeHashedBytes
}

//Address returns bitcoin address from PublicKey
func (priv *PrivateKey) Address() (string, []byte) {
	return priv.PublicKey.Address()
}

//DecodeAddress converts bitcoin address to hex form.
func DecodeAddress(addr string) ([]byte, error) {
	pb, err := base58check.Decode(addr)
	if err != nil {
		return nil, err
	}
	return pb[1:], nil
}

//Verify verifies signature is valid or not.
func (pub *PublicKey) Verify(signature []byte, data []byte) error {
	secp256k1 := btcec.S256()
	sig, err := btcec.ParseSignature(signature, secp256k1)
	if err != nil {
		return err
	}
	valid := sig.Verify(data, pub.PublicKey)
	if !valid {
		return fmt.Errorf("signature is invalid")
	}
	return nil
}
