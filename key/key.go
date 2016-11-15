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
}

//Key includes PublicKey and PrivateKey.
type Key struct {
	Pub  *PublicKey
	Priv *PrivateKey
}

//GetPublicKey returns PublicKey struct using public key hex string.
func GetPublicKey(pubKeyByte []byte) (*PublicKey, error) {
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

//GetKeyFromWIF gets PublicKey and PrivateKey from private key of WIF format.
func GetKeyFromWIF(wif string) (*Key, error) {
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

	pubk := PublicKey{PublicKey: pub, isCompressed: isCompressed}
	privk := PrivateKey{PrivateKey: priv}
	key := Key{
		Pub:  &pubk,
		Priv: &privk,
	}
	return &key, nil

}

//GenerateKey generates random PublicKey and PrivateKey.
func GenerateKey() (*Key, error) {
	secp256k1 := btcec.S256()
	prikey, err := btcec.NewPrivateKey(secp256k1)
	if err != nil {
		return nil, err
	}
	key := Key{
		Pub: &PublicKey{
			PublicKey:    prikey.PubKey(),
			isCompressed: true,
		},
		Priv: &PrivateKey{
			PrivateKey: prikey,
		},
	}

	//Print the keys
	log.Println("Your private key in WIF is")
	log.Println(key.GetWIFAddress())

	log.Println("Your address is")
	log.Println(key.Pub.GetAddress())

	return &key, nil
}

//Sign sign data.
func (priv *PrivateKey) Sign(hash []byte) ([]byte, error) {
	sig, err := priv.PrivateKey.Sign(hash)
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}

//SignMessage sign using bitcoin sign struct
func (key *Key) SignMessage(hash []byte) ([]byte, error) {
	msg := append([]byte("\x18Bitcoin Signed Message:\n"), byte(len(hash)))
	msg = append(msg, hash...)
	h := sha256.Sum256(msg)
	hh := sha256.Sum256(h[:])
	s256 := btcec.S256()
	sig, err := btcec.SignCompact(s256, key.Priv.PrivateKey, hh[:], key.Pub.isCompressed)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

//GetWIFAddress returns WIF format string from PrivateKey
func (key *Key) GetWIFAddress() string {
	return key.Priv.GetWIFAddress(key.Pub.isCompressed)
}

//GetWIFAddress returns WIF format string from PrivateKey
func (priv *PrivateKey) GetWIFAddress(isCompressed bool) string {
	p := priv.Serialize()
	if isCompressed {
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

//GetAddress returns bitcoin address from PublicKey
func (pub *PublicKey) GetAddress() (string, []byte) {
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
