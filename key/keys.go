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
	"bytes"
	"errors"
	"log"

	"github.com/boltdb/bolt"
	"github.com/monarj/wallet/bloom"
	"github.com/monarj/wallet/db"
)

//AddScriptHash adds scripthash.
func AddScriptHash(hash []byte) error {
	return db.DB.Update(func(tx *bolt.Tx) error {
		return db.Put(tx, "scripthash", hash, hash)
	})
}

//RemoveScriptHash adds scripthash.
func RemoveScriptHash(hash []byte) error {
	return db.DB.Update(func(tx *bolt.Tx) error {
		return db.Del(tx, "scripthash", hash)
	})
}

//BloomFilter returns bloomfilter which filtered keys and scripthash.
func BloomFilter() bloom.Bloom {
	bf := bloom.New()
	klist := Get()
	for _, k := range klist {
		_, adr := k.Address()
		bf.Insert(k.PublicKey.Serialize())
		bf.Insert(adr)
	}
	err := db.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("scripthash"))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			bf.Insert(k)
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	return bf
}

//New creates , registers , and returns a randome key.
func New() *PrivateKey {
	k, err := Generate()
	if err != nil {
		log.Fatal(err)
	}
	Add(k)
	return k
}

//Find returns privatekey from pub.
//It returns nil if not found.
func Find(pub *PublicKey) *PrivateKey {
	var priv *PrivateKey
	err := db.DB.View(func(tx *bolt.Tx) error {
		dat, err := db.Get(tx, "key", pub.Serialize(), nil)
		if err != nil {
			return err
		}
		priv = NewPrivateKey(dat)
		return nil
	})
	if err != nil {
		return nil
	}
	return priv
}

//FromPubHash returns pubkey if list has pubhash pubkey.
func FromPubHash(pubhash []byte) (*PublicKey, error) {
	var pub *PublicKey
	errr := db.DB.View(func(tx *bolt.Tx) error {
		c := tx.Bucket([]byte("key")).Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			pubk, err := NewPublicKey(k)
			if err != nil {
				return err
			}
			_, hash := pubk.Address()
			if bytes.Equal(pubhash, hash) {
				pub = pubk
				return nil
			}
		}
		return errors.New("keyhash not found")
	})
	return pub, errr
}

//Add adds key to key list.
func Add(k *PrivateKey) {
	err := db.DB.Update(func(tx *bolt.Tx) error {
		return db.Put(tx, "key", k.PublicKey.Serialize(), k.Serialize())
	})
	if err != nil {
		log.Fatal(err)
	}
}

//Get gets key list.
func Get() []*PrivateKey {
	var l []*PrivateKey
	err := db.DB.View(func(tx *bolt.Tx) error {
		bu := tx.Bucket([]byte("key"))
		if bu == nil {
			return nil
		}
		c := bu.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			priv := NewPrivateKey(k)
			l = append(l, priv)
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	return l
}

//Remove removes the key from key list.
func Remove(k *PrivateKey) error {
	return db.DB.Update(func(tx *bolt.Tx) error {
		return db.Del(tx, "key", k.PublicKey.Serialize())
	})
}
