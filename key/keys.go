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
	"log"
	"sync"
)

var (
	//list is a keylist.
	list []*Key

	mutex sync.RWMutex
)

//New creates , registers , and returns a randome key.
func New() *Key {
	mutex.Lock()
	defer mutex.Unlock()
	k, err := GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	Add(k)
	return k
}

//HasPubkey returns true if list has pub.
func HasPubkey(pub *PublicKey) bool {
	mutex.RLock()
	defer mutex.RUnlock()
	for _, k := range list {
		if pub.IsEqual(k.Pub.PublicKey) {
			return true
		}
	}
	return false
}

//HasPubHash returns true if list has pubhash pubkey.
func HasPubHash(pubhash []byte) (*PublicKey, bool) {
	mutex.RLock()
	defer mutex.RUnlock()
	for _, k := range list {
		_, hash := k.Pub.GetAddress()
		if bytes.Equal(pubhash, hash) {
			return k.Pub, true
		}
	}
	return nil, false
}

//Add adds key to key list.
func Add(k *Key) {
	mutex.Lock()
	defer mutex.Unlock()
	list = append(list, k)
}

//Get gets key list.
func Get() []*Key {
	mutex.RLock()
	defer mutex.RUnlock()
	l := make([]*Key, len(list))
	copy(l, list)
	return l
}

//Remove removes the key from key list.
func Remove(k *Key) {
	mutex.Lock()
	defer mutex.Unlock()
	for i, kl := range list {
		s1, _ := k.Pub.GetAddress()
		s2, _ := kl.Pub.GetAddress()
		if s1 == s2 {
			list = append(list[:i], list[i+1:]...)
			list[len(list)-1] = nil
			return
		}
	}
}
