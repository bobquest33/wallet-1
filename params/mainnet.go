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

package params

import (
	"log"

	"github.com/monarj/wallet/behex"
)

const (
	//DumpedPrivateKeyHeader is the first byte of a base58 encoded dumped private key.
	DumpedPrivateKeyHeader byte = 178 //This is always addressHeader + 128
	//DumpedPrivateKeyHeaderAlt  is another first byte of a base58 encoded dumped private key.
	DumpedPrivateKeyHeaderAlt byte = 176 // monacoin-qt 0.10.x (not modified from litecoin ...)
	//AddressHeader is the First byte of a base58 encoded address. This the one used for "normal" addresses.
	AddressHeader byte = 50
	//P2SHHeader is the first byte of a base58 encoded P2SH address.  P2SH addresses are defined as part of BIP0013.
	P2SHHeader = 5
	//ID is id to identify testnet or mainnet.
	ID = MainNet
	//Port is the default port of listen.
	Port = 9401
	//SpendableCoinbaseDepth is the block depth constrains when coinbase is used.
	SpendableCoinbaseDepth = 100
	//ProofOfWorkLimit is the upper limits of target in nBits format.
	ProofOfWorkLimit = 0x1e0fffff
)

var (
	//PacketMagic is  the header bytes that identify the start of a packet on this network
	PacketMagic = []byte{0xfb, 0xc0, 0xb6, 0xdb}
	//GenesisVersion is the version of genesis blocks.
	GenesisVersion uint32 = 1
	//GenesisTime is the time of genesis blocks.
	GenesisTime uint32 = 1388479472
	//GenesisBits is the nBits of genesis blocks.
	GenesisBits uint32 = 0x1e0ffff0
	//GenesisNonce is the nonce of genesis blocks.
	GenesisNonce = []byte{0x66, 0xd6, 0x12, 0x00}
	//GenesisMerkle is the merkle root of genesis blocks.
	GenesisMerkle []byte
	//GenesisHash is the hash of genesis blocks.
	GenesisHash []byte
	//CheckPoints are points hash should be checked.
	CheckPoints = make(map[uint64][]byte)
	//DNSSeeds is the list of dns for node seeds.
	DNSSeeds = []string{
		"dnsseed.monacoin.org",
		"dnsseed-multimona-test.tk",
		"seed.givememona.tk",
		"api.monaco-ex.org",
	}
)

func init() {
	var err error
	merkleGenesis :=
		"35e405a8a46f4dbc1941727aaf338939323c3b955232d0317f8731fe07ac4ba6"
	if GenesisMerkle, err = behex.DecodeString(merkleGenesis); err != nil {
		log.Fatal(err)
	}
	hashGenesis :=
		"ff9f1c0116d19de7c9963845e129f9ed1bfc0b376eb54fd7afa42e0d418c8bb6"
	if GenesisHash, err = behex.DecodeString(hashGenesis); err != nil {
		log.Fatal(err)
	}
	cpoints := map[uint64]string{
		1500:   "9f42d51d18d0a8914a00664c433a0ca4be3eed02f9374d790bffbd3d3053d41d",
		4000:   "2c60edac7d9f44d90d1e218af2a8085e78b735185c5bf42f9fe9dbd0e604c97b",
		8000:   "61d4d053b1a4c6deb4c7e806cedd876f25b51da6c51b209109579c7b9892e5c2",
		16000:  "3c4a8887bb3ae0599abfefe765f7c911fbfe98b3f23d7f70b05bf49cf62ebdaf",
		32000:  "c0703986c1c6a9052478db5e52432e5a1e55d6b6362b85f0ffdbb61ce3311b77",
		58700:  "a9c5d9878864b77ba52b068787b83ce2fcf526c5899f40af51c9d441eeb4c84d",
		80000:  "c99b83da7328b58251d16f4646da222b0280f180bd208efa5e3256c9eb6ea2be",
		115000: "75e642c003e5bd748b679472e981b7b2f81f344b3f197029f84470256cef33e4",
		189250: "1bea3d5c25a8097eef2e70ece4beb6c502b895fe00056552948309beb3497c99",
		300000: "11095515590421444ba29396d9122c234baced79be8b32604acc37cf094558ab",
		444000: "3ed05516cdce4db93b135189592c7e2b37d768f99a1819a1d2ea3a8e5b8439a8",
		655000: "4c556ef37bc75e95820200d2ae25472d7e2c05a981667beef5b2f6a64b5ce546",
	}
	for k, v := range cpoints {
		h, err := behex.DecodeString(v)
		if err != nil {
			log.Fatal(err)
		}
		CheckPoints[k] = h
	}
}
