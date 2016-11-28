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
	//GenesisHash is the hash of genesis blocks.
	GenesisHash []byte
	//CheckPoints are points hash should be checked.
	CheckPoints = make(map[uint64][]byte)
	//Prevs is previous block hash of CheckPoints.
	Prevs = make(map[uint64][]byte)
	//DNSSeeds is the list of dns for node seeds.
	DNSSeeds = []string{
		"dnsseed.monacoin.org",
		"dnsseed-multimona-test.tk",
		"seed.givememona.tk",
	}
)

func init() {
	var err error

	hashGenesis :=
		"ff9f1c0116d19de7c9963845e129f9ed1bfc0b376eb54fd7afa42e0d418c8bb6"
	if GenesisHash, err = behex.DecodeString(hashGenesis); err != nil {
		log.Fatal(err)
	}
	cpoints := map[uint64]string{
		0:      "ff9f1c0116d19de7c9963845e129f9ed1bfc0b376eb54fd7afa42e0d418c8bb6",
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
	prevs := map[uint64]string{
		0:      "0000000000000000000000000000000000000000000000000000000000000000",
		1500:   "9bfb0a32684c8e68839e08d59f2fbecc69586368540a2e1439e765d56072ff89",
		4000:   "82f94da36aa810abda67263b5c97bc821297dd17432ee3d81bccc0fe42ba0078",
		8000:   "cccfeff9a400a9dbd3b4d1ab181bc208cf08795558d2931483972e01b75cba47",
		16000:  "893efdeb009face8546e473469feba2950aa767de73b601e4572217083d99cd5",
		32000:  "a40c6ff7810f795c8c23f41fbe2a870278b3a4e7f68d66a46d21b06a678c9b51",
		58700:  "6fd4812b5c71362a7702182902deb7dd647ccbf1b1af924dcb797fc23d7a14d5",
		80000:  "d458aef846dd58f9a22d60ae7a98d3cdf2e25ed6863ef05d529102fc435e164f",
		115000: "4568160e0d97abc3cbc89f87fd5015a681fb5438de05dde791c9041847b8f960",
		189250: "0b660afcef545fa4fdfecd02e8694b8d319839f908e1dd9e3388232a05ef7e50",
		300000: "f9565504df0fd38529eb4d048e5ba2ce398b087dc202b315859677619a60543a",
		444000: "d165120dbb2a3ada178a7c40961e3ddef94646127335b996d589d3573f870bdd",
		655000: "fb72709f01a5a23fd998c71a1a2266dea3390e9ca59e18bacd80fe4626bdb7be",
	}
	for k, v := range prevs {
		h, err := behex.DecodeString(v)
		if err != nil {
			log.Fatal(err)
		}
		Prevs[k] = h
	}
}
