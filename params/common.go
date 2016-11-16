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

	"golang.org/x/crypto/scrypt"
)

var (
	//PoWFunc is a func to calculate PoW.
	PoWFunc func(int, []byte) []byte = func(height int, data []byte) []byte {
		if height >= 450000 {
			return Lyra2REv2(data)
		}
		converted, err := scrypt.Key(data, data, 1024, 1, 1, 32)
		if err != nil {
			log.Fatal(err)
		}
		return converted
	}
)

const (
	//Version is the version of this program.
	Version = "0.0.0"
	//ProtocolVersion is the version which this program supports.
	ProtocolVersion uint32 = 70003
	//MainNet represents mainnet.
	MainNet = "main"
	//TestNet represents testnet.
	TestNet = "test"

	//UserAgent is the user agent.
	UserAgent = "/monarj:" + Version + "/"
	//Nconfirmed is the block height block is regarded as confirmed.
	Nconfirmed = 5
	//Unit is base unit.
	Unit = 100000000
	//Fee for a transaction
	Fee = uint64(0.001 * Unit) //  1m MONA/kB
)

//TODO
func Lyra2REv2(data []byte) []byte {
	return nil
}
