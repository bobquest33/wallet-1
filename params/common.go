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
	"encoding/hex"
	"log"
)

//GenesisParams is for params of the genesis block.
type GenesisParams struct {
	Difficulty int64
	Time       int64
	Nonce      int64
	Hash       []byte
}

func newGenesisParams(difficulty, time, nonce int64, hash string) *GenesisParams {
	h, err := hex.DecodeString(hash)
	if err != nil {
		log.Fatal(err)
	}
	return &GenesisParams{
		difficulty,
		time,
		nonce,
		h,
	}
}

const (
	//Version is the version of this program.
	Version = "0.00"
	//ProtocolVersion is the version which this program supports.
	ProtocolVersion uint32 = 70003
	//MainNet represents mainnet.
	MainNet = "main"
	//TestNet represents testnet.
	TestNet = "test"
	//SwitchLYRA2 is the block from which number LYRA2 protocol begins.
	SwitchLYRA2 = 450000
	//UserAgent is the user agent.
	UserAgent = "/monarj:" + Version + "/"
)

var (
	//SatoshiKey is the alert signing key originally owned by Satoshi, and now passed on to Gavin along with a few others.
	SatoshiKey []byte
)

func init() {
	var err error
	SatoshiKey, err = hex.DecodeString("04fc55d919cdea21e8171fea24c3cf23864ff64a53404829ad50af86e1be1b8217115701b348d50c6aaba6983bc148d3c9e6fa8c11365889774fc1db6da6840c06")
	if err != nil {
		log.Fatal(err)
	}
}
