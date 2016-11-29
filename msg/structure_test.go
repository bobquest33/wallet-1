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

package msg

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"testing"

	"github.com/monarj/wallet/behex"
	"github.com/monarj/wallet/params"
)

func TestMerkle(t *testing.T) {
	log.SetFlags(log.Ldate | log.Lshortfile | log.Ltime)

	inp := "01000000" +
		"82bb869cf3a793432a66e826e05a6fc3" +
		"7469f8efb7421dc88067010000000000" +
		"7f16c5962e8bd963659c793ce370d95f" +
		"093bc7e367117b3c30c1f8fdd0d97287" +
		"76381b4d" +
		"4c86041b" +
		"554b8529" +
		"07000000" +
		"04" +
		"3612262624047ee87660be1a707519a4" +
		"43b1c1ce3d248cbfc6c15870f6c5daa2" +
		"019f5b01d4195ecbc9398fbf3c3b1fa9" +
		"bb3183301d7a1fb3bd174fcfa40a2b65" +
		"41ed70551dd7e841883ab8f0b16bf041" +
		"76b7d1480e4f0af9f3d4c3595768d068" +
		"20d2a7bc994987302e5b1ac80fc425fe" +
		"25f8b63169ea78e68fbaaefa59379bbf" +
		"01" + "1d"

	result := "019f5b01d4195ecbc9398fbf3c3b1fa9bb3183301d7a1fb3bd174fcfa40a2b65"
	b, err := hex.DecodeString(inp)
	if err != nil {
		t.Fatal(err)
	}
	buf := bytes.NewBuffer(b)
	h := Merkleblock{}
	if err = Unpack(buf, &h); err != nil {
		t.Fatal(err)
	}
	txs, err := h.FilteredTx()
	if err != nil {
		t.Error(err)
	}
	if len(txs) != 1 {
		t.Error("len of txs is not 1")
	}
	if result != hex.EncodeToString(txs[0].Hash) {
		t.Error("tx does not match")
	}
}

func TestStruct(t *testing.T) {
	inputhex := []string{
		"020000004c1271c211717198227392b029a64a7971931d351b387bb80db027f270411e398a07046f7d4a08dd815412a8712f874a7ebf0507e3878bd24e20a3b73fd750a667d2f451eac7471b00de665900", "0200000011503ee6a855e900c00cfdd98f5f55fffeaee9b6bf55bea9b852d9de2ce35828e204eef76acfd36949ae56d1fbe81c1ac9c0209e6331ad56414f9072506a77f8c6faf551eac7471b00389d0100", "02000000a72c8a177f523946f42f22c3e86b8023221b4105e8007e59e81f6beb013e29aaf635295cb9ac966213fb56e046dc71df5b3f7f67ceaeab24038e743f883aff1aaafaf551eac7471b0166249b00", "010000007824bc3a8a1b4628485eee3024abd8626721f7f870f8ad4d2f33a27155167f6a4009d1285049603888fe85a84b6c803a53305a8d497965a5e896e1a00568359589faf551eac7471b0065434e00", "0200000050bfd4e4a307a8cb6ef4aef69abc5c0f2d579648bd80d7733e1ccc3fbc90ed664a7f74006cb11bde87785f229ecd366c2d4e44432832580e0608c579e4cb76f383f7f551eac7471b00c3698200",
	}

	expected := []string{
		"00000000002bef4107f882f6115e0b01f348d21195dacd3582aa2dabd7985806",
		"00000000003a0d11bdd5eb634e08b7feddcfbbf228ed35d250daf19f1c88fc94",
		"00000000000b40f895f288e13244728a6c2d9d59d8aff29c65f8dd5114a8ca81",
		"00000000003007005891cd4923031e99d8e8d72f6e8e7edc6a86181897e105fe",
		"000000000018f0b426a4afc7130ccb47fa02af730d345b4fe7c7724d3800ec8c",
	}

	for i, inp := range inputhex {
		b, err := hex.DecodeString(inp)
		if err != nil {
			t.Fatal(err)
		}
		buf := bytes.NewBuffer(b)
		h := BlockHeader{}
		if err = Unpack(buf, &h); err != nil {
			t.Fatal(err)
		}
		var buf2 bytes.Buffer
		if err = Pack(&buf2, h.HBlockHeader); err != nil {
			t.Fatal(err)
		}
		outs := behex.EncodeToString(params.PoWFunc(0, buf2.Bytes()))
		if outs != expected[i] {
			t.Error("scrypt not match", outs)
		}
		if err := h.IsOK(0); err != nil {
			t.Error("judged not ok", err)
		}
	}

	g := BlockHeader{}
	g.Bits = 0x181bc330
	target := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0xc3, 0x1b,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	fmt.Println(behex.EncodeToString(g.target()))
	fmt.Println(behex.EncodeToString(target))
	if !bytes.Equal(g.target(), target) {
		t.Fatal("nbits does not match with target")
	}

}
