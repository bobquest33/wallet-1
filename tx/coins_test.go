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

package tx

import (
	"bytes"
	"encoding/hex"
	"log"
	"testing"

	"github.com/boltdb/bolt"
	"github.com/monarj/wallet/behex"
	"github.com/monarj/wallet/db"
	"github.com/monarj/wallet/key"
	"github.com/monarj/wallet/msg"
	"github.com/monarj/wallet/params"
)

func del() {
	errr := db.DB.Update(func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket([]byte("key")); err != nil {
			return err
		}
		if err := tx.DeleteBucket([]byte("coin")); err != nil {
			return err
		}
		return nil
	})
	if errr != nil {
		log.Print(errr)
	}
}

func addpubkey(addr string) *key.PublicKey {
	a, err := hex.DecodeString(addr)
	if err != nil {
		log.Fatal(err)
	}
	pub, err := key.NewPublicKey(a)
	if err != nil {
		log.Fatal(err)
	}
	p, err := key.Generate()
	if err != nil {
		log.Fatal(err)
	}
	//only for test
	err = db.DB.Update(func(tx *bolt.Tx) error {
		return db.Put(tx, "key", a, p.Serialize())
	})
	if err != nil {
		log.Fatal(err)
	}
	return pub
}

func maketx(stx []string) []*msg.Tx {
	txs := make([]*msg.Tx, len(stx))
	for i, tx := range stx {
		t, err := hex.DecodeString(tx)
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewBuffer(t)
		mtx := msg.Tx{}
		if err := msg.Unpack(buf, &mtx); err != nil {
			log.Fatal(err)
		}
		if buf.Len() != 0 {
			log.Fatal("not use whole bytes")
		}
		txs[i] = &mtx
		log.Print(i, " ", behex.EncodeToString(txs[i].Hash()))
	}
	return txs
}

func TestTx1(t *testing.T) {
	del()
	log.SetFlags(log.Ldate | log.Lshortfile | log.Ltime)

	// MQesEqAZNxeNNHS2XDNy23ozchyt1PXX2G
	addr := "0341573692e18d367df964ba1effc151c5952a6128a0f973cb5006b0151d32e517"

	stx := []string{
		//coinbase->MQesEqAZNxeNNHS2XDNy23ozchyt1PXX2G,50mona
		"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2703a51f04062f503253482f049434515408f829e69b910100000d2f7374726174756d506f6f6c2f000000000100f2052a010000001976a914b7c62137082c0846943c1b8d1c3eab628baa156f88ac00000000",
		// MQesEqAZNxeNNHS2XDNy23ozchyt1PXX2G -> 50mona
		"010000000188fa5c97be66845170db81a582888c55b24ca78943314f0a2d63c0b252854b4b000000006b483045022100a2e4bdc593bacb5918ac06dd6a718087c202dd7b8a8f5b62a243320c79c0629c022018e857dcdaa1afada0ebdf9b3f1086a95a70852d64fafd9d5233815392e5f81801210341573692e18d367df964ba1effc151c5952a6128a0f973cb5006b0151d32e517ffffffff04e2d10e06000000001976a914872455664fee9e4e9b5985f7ff09a3dfbd73bae688acaff98441000000001976a91431f10038a4debd33ca2d1c675575dc419b4b5fa288ac3a6eff6b000000001976a9146c1d53b7b5c18f34ad012c15439e4a0deb7c6b7988ac35b87276000000001976a914da2f111a4e3e2e88947577ae06b8e31958c887e788ac00000000",
	}
	coins, err := getCoins(nil)
	if len(coins) != 0 {
		t.Fatal(len(coins))
	}
	a := addpubkey(addr)
	txs := maketx(stx)
	if err = Add(txs[0], 0); err != nil {
		t.Fatal(err)
	}
	coins, err = getCoins(a)
	if err != nil {
		t.Fatal(err)
	}
	if len(coins) != 1 {
		t.Fatal("could not add coin", len(coins))
	}
	if coins[0].Value != 50*params.Unit {
		t.Fatal("value differes", coins[0].Value)
	}
	log.Println("adding tx")
	if err = Add(txs[1], 0); err != nil {
		t.Fatal(err)
	}
	coins, err = getCoins(a)
	if err != nil {
		t.Fatal(err)
	}
	if len(coins) != 0 {
		t.Fatal("cound not remove coin", len(coins))
	}
}

func TestTx2(t *testing.T) {
	del()

	// MUW2hLe4EMbxBERpoavpv7bz1LKXEnR4qw
	addr := "03f696acc30af622a3fdb489ff3b8ce1b2c9833f2053c842d3e83bb17b89ac8ca4"

	stx := []string{
		//coinbase->MQesEqAZNxeNNHS2XDNy23ozchyt1PXX2G,100mona
		"0100000004abcdeba2cd83533869c6b26c19a0ea4b6d21c728ea966382e62f7272cd663d1d010000006a47304402205fb201021e5601fba023582417dc8b15f241b3aac4a22252354a99f267adfcb1022004b7c83c8aa5f82edf40c46e62e215468a854a7e5242945c20cc9933fc8ee4df0121038edce35ae11525d7650b948b47db5d9751a5ed51346037eced60e562eb131806ffffffff6c13febe03f0205088a92b8d828953d2ee933e16772c9005577f44b138add469000000006a47304402207a6eb76253f16689862b680bf60ee06a58237ce7feaa72d21119418a6772a3c702205f557b7d96025ed22e6200696ba3fb187dac562042a7583f8d10ccaa3d68bc5101210205293d8559b12701c34ff4a6024368a5fe82ba64ee49d64c25902fbce3dce1b4ffffffff54b2ee51a8e82a49877935536ed11181dbbdc0f2dc36d3291b527b6fe7c515d8000000006a473044022054562599ada5fae10f2c0d97e1adf27d461beafe164e35cc9eb6539acbf190220220558dec98e6b94a6d9abc0544caa2bceb8ca80c487e3cdee0cc62b6ac52eb7179012102c0b04c3feb93449b415703be462efc285142e77ee4c06ee91ab342d503120b7dffffffff32470179bf04448359f0bc10be52c39245aff55bc1c4601794a6c404d732885b000000006a47304402205758d478776e2f370c72d4dc4748b4b9d9237fdff9ea67ba6ec4314d7fae965502200a1a4779372e8b8231086f06b7c5683ae1fa8bb7d2491d5b2a35e006611fed970121024acd8ae3dbc099f30525849dafa4a3cf4b8e2d0a76776c2457515afa6920778effffffff0200e40b54020000001976a914e1fac8978a2ad53c9275d8aefd5b05b1a769698f88ac57601b00000000001976a9143ad37564d6c7979f76992436e9c5f068063fa31388ac00000000",
		// 03f696acc30af622a3fdb489ff3b8ce1b2c9833f2053c842d3e83bb17b89ac8ca4 -> 100mona
		"010000000eb386ec2bfb567fb1e2aa243f05e1a46f9946b42c3a04c986574cae9a853e9ea2010000006a47304402201ed80e99f76eb87f143f9ac6054039fac53ef0c0b98844847135f1755113c8a0022047ad3ebf9c171e9165ccbbd4bfce12495b0bd6bad6cf8efe0bca4fd50329c43a0121035185ab3a4d579d0f16123562124d42b94afd2cf8ec42962d84e365c884ef7d49ffffffff01768652b583658f00c0f889bc37c9b4468215165b8e0f9979deaf8c7a3b78aa010000006a473044022064fc61f89c00ee522b43a1fddc90a20857b475e43b520864d092472b35d8624e022032e0c4e43e3d0d85d9ea7a753e9c3ad48066c3179614170a16ec69ef5b11186d0121035185ab3a4d579d0f16123562124d42b94afd2cf8ec42962d84e365c884ef7d49ffffffffddc141774b6709a849c58d432a6700ba24981d7f7e2bae064391089d0306f7d8000000006a4730440220773297c047edbed926a61fab66e08141921801adf619ebad01cc1b71c1e8eab8022012edfd1368d0eb44962864fb961d4b35e35a1b406ae9df8a63132590cc7e4743012103f696acc30af622a3fdb489ff3b8ce1b2c9833f2053c842d3e83bb17b89ac8ca4ffffffff929bc905e32eb67aafaaa64bb1884134675858aaa0743ed4e8cf3e24d498830a010000006b483045022100a6e47431d5d03d39cebc4bc25c95de8bb7936418432183acfcbbfe17954e2ad802205dd3ba1a47a83b95544095a3cae56b1f5e0c3fd8384fd0970b24efaba0df570c0121035185ab3a4d579d0f16123562124d42b94afd2cf8ec42962d84e365c884ef7d49ffffffff5e90759836c3bd58c687fc00d1d3cbdc49a11d3b81f70432d1e5d63d17ad1d3e000000006b483045022100f4312c4a5472b575c92d09ca7a314ab8bcc3e66591f6ddddaf8d43e024f36da702202a83cfded00748567f1a1aff837bc740ce8136dcace9774de068d6b0ba7ae95a0121031016376152af9d616aba508b27c50d56167e83e86781d853d6480cd97d57b097ffffffffb891b1f589b730cb059fdd500225f2fc50885c0625bc8d685b25a3cd5b643ed7010000006b483045022100cc641bc45da53658f45407e6b470791bcff6cfe6ba605773f3a0b814f0be97e702200992e0cace0f90070dcf82a6edd98889f4342b333fc39dba4d2ad122233c87ac0121035185ab3a4d579d0f16123562124d42b94afd2cf8ec42962d84e365c884ef7d49ffffffffa728a08353a1b9c28360dafaa166b69c8eedb61768e2cc70eab1bcd03f32727c010000006b483045022100e1c9ae2719693337b4970d81512934a27733bfeeb1f86fa3a6fb94262523f67d02203952a747464ba2ceb69570c5405ee4be26ec2510c89f42b0cab952bc3050fea20121027d263a7531e6c89260995ac312eff4ff7afa659626015b60e5b3cba079734e6bffffffff3ca318115c78fa9c07fafd31077034c2b5981daaa03a87e42c6ba687ebf4d66e000000006a473044022064df58c868162d24c7262b72f7ec75dea9445d91762afc24662549dd2d6e5c1e022077e11cc1f8b9f697173d3421de1b661d5d997e103f52b0b83629033a593b00190121035185ab3a4d579d0f16123562124d42b94afd2cf8ec42962d84e365c884ef7d49ffffffff0271124b7e69e526d44c772654e1a149fe900d961b6035d1912cfbdb1060d2af000000006a47304402203efb97e50d0ca0a1dd53549483a28241ac098b28f78c7f459c79a4c8894fa0c5022053047e5437366473503d1aef9c83b3d004dc6ed0fa9d76c5337c94a5415a2afa0121035185ab3a4d579d0f16123562124d42b94afd2cf8ec42962d84e365c884ef7d49ffffffff15ddb17ab5169d0d47c7480dda7fe6c81b36d5f7c0fb8d43e1f40e283fca1102010000006b483045022100a27fdf597a719322efb3bca18ea10b3b9cda98b3cd09ee3ff08746fd63dd761602202a25f7892ead35dbc9b96b41612ccca1a96f6e1bfe9e3d4a0f2946e6e92abb9b0121035185ab3a4d579d0f16123562124d42b94afd2cf8ec42962d84e365c884ef7d49fffffffffef72941214db40d553037995ff6e2fed5a76c1c162c10b3f624ee524015f81d000000006b48304502210096bde06807971608e9f5eea78f12849e54e309f1040f6c902e5f38e2932e7619022031d06d811dbe8a8b436ef15f7df884e3709df739f91ea34c96aec2527324142c0121035185ab3a4d579d0f16123562124d42b94afd2cf8ec42962d84e365c884ef7d49ffffffff93dac59b310f6d50e3fe5a6568d4cc139fe1b3831ad7b8a2e163002ba3564779010000006a473044022000f95e14ca7aa29cd8d80a3ea9054596b55bb81d25b65a6ec0a57d2f83b0da91022016e8cd6e42292e13556ebada8a91b8ae4a255212962c130f773fee1571e868a30121035185ab3a4d579d0f16123562124d42b94afd2cf8ec42962d84e365c884ef7d49ffffffffdc936693319b37fa0fd91e91737cd1a82cb88b7561b8f0ab5335ffb60a121ea8010000006b483045022100c70f507981fefe79fbdb86b7ec647c9141e1ca79d1c0bc3a27cb866b141e8b36022032e0a94ac9eef62ac32ab4536db95f669e2ef817e8e5e696c23213ea012918160121035185ab3a4d579d0f16123562124d42b94afd2cf8ec42962d84e365c884ef7d49ffffffff1257c8a571342266939e8e49759ab43ccde99a436bef4cca05216ee957ae33e7010000006a473044022058eb40aa7b031666b9ff3173842824fcba0aebbaba4f17c6520d8717f768076402202cba1b0811bbeee3bcde15825178a4a8c134665d1821933551e56c0880129970012103cd85c66436d0e7f30c5d0d2e344a02756ed1a3562e402c285c2d9eda02877b02ffffffff02004f6e76060200001976a9147dd483840798eabeea05c2d1409e0be9b99b624088aca3430f00000000001976a91403bbd566868b932d07be1733bd09ba806579fd6988ac00000000",
	}
	a := addpubkey(addr)
	txs := maketx(stx)
	log.Println(behex.EncodeToString(txs[0].Hash()))
	if err := Add(txs[0], 0); err != nil {
		t.Fatal(err)
	}
	coins, err := getCoins(a)
	if err != nil {
		t.Fatal(err)
	}
	if len(coins) != 1 {
		t.Fatal("cound not add coin")
	}
	if coins[0].Value != 100*params.Unit {
		t.Fatal("value differes", coins[0].Value)
	}
	log.Println(behex.EncodeToString(txs[1].Hash()))
	if err := Add(txs[1], 0); err != nil {
		t.Fatal(err)
	}
	coins, err = getCoins(a)
	if err != nil {
		t.Fatal(err)
	}
	if len(coins) != 0 {
		t.Fatal("cound not remove coin", len(coins))
	}
}
