package base58check

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/big"

	"fmt"

	"github.com/monarj/wallet/base58check/base58"
)

//Encode encodes byteData to base58.
func Encode(prefix byte, byteData []byte) string {
	length := len(byteData) + 1
	encoded := make([]byte, length, length+4)
	encoded[0] = prefix
	copy(encoded[1:], byteData)

	//Perform SHA-256 twice
	hash := sha256.Sum256(encoded)
	hash2 := sha256.Sum256(hash[:])

	//First 4 bytes if this double-sha'd byte array is the checksum
	//Append this checksum to the input bytes
	encoded = append(encoded, hash2[0:4]...)

	//Convert this checksum'd version to a big Int
	bigIntEncodedChecksum := big.NewInt(0)
	bigIntEncodedChecksum.SetBytes(encoded)

	//Encode the big int checksum'd version into a Base58Checked string
	base58EncodedChecksum := base58.EncodeBig(nil, bigIntEncodedChecksum)

	//Now for each zero byte we counted above we need to prepend a 1 to our
	//base58 encoded string. The rational behind this is that base58 removes 0's (0x00).
	//So bitcoin demands we add leading 0s back on as 1s.
	buffer := make([]byte, 0, len(base58EncodedChecksum))

	//base58 alone is not enough. We need to first count each of the zero bytes
	//which are at the beginning of the encodedCheckSum

	for _, v := range encoded {
		if v == 0 {
			buffer = append(buffer, '1')
		} else {
			break
		}
	}
	buffer = append(buffer, base58EncodedChecksum...)
	return string(buffer)
}

//Decode decodes base58 value to bytes.
func Decode(value string) ([]byte, error) {
	publicKeyInt, err := base58.DecodeToBig([]byte(value))
	if err != nil {
		return nil, err
	}

	encodedChecksum := publicKeyInt.Bytes()
	encoded := encodedChecksum[:len(encodedChecksum)-4]
	cksum := encodedChecksum[len(encodedChecksum)-4:]

	buffer := make([]byte, 0, len(encoded))
	for _, v := range value {
		if v == '1' {
			buffer = append(buffer, 0)
		} else {
			break
		}
	}

	buffer = append(buffer, encoded...)

	//Perform SHA-256 twice
	hash := sha256.Sum256(buffer)
	hash2 := sha256.Sum256(hash[:])

	if !bytes.Equal(hash2[:4], cksum) {
		return nil,
			fmt.Errorf("%s checksum not matched embeded cksum:%s cksum:%s",
				value, hex.EncodeToString(cksum), hex.EncodeToString(hash2[:4]))
	}

	return buffer, err
}
