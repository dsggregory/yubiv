package selfhosted

/*** Verify a Yubikey OTP. This is the self-hosted version that DOES NOT use
Yubico servers for validation. See README.md for more detail.
*/

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/dsggregory/yubiv/pkg/common"

	"github.com/dsggregory/yubiv/pkg/selfhosted/model"
	_ "github.com/jinzhu/gorm/dialects/mysql" // need this to load the DB engine
)

const (
	UidSize      = 6                 // nolint
	PubLen       = common.TokenIDLen // of otp token
	AesSize      = 16
	OtpSize      = common.TokenOTPLen
	CrcOkResidue = 0xf0b8
	ModHexMap    = "cbdefghijklnrtuv"
)

// Token Yubikey token structure. See https://developers.yubico.com/OTP/OTPs_Explained.html
type Token struct {
	// Uid Private secret ID
	Uid [UidSize]byte // nolint
	// Ctr Usage counter
	Ctr uint16
	// Tstpl timestamp
	Tstpl uint16
	// Tstph timestamp hour
	Tstph uint8
	// Use Session usage counter
	Use uint8
	// Rnd Random number
	Rnd uint16
	// Crc checksum of token
	Crc uint16
}

// ParseToken generic util to parse a OTP into public-key (yubikey ID) and token
func ParseToken(token string) ([]byte, []byte, error) {
	// check minimal otp length
	token = strings.TrimSpace(token)
	tokenLen := len(token)
	if tokenLen <= OtpSize {
		return nil, nil, common.BAD_OTP
	}

	// where the otp starts in the token
	canary := tokenLen - OtpSize

	// extract public key
	if lng := len(token[:canary]); lng < 1 || lng > OtpSize {
		return nil, nil, common.BAD_OTP
	}
	pub := make([]byte, len(token[:canary]))
	copy(pub, token[:canary])

	// extract otp
	otp := make([]byte, len(token[canary:]))
	copy(otp, token[canary:])

	return pub, otp, nil
}

func modHexDecode(src []byte) []byte {
	dst := make([]byte, (len(src)+1)/2)
	alt := false
	idx := 0

	for _, val := range src {
		b := bytes.IndexByte([]byte(ModHexMap), val)
		if b == -1 {
			b = 0
		}
		bb := byte(b)

		alt = !alt
		if alt {
			dst[idx] = bb
		} else {
			dst[idx] <<= 4
			dst[idx] |= bb
			idx++
		}
	}
	return dst
}

func crc16(buf []byte) uint16 {
	mCRC := uint16(0xffff)
	for _, val := range buf {
		mCRC ^= uint16(val & 0xff)
		for i := 0; i < 8; i++ {
			j := mCRC & 1
			mCRC >>= 1
			if j > 0 {
				mCRC ^= 0x8408
			}
		}
	}

	return mCRC
}

func extractOtp(buf []byte) (*Token, error) {
	var token Token

	if len(buf) != 16 || crc16(buf) != CrcOkResidue {
		return nil, common.CRC_FAILURE
	}

	copy(token.Uid[:], buf[:6])

	token.Ctr = binary.LittleEndian.Uint16(buf[6:])
	token.Tstpl = binary.LittleEndian.Uint16(buf[8:])

	token.Tstph = buf[10]
	token.Use = buf[11]

	token.Rnd = binary.LittleEndian.Uint16(buf[12:])
	token.Crc = binary.LittleEndian.Uint16(buf[14:])

	return &token, nil
}

func decipherOtp(otp [OtpSize]byte, key [AesSize]byte) (*Token, error) {
	// decipher the token using the aes key
	buf := make([]byte, len(otp))
	copy(buf, otp[:])

	buf = modHexDecode(buf)

	cipher, _ := aes.NewCipher(key[:])
	cipher.Decrypt(buf, buf)

	// extract the deciphered token
	token, err := extractOtp(buf)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// ShvValidateOTP self-hosted validation of OTP token. Note that `otp` should NOT include the leading public key.
func ShvValidateOTP(user model.YubiUser, otp []byte) (*Token, error) {
	// verify the AES128 key
	priv, err := hex.DecodeString(strings.TrimSpace(string(user.Secret)))
	if err != nil {
		return nil, common.BACKEND_ERROR
	}

	var aesData [AesSize]byte
	copy(aesData[:], priv)

	// decipher the token
	var o [OtpSize]byte
	copy(o[:], otp)
	token, err := decipherOtp(o, aesData)
	if err != nil {
		// Make sure they have not passed in a full OTP token (pub + otp). otp here should NOT include pub
		// but we'll try to adjust.
		if len(otp) == (PubLen + OtpSize) {
			copy(o[:], otp[PubLen:])
			t, nerr := decipherOtp(o, aesData)
			if nerr != nil {
				return nil, fmt.Errorf("otp length suggests it includes public - %w", err)
			}
			token = t
		} else {
			return nil, err
		}
	}

	// check token validity
	if token.Ctr < uint16(user.Counter) {
		return nil, common.REPLAYED_OTP
	} else if token.Ctr == uint16(user.Counter) && token.Use <= uint8(user.Session) {
		return nil, common.REPLAYED_OTP
	}

	return token, nil
}
