/***
Provides a column type to database/sql/driver whose value is encrypted when persisting to the database.
The encryption is AES256 with a nonce.
The key used for encryption and decryption is supplied by the calling function which could originate
from a k8s secret, for instance.
*/
package model

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/hex"
	"fmt"
	"io"
)

// DefaultColumnSecretKey the shared private key for enc/dec
var DefaultColumnSecretKey *string

// when the DB driver writes to DB
func (sec ColumnSecret) Value() (driver.Value, error) {
	if DefaultColumnSecretKey == nil {
		return nil, fmt.Errorf("DefaultColumnSecretKey not initialized")
	}
	// enc the string in b64
	enc, err := Encrypt([]byte(sec), *DefaultColumnSecretKey)
	return driver.Value(enc), err
}

// when the DB driver reads from the DB
func (sec *ColumnSecret) Scan(src interface{}) error {
	if DefaultColumnSecretKey == nil {
		return fmt.Errorf("DefaultColumnSecretKey not initialized")
	}
	// dec the src string in b64
	sb, _ := src.([]byte)
	dec, err := Decrypt(string(sb), *DefaultColumnSecretKey)
	*sec = ColumnSecret(dec)
	return err
}

func createHash(key string) string {
	hmac := sha256.New()
	_, _ = hmac.Write([]byte(key))
	x := hex.EncodeToString(hmac.Sum(nil))
	return x[:32] // aes.NewCipher() requires a 32-byte key for aes256
}

// Encrypt bytes and return a hex encoding. Uses a nonce so two calls on the same data&pass result in diff values.
func Encrypt(data []byte, passphrase string) (string, error) {
	block, err := aes.NewCipher([]byte(createHash(passphrase)))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	// nonce is stored with the encrypted data to be used in decryption
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return fmt.Sprintf("%x", ciphertext), nil
}

// Decrypt a hex encoded string (from Encrypt()) and return the plaintext bytes
func Decrypt(xdata string, passphrase string) ([]byte, error) {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	var data []byte
	if _, err = fmt.Sscanf(xdata, "%x", &data); err != nil {
		return nil, err
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
