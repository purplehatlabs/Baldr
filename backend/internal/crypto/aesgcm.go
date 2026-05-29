// Package crypto provides AES-256-GCM encryption helpers for secrets at rest.
//
// The output format is: nonce (12 bytes) || ciphertext || GCM tag (16 bytes).
// The encryption key is expected to be exactly 32 bytes (AES-256).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const KeySize = 32

var ErrInvalidKeySize = fmt.Errorf("encryption key must be %d bytes", KeySize)

// DecodeKey parses a base64-encoded 32-byte key from a string.
func DecodeKey(b64 string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}
	return key, nil
}

// Encrypt seals plaintext with AES-256-GCM. The returned blob has the nonce
// prefixed and can be passed back to Decrypt.
func Encrypt(plaintext, key []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt reverses Encrypt. Returns an error if the blob is malformed or the
// key/tag is wrong.
func Decrypt(blob, key []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}

	if len(blob) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm open: %w", err)
	}
	return plaintext, nil
}
