// Package secret provides reversible symmetric encryption for secrets stored in
// the database (e.g. the SMTP password), using AES-256-GCM.
//
// The key is derived (SHA-256) from the AEGIS_SECRET_KEY environment variable.
// When that variable is unset, a constant baked into the binary is used instead
// and UsingBakedKey reports true — this is obfuscation only (anyone with the
// binary can decrypt), so callers should warn the operator to set
// AEGIS_SECRET_KEY in any real deployment.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// bakedKey is the fallback key material when AEGIS_SECRET_KEY is unset. It only
// obfuscates at-rest secrets; it is not a real secret.
const bakedKey = "aegis-recon-default-key-set-AEGIS_SECRET_KEY-in-production"

var (
	once  sync.Once
	key   [32]byte
	baked bool
)

func derive() {
	env := os.Getenv("AEGIS_SECRET_KEY")
	if env == "" {
		baked = true
		env = bakedKey
	}
	key = sha256.Sum256([]byte(env))
}

func gcm() (cipher.AEAD, error) {
	once.Do(derive)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// UsingBakedKey reports whether the baked fallback key is in use (AEGIS_SECRET_KEY
// not set). Callers should log a warning when true.
func UsingBakedKey() bool {
	once.Do(derive)
	return baked
}

// Encrypt returns base64(nonce || ciphertext) for the plaintext.
func Encrypt(plaintext string) (string, error) {
	aead, err := gcm()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// Decrypt reverses Encrypt. It fails if the data is corrupt or was encrypted
// with a different key.
func Decrypt(enc string) (string, error) {
	aead, err := gcm()
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", fmt.Errorf("secret: base64: %w", err)
	}
	ns := aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("secret: ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("secret: decrypt: %w", err)
	}
	return string(pt), nil
}
