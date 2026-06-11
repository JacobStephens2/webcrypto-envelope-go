// Package envelope is a tiny, dependency-free AES-256-GCM envelope library -
// the Go twin of github.com/JacobStephens2/webcrypto-envelope (TypeScript,
// Web Crypto). The two are wire-compatible: an envelope produced by either
// implementation opens in the other.
//
// Two patterns, one primitive (AES-256-GCM in a compact "iv:tag:ciphertext"
// base64 envelope):
//
//  1. Password vault - derive a key from a password (PBKDF2-SHA-256) and
//     encrypt/decrypt locally. Good for offline-first apps that sync
//     ciphertext the server can't read.
//  2. Sealed share - Seal encrypts under a fresh random key and hands the
//     key back to you. Store the ciphertext anywhere (the server only ever
//     holds ciphertext); deliver the key out-of-band - e.g. in a URL
//     fragment, which browsers never send to the server - and the recipient
//     Opens it. This is the zero-knowledge shareable-link primitive.
//
// Standard library only (crypto/pbkdf2 needs Go 1.24+). Every function
// returns an error rather than panicking on attacker-controlled input.
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// DefaultIterations is the PBKDF2 iteration count used when DeriveOptions
// is nil or its Iterations field is zero. It matches the TypeScript twin.
const DefaultIterations = 600_000

const (
	keySize   = 32 // AES-256
	nonceSize = 12 // GCM standard nonce
	tagSize   = 16 // GCM tag
	saltSize  = 16
)

// ErrInvalidEnvelope is returned when an envelope is not three base64 parts
// separated by colons.
var ErrInvalidEnvelope = errors.New("invalid envelope format (expected iv:tag:ciphertext)")

// DeriveOptions configures DeriveKey. A nil pointer (or zero Iterations)
// means DefaultIterations.
type DeriveOptions struct {
	Iterations int
}

func mustRandom(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read never fails on Go 1.24+.
		panic(err)
	}
	return b
}

// RandomSalt returns a random base64 salt for password derivation (16 bytes).
func RandomSalt() string {
	return base64.StdEncoding.EncodeToString(mustRandom(saltSize))
}

// RandomKey returns a random base64 256-bit key - e.g. for a sealed,
// shareable payload.
func RandomKey() string {
	return base64.StdEncoding.EncodeToString(mustRandom(keySize))
}

// DeriveKey derives a 32-byte AES-256-GCM key from a password and a base64
// salt using PBKDF2-SHA-256.
func DeriveKey(password, saltB64 string, opts *DeriveOptions) ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 salt: %w", err)
	}
	iterations := DefaultIterations
	if opts != nil && opts.Iterations != 0 {
		iterations = opts.Iterations
	}
	return pbkdf2.Key(sha256.New, password, salt, iterations, keySize)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Encrypt encrypts a UTF-8 string under a 32-byte key. It returns a compact
// "iv:tag:ciphertext" base64 envelope with a fresh random IV per call.
func Encrypt(plaintext string, key []byte) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	iv := mustRandom(nonceSize)
	sealed := gcm.Seal(nil, iv, []byte(plaintext), nil) // ciphertext || tag
	ciphertext, tag := sealed[:len(sealed)-tagSize], sealed[len(sealed)-tagSize:]
	enc := base64.StdEncoding
	return enc.EncodeToString(iv) + ":" + enc.EncodeToString(tag) + ":" + enc.EncodeToString(ciphertext), nil
}

// Decrypt opens an "iv:tag:ciphertext" envelope with a 32-byte key. It
// returns an error if the envelope is malformed, the key is wrong, or the
// data was tampered with.
func Decrypt(envelopeStr string, key []byte) (string, error) {
	parts := strings.Split(envelopeStr, ":")
	if len(parts) != 3 {
		return "", ErrInvalidEnvelope
	}
	enc := base64.StdEncoding
	iv, err := enc.DecodeString(parts[0])
	if err != nil {
		return "", ErrInvalidEnvelope
	}
	tag, err := enc.DecodeString(parts[1])
	if err != nil {
		return "", ErrInvalidEnvelope
	}
	ciphertext, err := enc.DecodeString(parts[2])
	if err != nil {
		return "", ErrInvalidEnvelope
	}
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	if len(iv) != gcm.NonceSize() {
		return "", ErrInvalidEnvelope
	}
	plain, err := gcm.Open(nil, iv, append(ciphertext, tag...), nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// Seal encrypts plaintext under a fresh random key and returns both.
//
// Store the envelope wherever you like - it is opaque ciphertext, so the
// storage service can't read it. Deliver the key out-of-band (a URL fragment
// is ideal: browsers never send the fragment to the server). The recipient
// calls Open(envelope, key). The storage service is therefore zero-knowledge
// with respect to the content.
func Seal(plaintext string) (key, envelope string, err error) {
	key = RandomKey()
	rawKey, _ := base64.StdEncoding.DecodeString(key)
	envelope, err = Encrypt(plaintext, rawKey)
	return key, envelope, err
}

// Open opens a sealed payload with its base64 key.
func Open(envelopeStr, keyB64 string) (string, error) {
	rawKey, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return "", fmt.Errorf("invalid base64 key: %w", err)
	}
	return Decrypt(envelopeStr, rawKey)
}
