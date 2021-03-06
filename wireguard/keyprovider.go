package wireguard

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"wg-server/wireguard/datastruct"
)

// KeyProvider contains key generation and management functionalities
type KeyProvider struct {
}

// NewKeyProvider creates new keyProvider instance
func NewKeyProvider() *KeyProvider {
	return &KeyProvider{}
}

// GenerateKey generates a Key suitable for use as a pre-shared secret key from
// a cryptographically safe source.
//
// The output Key should not be used as a private key; use GeneratePrivateKey
// instead.
func (k *KeyProvider) GenerateKey() (datastruct.Key, error) {
	b := make([]byte, datastruct.KeyLen)
	if _, err := rand.Read(b); err != nil {
		return datastruct.Key{}, fmt.Errorf("wiregaurd: failed to read random bytes: %v", err)
	}

	return newKey(b)
}

// GeneratePrivateKey generates a Key suitable for use as a private key from a
// cryptographically safe source.
func (k *KeyProvider) GeneratePrivateKey() (datastruct.Key, error) {
	key, err := k.GenerateKey()
	if err != nil {
		return datastruct.Key{}, err
	}

	// Modify random bytes using algorithm described at:
	// https://cr.yp.to/ecdh.html.
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64

	return key, nil
}

// NewKey creates a Key from an existing byte slice.  The byte slice must be
// exactly 32 bytes in length.
func newKey(b []byte) (datastruct.Key, error) {
	if len(b) != datastruct.KeyLen {
		return datastruct.Key{}, fmt.Errorf("wiregaurd: incorrect key size: %d", len(b))
	}

	var k datastruct.Key
	copy(k[:], b)

	return k, nil
}

// ParseKey parses a Key from a base64-encoded string, as produced by the
// Key.String method.
func (k *KeyProvider) ParseKey(s string) (datastruct.Key, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return datastruct.Key{}, fmt.Errorf("wiregaurd: failed to parse base64-encoded key: %v", err)
	}

	return newKey(b)
}
