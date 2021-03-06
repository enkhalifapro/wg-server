package datastruct

import (
	"encoding/base64"
	"golang.org/x/crypto/curve25519"
)

// A Key is a public, private, or pre-shared secret key.  The Key constructor
// functions in this package can be used to create Keys suitable for each of
// these applications.
type Key [KeyLen]byte


// PublicKey computes a public key from the private key k.
//
// PublicKey should only be called when k is a private key.
func (k Key) PublicKey() Key {
	var (
		pub  [KeyLen]byte
		priv = [KeyLen]byte(k)
	)

	// ScalarBaseMult uses the correct base value per https://cr.yp.to/ecdh.html,
	// so no need to specify it.
	curve25519.ScalarBaseMult(&pub, &priv)

	return Key(pub)
}

// String returns the base64-encoded string representation of a Key.
//
// ParseKey can be used to produce a new Key from this string.
func (k Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}
