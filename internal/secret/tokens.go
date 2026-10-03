package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
)

// Token returns a new random bearer value (256 bits, base64url) with an
// optional prefix that makes leaked values easy to recognize (e.g. in
// secret scanners).
func Token(prefix string) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand never fails on supported platforms; a failure here
		// must not produce a predictable token.
		panic("secret: crypto/rand failed: " + err.Error())
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

// Hash is the storage form of a random bearer value (authorization code,
// refresh token, client secret, session cookie). The values carry 256 bits
// of entropy, so a plain SHA-256 is enough: there is nothing to brute
// force.
func Hash(value string) string {
	h := sha256.Sum256([]byte(value))
	return hex.EncodeToString(h[:])
}

// Equal compares two strings in constant time (for equal lengths).
func Equal(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
