package token

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"strings"
)

// New returns a new token by given secret key.
func New(secret string) string {
	return generateWithSalt(secret, randomString())
}

// NewSecret creates a new secret key.
func NewSecret() string {
	return randomString()
}

// Verify checks if the given token is valid for the given secret.
func Verify(secret, token string) bool {
	i := strings.Index(token, ".")

	if i == -1 {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(token), []byte(generateWithSalt(secret, token[0:i]))) == 1
}

func generateWithSalt(secret, salt string) string {
	h := sha1.New()
	h.Write([]byte(salt + "." + secret))

	return salt + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func randomString() string {
	b := make([]byte, 18)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
