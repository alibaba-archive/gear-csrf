package token

import (
	cr "crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"strings"
)

// CreateSecret creates a new secret key.
func CreateSecret() string {
	return randomString()
}

// Generate returns a new token.
func Generate(secret string) string {
	return generateWithSalt(secret, randomString())
}

func generateWithSalt(secret, salt string) string {
	h := sha1.New()
	h.Write([]byte(salt + "." + secret))

	return salt + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// Verify checks if given token is valid for the given secret.
func Verify(secret, token string) bool {
	i := strings.Index(token, ".")

	if i == -1 {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(token), []byte(generateWithSalt(secret, token[0:i]))) == 1
}

func randomString() string {
	b := make([]byte, 18)
	cr.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
