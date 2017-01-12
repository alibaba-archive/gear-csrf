package token

import (
	cr "crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	mr "math/rand"
	"regexp"
	"strings"
)

var (
	plusRegex      = regexp.MustCompile(`\+`)
	slashRegex     = regexp.MustCompile(`\/`)
	equalSignRegex = regexp.MustCompile(`=`)
)

// CreateSecret creates a new secret key.
func CreateSecret(len int) (string, error) {
	if len <= 0 {
		return "", errors.New("token: secret length <= 0")
	}

	b := make([]byte, len)
	if _, err := cr.Read(b); err != nil {
		return "", err
	}

	return escape(base64.URLEncoding.EncodeToString(b)), nil
}

// Generate returns a new token.
func Generate(secret string, saltLen int) (string, error) {
	if secret == "" {
		return "", errors.New("token: empty secret")
	}
	if saltLen <= 0 {
		return "", errors.New("token: salt length <= 0")
	}

	return generateWithSalt(secret, randomString(saltLen)), nil
}

func generateWithSalt(secret, salt string) string {
	hash := base64.URLEncoding.EncodeToString(sha1.New().Sum([]byte(salt + "-" + secret)))

	return escape(salt + "-" + hash)
}

// Verify checks if given token is valid for the given secret.
func Verify(secret, token string) bool {
	i := strings.Index(token, "-")

	if i == -1 {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(token), []byte(generateWithSalt(secret, token[0:i]))) == 1
}

func escape(s string) string {
	s = plusRegex.ReplaceAllString(s, "-")
	s = slashRegex.ReplaceAllString(s, "_")
	s = equalSignRegex.ReplaceAllString(s, "")

	return s
}

const base = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
const baseLength = len(base)

func randomString(length int) string {
	s := make([]byte, length)

	for i := 0; i < length; i++ {
		s[i] = base[mr.Intn(baseLength)]
	}

	return string(s)
}
