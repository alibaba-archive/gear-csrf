package token

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateSecret(t *testing.T) {
	assert := assert.New(t)

	t.Run("Should create a secret", func(t *testing.T) {
		s := CreateSecret()

		assert.NotEqual(0, len(s))
	})
}

func TestGenerate(t *testing.T) {
	assert := assert.New(t)

	secret := CreateSecret()

	t.Run("Should create a token", func(t *testing.T) {
		token := Generate(secret)

		assert.NotEqual(0, len(token))
	})

	t.Run("Should always generate same length tokens when saltLen and secret are same", func(t *testing.T) {
		token := Generate(secret)

		l := len(token)

		for i := 0; i < 1000; i++ {
			t := Generate(secret)

			assert.Equal(l, len(t))
		}
	})

	t.Run("Should not contain '/', '+' and '='", func(t *testing.T) {
		for i := 0; i < 1000; i++ {
			token := Generate(secret)

			assert.Equal(-1, strings.Index(token, "/"))
			assert.Equal(-1, strings.Index(token, "+"))
			assert.Equal(-1, strings.Index(token, "="))
		}
	})
}

func TestVerify(t *testing.T) {
	assert := assert.New(t)

	secret := CreateSecret()
	token := Generate(secret)

	t.Run("Should return true for valid token", func(t *testing.T) {
		assert.True(Verify(secret, token))
	})

	t.Run("Should return false for valid secret", func(t *testing.T) {
		assert.False(Verify("", token))
	})

	t.Run("Should return false for invalid token", func(t *testing.T) {
		s := CreateSecret()
		invalidToken := Generate(s)

		assert.False(Verify(secret, invalidToken))
		assert.False(Verify(secret, "NotContainMinus"))
	})
}
