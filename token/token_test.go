package token

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateSecret(t *testing.T) {
	assert := assert.New(t)

	t.Run("Should return error when len is <= 0", func(t *testing.T) {
		_, err := CreateSecret(0)

		assert.Equal(errors.New("token: secret length <= 0"), err)
	})

	t.Run("Should create a secret", func(t *testing.T) {
		s, err := CreateSecret(10)

		assert.Nil(err)
		assert.NotEqual(0, len(s))
	})
}

func TestGenerate(t *testing.T) {
	assert := assert.New(t)

	secret, err := CreateSecret(10)
	assert.Nil(err)

	t.Run("Should return error when secret is empty", func(t *testing.T) {
		_, err := Generate("", 10)

		assert.Equal(errors.New("token: empty secret"), err)
	})

	t.Run("Should return error when salt length is empty", func(t *testing.T) {
		_, err := Generate(secret, 0)

		assert.Equal(errors.New("token: salt length <= 0"), err)
	})

	t.Run("Should create a token", func(t *testing.T) {
		token, err := Generate(secret, 10)

		assert.Nil(err)
		assert.NotEqual(0, len(token))
	})

	t.Run("Should always generate same length tokens when saltLen and secret are same", func(t *testing.T) {
		token, err := Generate(secret, 10)

		assert.Nil(err)
		l := len(token)

		for i := 0; i < 1000; i++ {
			t, err := Generate(secret, 10)

			assert.Nil(err)
			assert.Equal(l, len(t))
		}
	})

	t.Run("Should not contain '/', '+' and '='", func(t *testing.T) {
		for i := 0; i < 1000; i++ {
			token, err := Generate(secret, 10)

			assert.Nil(err)
			assert.Equal(-1, strings.Index(token, "/"))
			assert.Equal(-1, strings.Index(token, "+"))
			assert.Equal(-1, strings.Index(token, "="))
		}
	})
}

func TestVerify(t *testing.T) {
	assert := assert.New(t)

	secret, err := CreateSecret(10)
	assert.Nil(err)

	token, err := Generate(secret, 10)

	assert.Nil(err)

	t.Run("Should return true for valid token", func(t *testing.T) {
		assert.True(Verify(secret, token))
	})

	t.Run("Should return false for valid secret", func(t *testing.T) {
		assert.False(Verify("", token))
	})

	t.Run("Should return false for invalid token", func(t *testing.T) {
		s, err := CreateSecret(10)
		assert.Nil(err)

		invalidToken, err := Generate(s, 10)

		assert.Nil(err)
		assert.False(Verify(secret, invalidToken))
		assert.False(Verify(secret, "NotContainMinus"))
	})
}
