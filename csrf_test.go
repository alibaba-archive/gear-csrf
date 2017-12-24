package csrf

import (
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/teambition/crypto-go"
)

var DefaultClient = &http.Client{}

func TestCSRFToken(t *testing.T) {
	assert := assert.New(t)
	CSRF := New("some key", time.Second)
	secret := base64.RawURLEncoding.EncodeToString(crypto.RandN(16))
	token := CSRF.SignToken(secret)

	assert.False(CSRF.VerifyToken(secret+"x", token))
	assert.False(CSRF.VerifyToken(secret, "x"+token))
	assert.True(CSRF.VerifyToken(secret, token))
	time.Sleep(time.Second * 2)
	assert.False(CSRF.VerifyToken(secret, token))
	assert.True(CSRF.VerifyToken(secret, CSRF.SignToken(secret)))
}
