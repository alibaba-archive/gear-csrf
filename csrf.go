package csrf

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/teambition/crypto-go"
	"github.com/teambition/gear"
)

// Version ...
const Version = "2.0.0"

var defaultCookieOptions = http.Cookie{Name: "_csrf", HttpOnly: true}

// TokenExtractor is a function that takes a gear.Context as input and
// returns either a string token or an empty string. Default to:
//
//  func(ctx *gear.Context) string {
//  	token := ctx.GetHeader(gear.HeaderXCSRFToken)
//  	if token == "" {
//  		token = ctx.Query("csrf_token")
//  	}
//  	if token == "" {
//  		token = ctx.Req.FormValue("csrf_token")
//  	}
//  	return token
//  }
//
type TokenExtractor func(ctx *gear.Context) (token string)

// New returns a new CSRF instance.
func New(key string, expire time.Duration, cookieOptions ...http.Cookie) *CSRF {
	co := defaultCookieOptions
	if len(cookieOptions) > 0 {
		co = cookieOptions[0]
	}
	if co.Name == "" {
		co.Name = "_csrf"
	}
	return &CSRF{
		key:           []byte(key),
		expire:        expire,
		cookieOptions: co,
		tokenExtractor: func(ctx *gear.Context) string {
			token := ctx.GetHeader(gear.HeaderXCSRFToken)
			if token == "" {
				token = ctx.Query("csrf_token")
			}
			if token == "" {
				token = ctx.Req.FormValue("csrf_token")
			}
			return token
		},
	}
}

// CSRF will prevent your Gear app from CSRF attack.
type CSRF struct {
	key            []byte
	expire         time.Duration
	cookieOptions  http.Cookie
	tokenExtractor TokenExtractor
}

// SetTokenParser set a custom tokenExtractor to CSRF.
func (c *CSRF) SetTokenParser(tokenExtractor TokenExtractor) {
	c.tokenExtractor = tokenExtractor
}

// SignToken returns a token for the secret
func (c *CSRF) SignToken(secret string) string {
	return crypto.SignState(c.key, secret)
}

// VerifyToken verify the token with the secret.
func (c *CSRF) VerifyToken(secret, token string) bool {
	return crypto.VerifyState(c.key, secret, token, c.expire)
}

// SecretFromCookie retrieves secret from the cookie and returns it.
// If it not exists, a new secret will be created and then set to cookie.
func (c *CSRF) SecretFromCookie(ctx *gear.Context) string {
	csrfCookie, err := ctx.Req.Cookie(c.cookieOptions.Name)

	// ctx.Cookie can only return http.ErrNoCookie error.
	if err != nil {
		csrfCookie = new(http.Cookie)
		*csrfCookie = c.cookieOptions
		b := crypto.RandN(16)
		csrfCookie.Value = base64.URLEncoding.EncodeToString(b)
		http.SetCookie(ctx.Res, csrfCookie)
	}

	return csrfCookie.Value
}

// Serve implements gear.Handler interface. We can use it as middleware.
// It will parse and validate token from the ctx, if succeed, gear's middleware process
// will go on, otherwise process ended and a 403 error will be to respond to client.
//
func (c *CSRF) Serve(ctx *gear.Context) error {
	token := c.tokenExtractor(ctx)
	secret := c.SecretFromCookie(ctx)

	ctx.Res.Vary(gear.HeaderCookie)
	if token == "" || !c.VerifyToken(secret, token) {
		return gear.ErrForbidden.WithMsg("Invalid CSRF token")
	}

	return nil
}
