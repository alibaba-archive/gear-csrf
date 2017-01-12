package csrf

import (
	"net/http"
	"time"

	"github.com/teambition/gear"
	"github.com/teambition/gear-csrf/token"
)

const cookieName = "_csrf"

// Token represents a CSRF token.
type Token string

// New is to implements gear.Any interface.
// It will set a token secret in your cookie if not exist and
// then returns a new CSRF token.
func (t Token) New(ctx *gear.Context) (interface{}, error) {
	return token.Generate(getSecretCookie(ctx, cookieName).Value, 18)
}

// Options is the CSRF middleware options.
type Options struct {
	// RequestFilter checks whether this request should be
	// checked its CSRF token by this middleware. If you
	// want the request to skip this middleware, just make
	// the function return false.
	RequestFilter func(*gear.Context) bool
	// InvalidTokenStatusCode is the returned HTTP status code
	// when the request CSRF token is invalid. By default it is
	// 403 .
	InvalidTokenStatusCode int
	// InvalidTokenMessage is the returned message
	// when the request CSRF token is invalid. By default it is
	// "Invalid CSRF token" .
	InvalidTokenMessage string
	// TokenFormKey is the key in your form to extract the CSRF
	// token from your request. By default it is "csrf_token".
	TokenFormKey string
	// TokenHeader is the name of the request header to  extract
	// the CSRF token.By default it is "X-CSRF-Token" .
	TokenHeader string
}

// New returns a new CSRF middleware to prevent your Gear app from
// CSRF attack.
func New(opts Options) gear.Middleware {
	if opts.InvalidTokenStatusCode == 0 {
		opts.InvalidTokenStatusCode = http.StatusForbidden
	}

	if opts.InvalidTokenMessage == "" {
		opts.InvalidTokenMessage = "Invalid CSRF token"
	}

	if opts.TokenFormKey == "" {
		opts.TokenFormKey = "csrf_token"
	}

	if opts.TokenHeader == "" {
		opts.TokenHeader = gear.HeaderXCSRFToken
	}

	return func(ctx *gear.Context) (err error) {
		if opts.RequestFilter != nil && !opts.RequestFilter(ctx) {
			return
		}

		// Prevent middle proxies from caching the response.
		defer func() {
			ctx.Res.Vary(gear.HeaderCookie)
		}()

		secretCookie := getSecretCookie(ctx, cookieName)
		csrfToken := getToken(ctx, opts)

		if csrfToken == "" || !token.Verify(secretCookie.Value, csrfToken) {
			return ctx.Error(&gear.Error{
				Code: opts.InvalidTokenStatusCode,
				Msg:  opts.InvalidTokenMessage,
			})
		}

		return
	}
}

func getSecretCookie(ctx *gear.Context, name string) *http.Cookie {
	secretCookie, err := ctx.Cookie(name)

	// ctx.Cookie can only return http.ErrNoCookie error.
	if err != nil {
		s, _ := token.CreateSecret(18)
		secretCookie = &http.Cookie{
			Name:     name,
			Value:    s,
			HttpOnly: true,
			Expires:  time.Now().Add(24 * time.Hour),
		}
		ctx.SetCookie(secretCookie)
	}

	return secretCookie
}

func getToken(ctx *gear.Context, opts Options) string {
	if token := ctx.Req.FormValue(opts.TokenFormKey); token != "" {
		return token
	}

	return ctx.Get(opts.TokenHeader)
}
