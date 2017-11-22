package csrf

import (
	"net/http"

	"github.com/teambition/gear"
	"github.com/teambition/gear-csrf/token"
)

const cookieName = "_csrf"

var cookieOptions = &http.Cookie{Name: cookieName}

// GetTokenFromCtx returns a CSRF token. It will set a user secret in request
// cookie if it not exists.
func GetTokenFromCtx(ctx *gear.Context) string {
	return token.New(getSecret(ctx))
}

// Options is the CSRF middleware options.
type Options struct {
	// Skipper checks whether this request should be
	// checked its CSRF token by this middleware. If you
	// want the request to skip this middleware, just make
	// the function return true.
	Skipper func(*gear.Context) bool
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
	// CookieOptions is the options of the secret cookie.It's type
	// is *http.Cookie so you can set every field of http.Cookie type
	// but Name and Value. They are reserved for storing the secret
	// key/value.
	CookieOptions *http.Cookie
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

	if opts.CookieOptions != nil {
		cookieOptions = opts.CookieOptions
		cookieOptions.Name = cookieName
	}

	return func(ctx *gear.Context) error {
		if opts.Skipper != nil && opts.Skipper(ctx) {
			return nil
		}

		// Prevent middle proxies from caching the response.
		ctx.Res.Vary(gear.HeaderCookie)
		csrfToken := getToken(ctx, opts)
		if csrfToken == "" || !token.Verify(getSecret(ctx), csrfToken) {
			return &gear.Error{
				Code: opts.InvalidTokenStatusCode,
				Msg:  opts.InvalidTokenMessage,
			}
		}

		return nil
	}
}

func getSecret(ctx *gear.Context) string {
	secretCookie, err := ctx.Req.Cookie(cookieName)

	// ctx.Cookie can only return http.ErrNoCookie error.
	if err != nil {
		secretCookie = new(http.Cookie)
		*secretCookie = *cookieOptions
		secretCookie.Value = token.NewSecret()

		http.SetCookie(ctx.Res, secretCookie)
	}

	return secretCookie.Value
}

func getToken(ctx *gear.Context, opts Options) string {
	if token := ctx.Req.FormValue(opts.TokenFormKey); token != "" {
		return token
	}

	return ctx.GetHeader(opts.TokenHeader)
}
