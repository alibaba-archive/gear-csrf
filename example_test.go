package csrf_test

import (
	"net/http"

	"github.com/teambition/gear"
	csrf "github.com/teambition/gear-csrf"
)

func Example() {
	app := gear.New()

	// Enable the CSRF checking.
	app.Use(csrf.New(csrf.Options{
		Skipper: func(ctx *gear.Context) bool {
			switch ctx.Method {
			// Disable the CSRF checking when request method is GET, HEAD or OPTIONS.
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				return true
			default:
				return false
			}
		},
		CookieOptions: &http.Cookie{Secure: true, HttpOnly: true},
	}))

	app.Use(func(ctx *gear.Context) (err error) {
		// Add the CSRF token in your template forms.
		ctx.Render(http.StatusOK, "./path/to/your/teamplate", csrf.GetTokenFromCtx(ctx))

		return
	})
}
