package main

import (
	"net/http"
	"time"

	"github.com/teambition/gear"
	csrf "github.com/teambition/gear-csrf"
)

func main() {
	app := gear.New()
	router := gear.NewRouter()
	CSRF := csrf.New("some_key", time.Minute*10)

	// http://127.0.0.1:3000/csrf
	router.Get("/csrf", func(ctx *gear.Context) error {
		secret := CSRF.SecretFromCookie(ctx)
		return ctx.JSON(http.StatusOK, map[string]string{
			"secret": secret,
			"token":  CSRF.SignToken(secret),
		})
	})

	// Enable the CSRF checking.
	// http://127.0.0.1:3000/verify-csrf?csrf_token={token}
	router.Get("/verify-csrf", CSRF.Serve, func(ctx *gear.Context) error {
		secret := CSRF.SecretFromCookie(ctx)
		return ctx.JSON(http.StatusOK, map[string]string{
			"secret": secret,
			"verify": "ok",
		})
	})

	app.UseHandler(router)
	app.Listen(":3000")
}
