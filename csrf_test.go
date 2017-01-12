package csrf

import (
	"net/http"
	"testing"

	"net/url"

	"strings"

	"github.com/stretchr/testify/assert"
	"github.com/teambition/gear"
)

var DefaultClient = &http.Client{}

func TestToken(t *testing.T) {
	assert := assert.New(t)

	app := gear.New()

	app.Use(func(ctx *gear.Context) error {
		token, err := ctx.Any(new(Token))

		assert.Nil(err)
		assert.NotEqual(0, len(token.(string)))

		return ctx.HTML(200, "OK")
	})
	srv := app.Start()
	defer srv.Close()

	url := "http://" + srv.Addr().String()

	t.Run("Should generate token and set the cookie", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, url, nil)

		assert.Nil(err)

		res, err := DefaultClient.Do(req)

		assert.Nil(err)
		assert.Equal(1, len(res.Cookies()))
		assert.Equal(cookieName, res.Cookies()[0].Name)
		assert.NotEmpty(res.Cookies()[0].Value)
	})

	t.Run("Should generate the cookie only one time", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, url, nil)

		assert.Nil(err)

		res, err := DefaultClient.Do(req)

		assert.Nil(err)
		assert.Equal(1, len(res.Cookies()))

		req.AddCookie(&http.Cookie{
			Name:  cookieName,
			Value: res.Cookies()[0].Value,
		})

		res, err = DefaultClient.Do(req)

		assert.Nil(err)
		assert.Equal(0, len(res.Cookies()))
	})
}

func TestMiddleware(t *testing.T) {
	assert := assert.New(t)
	token := ""
	cookie := &http.Cookie{}

	app := gear.New()

	app.Use(func(ctx *gear.Context) error {
		t, err := ctx.Any(new(Token))

		assert.Nil(err)

		token = t.(string)

		return nil
	})

	app.Use(New(Options{
		RequestFilter: func(ctx *gear.Context) bool {
			if ctx.Get("Test-Not-Pass") != "" {
				return false
			}
			return true
		},
	}))

	app.Use(func(ctx *gear.Context) error {
		return ctx.HTML(200, "OK")
	})
	srv := app.Start()
	defer srv.Close()

	URL := "http://" + srv.Addr().String()

	t.Run("Should not run the middleware when the request be filterd", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, URL, nil)

		assert.Nil(err)

		req.Header.Set("Test-Not-Pass", "not-pass")
		res, err := DefaultClient.Do(req)

		assert.Nil(err)
		assert.Equal(http.StatusOK, res.StatusCode)
		assert.Equal(1, len(res.Cookies()))

		cookie = res.Cookies()[0]
	})

	t.Run("Should pass the middleware when token is valid in header", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, URL, nil)

		assert.Nil(err)

		req.AddCookie(cookie)
		req.Header.Set(gear.HeaderXCSRFToken, token)

		res, err := DefaultClient.Do(req)

		assert.Nil(err)
		assert.Equal(http.StatusOK, res.StatusCode)
	})

	t.Run("Should pass the middleware when token is valid in query", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, URL+"?csrf_token="+token, nil)

		assert.Nil(err)

		req.AddCookie(cookie)

		res, err := DefaultClient.Do(req)

		assert.Nil(err)
		assert.Equal(http.StatusOK, res.StatusCode)
	})

	t.Run("Should pass the middleware when token is valid in body", func(t *testing.T) {
		data := url.Values{}
		data.Set("csrf_token", token)

		req, err := http.NewRequest(http.MethodPost, URL, strings.NewReader(data.Encode()))

		assert.Nil(err)

		req.Header.Set(gear.HeaderContentType, "application/x-www-form-urlencoded")
		req.AddCookie(cookie)

		res, err := DefaultClient.Do(req)

		assert.Nil(err)
		assert.Equal(http.StatusOK, res.StatusCode)
	})

	t.Run("Should return 403 when token is invalid", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, URL, nil)

		assert.Nil(err)

		req.AddCookie(cookie)

		res, err := DefaultClient.Do(req)

		assert.Nil(err)
		assert.Equal(http.StatusForbidden, res.StatusCode)
	})
}
