# gear-csrf
[![Build Status](https://travis-ci.org/teambition/gear-csrf.svg?branch=master)](https://travis-ci.org/teambition/gear-csrf)
[![Coverage Status](https://coveralls.io/repos/github/teambition/gear-csrf/badge.svg?branch=master)](https://coveralls.io/github/teambition/gear-csrf?branch=master)
[![License](http://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/teambition/gear-auth/master/LICENSE)
[![GoDoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](http://godoc.org/github.com/teambition/gear-csrf)

CSRF middleware for Gear.

## Installation

```sh
go get -u github.com/teambition/gear-csrf
```

## Usage

```go
import (
	csrf "github.com/teambition/gear-csrf"
)
```

```go
app := gear.New()

// Enable the CSRF checking.
app.Use(csrf.New(csrf.Options{
  RequestFilter: func(ctx *gear.Context) bool {
    switch ctx.Method {
    // Disable the checking when request method is GET, HEAD or OPTIONS.
    case http.MethodGet, http.MethodHead, http.MethodOptions:
      return false
    default:
      return true
    }
  },
  CookieOptions: &http.Cookie{Secure: true, HttpOnly: true},
}))

app.Use(func(ctx *gear.Context) (err error) {
  token, err := ctx.Any(new(csrf.Token))

  // Add your CSRF token in your template forms.
  ctx.Render(http.StatusOK, "./path/to/your/teamplate", token.(string))

  return
})
```

## Documentation

The docs can be found at [godoc.org](https://godoc.org/github.com/teambition/gear-csrf), as usual.

## License

MIT
