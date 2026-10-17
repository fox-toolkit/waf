[![Go Reference](https://pkg.go.dev/badge/github.com/fox-toolkit/waf.svg)](https://pkg.go.dev/github.com/fox-toolkit/waf)
![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/fox-toolkit/waf)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/fox-toolkit/waf)

# WAF

WAF is an **experimental** middleware for the [Fox](https://github.com/fox-toolkit/fox) router that integrates the 
[Coraza Web Application Firewall (WAF)](https://coraza.io/) to enhance the security of your web applications by intercepting 
and analyzing HTTP requests and responses.

### Disclaimer
The current API is not yet stabilized. Breaking changes may occur before v1.0.0 and will be noted on the release note.

### Getting Started
Installation
````sh
go get -u github.com/fox-toolkit/waf
````

### Usage
Here is an example to load [OWASP CRS](https://coreruleset.org/) using [coraza-coreruleset](https://github.com/corazawaf/coraza-coreruleset).
````go
package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"

	corazaconf "github.com/corazawaf/coraza-coreruleset/coraza/v3"
	crs "github.com/corazawaf/coraza-coreruleset/crs/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/fox-toolkit/fox"
	"github.com/fox-toolkit/waf"
	"github.com/jcchavezs/mergefs"
)

func main() {

	cfg := coraza.NewWAFConfig().
		WithDirectives("Include @coraza.conf-recommended").
		WithDirectives("Include @crs-setup.conf.example").
		WithDirectives("Include @owasp_crs/*.conf").
		WithDirectives("SecRuleEngine On").
		WithRootFS(mergefs.Merge(crs.FS, corazaconf.FS))

	co, err := coraza.NewWAF(cfg)
	if err != nil {
		panic(err)
	}

	f := fox.MustRouter(
		fox.WithMiddleware(waf.Middleware(co)),
	)

	f.MustAdd(fox.MethodGet, "/hello/{name}", func(c *fox.Context) {
		_ = c.String(http.StatusOK, fmt.Sprintf("Hello, %s", c.Param("name")))
	})

	if err = http.ListenAndServe(":8080", f); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalln(err)
	}
}
````

````sh
curl -sS -D - "http://localhost:8080/hello/fox?path=../foo"
# HTTP/1.1 403 Forbidden
# Date: Mon, 15 Jul 2024 14:52:24 GMT
# Content-Length: 0
````
