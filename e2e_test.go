// Copyright 2024 Sylvain Müller.
// SPDX-License-Identifier: Apache-2.0

package waf_test

import (
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/http/e2e"
	"github.com/fox-toolkit/fox"
	"github.com/fox-toolkit/waf"
	"github.com/mccutchen/go-httpbin/v2/httpbin"
)

// TestE2E runs the Coraza connectors end-to-end test suite against a router proxying requests to httpbin.
func TestE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end tests in short mode")
	}

	w, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(e2e.Directives))
	if err != nil {
		t.Fatal(err)
	}

	httpbinSrv := httptest.NewServer(httpbin.New())
	defer httpbinSrv.Close()

	target, err := url.Parse(httpbinSrv.URL)
	if err != nil {
		t.Fatal(err)
	}

	f := fox.MustRouter(fox.WithMiddleware(waf.Middleware(w)))
	f.MustAdd(fox.MethodAny, "/*{any}", fox.WrapH(httputil.NewSingleHostReverseProxy(target)))

	proxySrv := httptest.NewServer(f)
	defer proxySrv.Close()

	if err := e2e.Run(e2e.Config{
		ProxiedEntrypoint: proxySrv.URL,
		HttpbinEntrypoint: httpbinSrv.URL,
	}); err != nil {
		t.Fatal(err)
	}
}
