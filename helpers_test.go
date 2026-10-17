// Copyright 2024 Sylvain Müller.
// SPDX-License-Identifier: Apache-2.0

package waf

import (
	"net/http"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/fox-toolkit/fox"
)

// The helpers below confine the Fox specific wiring needed by the tests ported from
// https://github.com/corazawaf/coraza/tree/main/http, so the ported test bodies stay as close as possible to upstream.

// wrap is the counterpart of the upstream wrap function. It returns the interceptor wrapping w (through the Fox
// response writer, as the middleware does) and the response processor to call once the handler returns.
func wrap(w http.ResponseWriter, r *http.Request, tx types.Transaction) (
	fox.ResponseWriter,
	func(types.Transaction, *http.Request) error,
) {
	i := &rwInterceptor{}
	i.reset(tx, fox.NewTestContextOnly(w, r).Writer(), r.Proto)
	return i, func(tx types.Transaction, _ *http.Request) error {
		return processResponse(tx, i)
	}
}

// newRouter is the counterpart of the upstream WrapHandler function. It returns a router protecting every route
// with the WAF middleware and serving h for any method and path.
func newRouter(waf coraza.WAF, h fox.HandlerFunc) *fox.Router {
	f := fox.MustRouter(fox.WithMiddleware(Middleware(waf)))
	f.MustAdd(fox.MethodAny, "/*{any}", h)
	return f
}
