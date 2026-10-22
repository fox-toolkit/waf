// Copyright 2026 Sylvain Müller.
// SPDX-License-Identifier: Apache-2.0

package waf

import (
	"iter"
	"net/http"
	"net/netip"
	"net/url"
	"slices"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/fox-toolkit/fox"
)

// Context is the subset of the [fox.Context] API passed to a [Hook], without access to the response.
type Context interface {
	Request() *http.Request
	RemoteIP() netip.Addr
	ClientIP() (netip.Addr, error)
	Method() string
	RoutingPath() string
	Host() string
	QueryParams() url.Values
	QueryParam(name string) string
	Header(key string) string
	Route() *fox.Route
	Param(name string) string
	Params() iter.Seq[fox.Param]

	sealed()
}

// Hook customizes a transaction before Coraza evaluates any rule. It must not retain c or tx.
type Hook func(c Context, tx types.Transaction)

type hookKey struct{}

// WithTransactionHook attaches hooks to a route. For every request matching the route, the middleware calls the
// hooks in the given order, once the connection, URI and request headers are populated in the transaction and
// right before the request headers phase (phase 1) is evaluated. Hooks are not called when the rule engine is off.
// Applying this option more than once to the same route replaces the previously attached hooks. It panics if a
// hook is nil.
func WithTransactionHook(hooks ...Hook) fox.RouteOption {
	if slices.ContainsFunc(hooks, func(hook Hook) bool { return hook == nil }) {
		panic("waf: nil transaction hook")
	}
	return fox.WithAnnotation(hookKey{}, slices.Clone(hooks))
}

// TxVar returns a [Hook] that sets the transaction variable TX:key to value, overwriting any previous value. Since
// rules read TX variables at evaluation time, this is the way to configure per-route behaviors that rule sets
// expose through TX variables, such as enabling an OWASP CRS plugin or setting the paranoia level. Setting TX
// variables requires a transaction that implements [plugintypes.TransactionState], as the transactions of the
// Coraza WAF implementation do. For any other transaction, the hook is a no-op.
func TxVar(key, value string) Hook {
	values := []string{value}
	return func(_ Context, tx types.Transaction) {
		if state, ok := tx.(plugintypes.TransactionState); ok {
			state.Variables().TX().Set(key, values)
		}
	}
}

type ruleRemover interface {
	RemoveRuleByID(id int)
	RemoveRuleByIDRange(start, end int)
}

// RemoveRules returns a [Hook] that removes the rules with the given IDs from the transaction, the per-route
// equivalent of ctl:ruleRemoveById. The rules of the WAF are not affected. Removing rules requires a transaction
// created by the Coraza WAF implementation. For any other transaction, the hook is a no-op.
func RemoveRules(ids ...int) Hook {
	ids = slices.Clone(ids)
	return func(_ Context, tx types.Transaction) {
		if remover, ok := tx.(ruleRemover); ok {
			for _, id := range ids {
				remover.RemoveRuleByID(id)
			}
		}
	}
}

// RemoveRuleRange returns a [Hook] that removes the rules whose ID is between start and end inclusive from the
// transaction, the per-route equivalent of ctl:ruleRemoveById with a range. The rules of the WAF are not affected.
// Removing rules requires a transaction created by the Coraza WAF implementation. For any other transaction, the
// hook is a no-op. It panics if start is greater than end.
func RemoveRuleRange(start, end int) Hook {
	if start > end {
		panic("waf: invalid rule range")
	}
	return func(_ Context, tx types.Transaction) {
		if remover, ok := tx.(ruleRemover); ok {
			remover.RemoveRuleByIDRange(start, end)
		}
	}
}

func runHooks(c *fox.Context, tx types.Transaction) {
	route := c.Route()
	if route == nil {
		return
	}
	hooks, _ := route.Annotation(hookKey{}).([]Hook)
	for _, hook := range hooks {
		hook(hookContext{c}, tx)
	}
}

type hookContext struct {
	c *fox.Context
}

func (s hookContext) Request() *http.Request        { return s.c.Request() }
func (s hookContext) RemoteIP() netip.Addr          { return s.c.RemoteIP() }
func (s hookContext) ClientIP() (netip.Addr, error) { return s.c.ClientIP() }
func (s hookContext) Method() string                { return s.c.Method() }
func (s hookContext) RoutingPath() string           { return s.c.RoutingPath() }
func (s hookContext) Host() string                  { return s.c.Host() }
func (s hookContext) QueryParams() url.Values       { return s.c.QueryParams() }
func (s hookContext) QueryParam(name string) string { return s.c.QueryParam(name) }
func (s hookContext) Header(key string) string      { return s.c.Header(key) }
func (s hookContext) Route() *fox.Route             { return s.c.Route() }
func (s hookContext) Param(name string) string      { return s.c.Param(name) }
func (s hookContext) Params() iter.Seq[fox.Param]   { return s.c.Params() }
func (s hookContext) sealed()                       {}
