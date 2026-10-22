// Copyright 2026 Sylvain Müller.
// SPDX-License-Identifier: Apache-2.0

package waf

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/fox-toolkit/fox"
)

func TestRunHooksAllocs(t *testing.T) {
	w, err := coraza.NewWAF(coraza.NewWAFConfig())
	if err != nil {
		t.Fatal(err)
	}
	tx := w.NewTransaction()
	defer tx.Close()

	var allocs float64
	f := fox.MustRouter()
	f.MustAdd(fox.MethodGet, "/{name}", func(c *fox.Context) {
		allocs = testing.AllocsPerRun(100, func() { runHooks(c, tx) })
	}, WithTransactionHook(func(c Context, _ types.Transaction) { _ = c.Param("name") }))
	f.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/fox", nil))

	if allocs != 0 {
		t.Errorf("unexpected allocations, want: 0, have: %v", allocs)
	}
}

func TestRuleRemover(t *testing.T) {
	w, err := coraza.NewWAF(coraza.NewWAFConfig())
	if err != nil {
		t.Fatal(err)
	}
	tx := w.NewTransaction()
	defer tx.Close()

	if _, ok := tx.(ruleRemover); !ok {
		t.Error("expected the Coraza transaction to implement ruleRemover")
	}
}
