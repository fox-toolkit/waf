// Copyright 2024 Sylvain Müller.
// SPDX-License-Identifier: Apache-2.0

package waf_test

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/fox-toolkit/fox"
	"github.com/fox-toolkit/fox/clientip"
	"github.com/fox-toolkit/waf"
)

// Tests in this file cover the Fox specific behaviors of the middleware, which have no upstream counterpart.

func newWAF(t *testing.T, directives string) coraza.WAF {
	t.Helper()
	w, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestResponseBodyWriteMethods(t *testing.T) {
	w := newWAF(t, `
SecRuleEngine On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
SecRule RESPONSE_BODY "@contains password" "id:100,phase:4,deny,status:403"
`)

	writeMethods := map[string]func(c *fox.Context, body string) error{
		"Write": func(c *fox.Context, body string) error {
			_, err := c.Writer().Write([]byte(body))
			return err
		},
		"WriteString": func(c *fox.Context, body string) error {
			_, err := c.Writer().WriteString(body)
			return err
		},
		"ReadFrom": func(c *fox.Context, body string) error {
			_, err := c.Writer().ReadFrom(strings.NewReader(body))
			return err
		},
		"String": func(c *fox.Context, body string) error {
			return c.String(http.StatusOK, body)
		},
		"Stream": func(c *fox.Context, body string) error {
			return c.Stream(http.StatusOK, fox.MIMETextPlain, strings.NewReader(body))
		},
	}

	cases := []struct {
		name       string
		body       string
		wantStatus int
		wantBody   string
	}{
		{name: "not blocking", body: "hello world", wantStatus: http.StatusOK, wantBody: "hello world"},
		{name: "blocking", body: "password=xxxx", wantStatus: http.StatusForbidden, wantBody: ""},
	}

	for method, write := range writeMethods {
		for _, tc := range cases {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				f := fox.MustRouter(fox.WithMiddleware(waf.Middleware(w)))
				f.MustAdd(fox.MethodGet, "/", func(c *fox.Context) {
					c.Writer().Header().Set(fox.HeaderContentType, fox.MIMETextPlain)
					if err := write(c, tc.body); err != nil {
						t.Errorf("unexpected write error: %v", err)
					}
				})

				rec := httptest.NewRecorder()
				f.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

				if want, have := tc.wantStatus, rec.Code; want != have {
					t.Errorf("unexpected status code, want: %d, have: %d", want, have)
				}
				if want, have := tc.wantBody, rec.Body.String(); want != have {
					t.Errorf("unexpected response body, want: %q, have: %q", want, have)
				}
			})
		}
	}
}

func TestResponseWriterState(t *testing.T) {
	w := newWAF(t, `
SecRuleEngine On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
SecRule RESPONSE_HEADERS:X-Block "@streq true" "id:100,phase:3,deny,status:401"
SecRule RESPONSE_BODY "@contains password" "id:101,phase:4,deny,status:403"
`)

	type state struct {
		status  int
		written bool
		size    int
	}

	snapshot := func(rw fox.ResponseWriter) state {
		return state{status: rw.Status(), written: rw.Written(), size: rw.Size()}
	}

	cases := []struct {
		name    string
		handler func(c *fox.Context) []state
		want    []state
	}{
		{
			name: "nothing written",
			handler: func(c *fox.Context) []state {
				return []state{snapshot(c.Writer())}
			},
			want: []state{{status: http.StatusOK, written: false, size: 0}},
		},
		{
			name: "header and body buffered",
			handler: func(c *fox.Context) []state {
				rw := c.Writer()
				rw.Header().Set(fox.HeaderContentType, fox.MIMETextPlain)
				rw.WriteHeader(http.StatusCreated)
				s1 := snapshot(rw)
				_, _ = rw.Write([]byte("hello"))
				return []state{s1, snapshot(rw)}
			},
			want: []state{
				{status: http.StatusCreated, written: true, size: 0},
				{status: http.StatusCreated, written: true, size: 5},
			},
		},
		{
			name: "interrupted at response headers",
			handler: func(c *fox.Context) []state {
				rw := c.Writer()
				rw.Header().Set("X-Block", "true")
				rw.WriteHeader(http.StatusCreated)
				return []state{snapshot(rw)}
			},
			want: []state{{status: http.StatusUnauthorized, written: true, size: 0}},
		},
		{
			name: "interrupted at response body",
			handler: func(c *fox.Context) []state {
				rw := c.Writer()
				rw.Header().Set(fox.HeaderContentType, fox.MIMETextPlain)
				_, _ = rw.Write([]byte("hello"))
				s1 := snapshot(rw)
				_, _ = rw.Write([]byte("password=xxxx"))
				return []state{s1, snapshot(rw)}
			},
			// The response body rules run once the handler returns, so the buffered state is reported.
			want: []state{
				{status: http.StatusOK, written: true, size: 5},
				{status: http.StatusOK, written: true, size: 18},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []state
			f := fox.MustRouter(fox.WithMiddleware(waf.Middleware(w)))
			f.MustAdd(fox.MethodGet, "/", func(c *fox.Context) {
				got = tc.handler(c)
			})

			f.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

			if len(got) != len(tc.want) {
				t.Fatalf("unexpected number of snapshots, want: %d, have: %d", len(tc.want), len(got))
			}
			for i := range tc.want {
				if tc.want[i] != got[i] {
					t.Errorf("unexpected state at snapshot %d, want: %+v, have: %+v", i, tc.want[i], got[i])
				}
			}
		})
	}
}

// TestInterceptorReuse ensures that the pooled interceptor does not leak any state from a request to the next one.
func TestInterceptorReuse(t *testing.T) {
	w := newWAF(t, `
SecRuleEngine On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
SecRule RESPONSE_HEADERS:X-Block "@streq true" "id:100,phase:3,deny,status:401"
SecRule RESPONSE_BODY "@contains password" "id:101,phase:4,deny,status:403"
`)

	f := fox.MustRouter(fox.WithMiddleware(waf.Middleware(w)))
	f.MustAdd(fox.MethodGet, "/headers", func(c *fox.Context) {
		c.Writer().Header().Set("X-Block", "true")
		_ = c.String(http.StatusCreated, "hello")
	})
	f.MustAdd(fox.MethodGet, "/body", func(c *fox.Context) {
		_ = c.String(http.StatusCreated, "password=xxxx")
	})
	f.MustAdd(fox.MethodGet, "/hijack", func(c *fox.Context) {
		conn, _, err := c.Writer().Hijack()
		if err != nil {
			t.Errorf("unexpected hijack error: %v", err)
			return
		}
		_ = conn.Close()
	})
	f.MustAdd(fox.MethodGet, "/clean", func(c *fox.Context) {
		_ = c.String(http.StatusCreated, "hello")
	})

	srv := httptest.NewServer(f)
	defer srv.Close()

	// The hijacked connection can't be used anymore, so we don't share it with the other requests.
	hijackClient := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

	expect := func(t *testing.T, path string, wantStatus int, wantBody string) {
		t.Helper()
		res, err := srv.Client().Get(srv.URL + path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		body, err := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want, have := wantStatus, res.StatusCode; want != have {
			t.Errorf("unexpected status code for %s, want: %d, have: %d", path, want, have)
		}
		if want, have := wantBody, string(body); want != have {
			t.Errorf("unexpected response body for %s, want: %q, have: %q", path, want, have)
		}
	}

	for _, path := range []string{"/headers", "/body", "/hijack", "/clean"} {
		t.Run(path, func(t *testing.T) {
			for range 10 {
				res, err := hijackClient.Get(srv.URL + path)
				if err == nil {
					_ = res.Body.Close()
				}
				expect(t, "/clean", http.StatusCreated, "hello")

				res, err = hijackClient.Get(srv.URL + path)
				if err == nil {
					_ = res.Body.Close()
				}
				expect(t, "/body", http.StatusForbidden, "")
			}
		})
	}
}

// TestInterceptorReuseConcurrent ensures that concurrent requests sharing the interceptor pool never observe each
// other's state.
func TestInterceptorReuseConcurrent(t *testing.T) {
	w := newWAF(t, `
SecRuleEngine On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
SecRule RESPONSE_HEADERS:X-Block "@streq true" "id:100,phase:3,deny,status:401"
SecRule RESPONSE_BODY "@contains password" "id:101,phase:4,deny,status:403"
`)

	f := fox.MustRouter(fox.WithMiddleware(waf.Middleware(w)))
	f.MustAdd(fox.MethodGet, "/headers", func(c *fox.Context) {
		c.Writer().Header().Set("X-Block", "true")
		_ = c.String(http.StatusCreated, "hello")
	})
	f.MustAdd(fox.MethodGet, "/body", func(c *fox.Context) {
		_ = c.String(http.StatusCreated, "password=xxxx")
	})
	f.MustAdd(fox.MethodGet, "/clean/{name}", func(c *fox.Context) {
		_ = c.String(http.StatusCreated, c.Param("name"))
	})

	srv := httptest.NewServer(f)
	defer srv.Close()

	cases := []struct {
		path       string
		wantStatus int
		wantBody   string
	}{
		{path: "/headers", wantStatus: http.StatusUnauthorized, wantBody: ""},
		{path: "/body", wantStatus: http.StatusForbidden, wantBody: ""},
		{path: "/clean/foo", wantStatus: http.StatusCreated, wantBody: "foo"},
		{path: "/clean/bar", wantStatus: http.StatusCreated, wantBody: "bar"},
	}

	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			for j := range 20 {
				tc := cases[(i+j)%len(cases)]
				res, err := srv.Client().Get(srv.URL + tc.path)
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				body, err := io.ReadAll(res.Body)
				_ = res.Body.Close()
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if res.StatusCode != tc.wantStatus || string(body) != tc.wantBody {
					t.Errorf("unexpected response for %s, want: %d %q, have: %d %q", tc.path, tc.wantStatus, tc.wantBody, res.StatusCode, body)
				}
			}
		})
	}
	wg.Wait()
}

func TestSuperfluousWriteHeaderCaller(t *testing.T) {
	buf := new(bytes.Buffer)
	w, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives("SecRuleEngine On").
		WithDebugLogger(debuglog.Default().WithOutput(buf).WithLevel(debuglog.LevelWarn)))
	if err != nil {
		t.Fatal(err)
	}

	f := fox.MustRouter(fox.WithMiddleware(waf.Middleware(w)))
	f.MustAdd(fox.MethodGet, "/", func(c *fox.Context) {
		c.Writer().WriteHeader(http.StatusCreated)
		c.Writer().WriteHeader(http.StatusAccepted)
	})

	rec := httptest.NewRecorder()
	f.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if want, have := http.StatusCreated, rec.Code; want != have {
		t.Errorf("unexpected status code, want: %d, have: %d", want, have)
	}
	out := buf.String()
	if !strings.Contains(out, "superfluous response.WriteHeader call") {
		t.Fatalf("expected a superfluous WriteHeader warning, got: %q", out)
	}
	if !strings.Contains(out, "fox_test.go") {
		t.Errorf("expected the warning to report the handler as caller, got: %q", out)
	}
}

func TestRouteParams(t *testing.T) {
	w := newWAF(t, "SecRuleEngine On")

	f := fox.MustRouter(fox.WithMiddleware(waf.Middleware(w)))
	f.MustAdd(fox.MethodGet, "/hello/{name}", func(c *fox.Context) {
		_ = c.String(http.StatusOK, c.Param("name"))
	})

	rec := httptest.NewRecorder()
	f.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/hello/fox", nil))

	if want, have := "fox", rec.Body.String(); want != have {
		t.Errorf("unexpected response body, want: %q, have: %q", want, have)
	}
}

func TestServerName(t *testing.T) {
	w := newWAF(t, `
SecRuleEngine On
SecRule SERVER_NAME "@streq blocked.example.com" "id:1,phase:1,deny,status:403"
`)

	f := fox.MustRouter(fox.WithMiddleware(waf.Middleware(w)))
	f.MustAdd(fox.MethodGet, "/", func(c *fox.Context) {
		c.Writer().WriteHeader(http.StatusOK)
	})

	for host, want := range map[string]int{"blocked.example.com": http.StatusForbidden, "example.com": http.StatusOK} {
		t.Run(host, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Host = host
			rec := httptest.NewRecorder()
			f.ServeHTTP(rec, req)
			if have := rec.Code; want != have {
				t.Errorf("unexpected status code, want: %d, have: %d", want, have)
			}
		})
	}
}

func TestPathParams(t *testing.T) {
	w := newWAF(t, `
SecRuleEngine On
SecRule ARGS_PATH:id "@streq blocked" "id:1,phase:1,deny,status:403"
SecRule &ARGS_PATH:sub "@gt 0" "id:2,phase:1,deny,status:403"
SecRule ARGS_PATH:path "@streq a/b/c" "id:3,phase:1,deny,status:403"
SecRule &ARGS_PATH:rest "@eq 1" "id:4,phase:1,deny,status:403"
SecRule ARGS_PATH:id "@rx ^(?:<script>|é|%3Cx%3E)$" "id:5,phase:1,deny,status:403"
`)

	f := fox.MustRouter(fox.WithMiddleware(waf.Middleware(w)))
	f.MustAdd(fox.MethodGet, "{sub}.example.com/users/{id}", okHandler)
	f.MustAdd(fox.MethodGet, "/files/+{path}", okHandler)
	f.MustAdd(fox.MethodGet, "/opt/*{rest}", okHandler)

	cases := []struct {
		name string
		host string
		path string
		want int
	}{
		{name: "path param", host: "fox.example.com", path: "/users/blocked", want: http.StatusForbidden},
		{name: "host param excluded", host: "fox.example.com", path: "/users/fox", want: http.StatusOK},
		{name: "encoded path param", host: "fox.example.com", path: "/users/%3Cscript%3E", want: http.StatusForbidden},
		{name: "encoded utf8 path param", host: "fox.example.com", path: "/users/%C3%A9", want: http.StatusForbidden},
		{name: "double encoded path param", host: "fox.example.com", path: "/users/%253Cx%253E", want: http.StatusForbidden},
		{name: "multi segment wildcard", host: "example.com", path: "/files/a/b/c", want: http.StatusForbidden},
		{name: "other wildcard value", host: "example.com", path: "/files/a/b", want: http.StatusOK},
		{name: "empty optional wildcard", host: "example.com", path: "/opt/", want: http.StatusForbidden},
		{name: "no route", host: "example.com", path: "/not-found", want: http.StatusNotFound},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.Host = tc.host
			rec := httptest.NewRecorder()
			f.ServeHTTP(rec, req)
			if have := rec.Code; tc.want != have {
				t.Errorf("unexpected status code, want: %d, have: %d", tc.want, have)
			}
		})
	}
}

// TestRequestBodyWriterTo ensures that the request body seen by the handler supports io.WriterTo and yields the
// full payload, including the bytes beyond the request body limit.
func TestRequestBodyWriterTo(t *testing.T) {
	w, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives("SecRuleEngine On\nSecRequestBodyLimitAction ProcessPartial").
		WithRequestBodyAccess().
		WithRequestBodyLimit(3).
		WithRequestBodyInMemoryLimit(3))
	if err != nil {
		t.Fatal(err)
	}

	const payload = "the full payload"
	f := fox.MustRouter(fox.WithMiddleware(waf.Middleware(w)))
	f.MustAdd(fox.MethodPost, "/", func(c *fox.Context) {
		if _, ok := c.Request().Body.(io.WriterTo); !ok {
			t.Error("expected the request body to implement io.WriterTo")
		}
		buf := new(bytes.Buffer)
		if _, err := io.Copy(buf, c.Request().Body); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		_ = c.String(http.StatusOK, buf.String())
	})

	srv := httptest.NewServer(f)
	defer srv.Close()

	// A reader without a known size forces a chunked request body.
	req, _ := http.NewRequest(http.MethodPost, srv.URL, struct{ io.Reader }{strings.NewReader(payload)})
	req.Header.Set(fox.HeaderContentType, "application/x-www-form-urlencoded")
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)

	if want, have := payload, string(body); want != have {
		t.Errorf("unexpected response body, want: %q, have: %q", want, have)
	}
}

func TestEnableFullDuplex(t *testing.T) {
	w := newWAF(t, "SecRuleEngine On")

	f := fox.MustRouter(fox.WithMiddleware(waf.Middleware(w)))
	f.MustAdd(fox.MethodGet, "/", func(c *fox.Context) {
		if err := c.Writer().EnableFullDuplex(); !errors.Is(err, http.ErrNotSupported) {
			t.Errorf("expected http.ErrNotSupported, got: %v", err)
		}
	})

	f.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
}

func okHandler(c *fox.Context) {
	c.Writer().WriteHeader(http.StatusOK)
}

func TestTransactionHook(t *testing.T) {
	w := newWAF(t, `
SecRuleEngine On
SecRule TX:blocked "@eq 1" "id:1,phase:1,deny,status:403"
`)

	f := fox.MustRouter(fox.WithMiddleware(waf.Middleware(w)))
	f.MustAdd(fox.MethodGet, "/hooked", okHandler, waf.WithTransactionHook(waf.TxVar("blocked", "1")))
	f.MustAdd(fox.MethodGet, "/plain", okHandler)

	for path, want := range map[string]int{"/hooked": http.StatusForbidden, "/plain": http.StatusOK} {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			f.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if have := rec.Code; want != have {
				t.Errorf("unexpected status code, want: %d, have: %d", want, have)
			}
		})
	}
}

func TestTransactionHookOrder(t *testing.T) {
	w := newWAF(t, `
SecRuleEngine On
SecRule TX:level "@eq 2" "id:1,phase:1,deny,status:403"
`)

	var calls []int
	record := func(n int) waf.Hook {
		return func(waf.Context, types.Transaction) {
			calls = append(calls, n)
		}
	}

	f := fox.MustRouter(fox.WithMiddleware(waf.Middleware(w)))
	f.MustAdd(fox.MethodGet, "/recorded", okHandler, waf.WithTransactionHook(record(1), record(2), record(3)))
	f.MustAdd(fox.MethodGet, "/last-wins", okHandler, waf.WithTransactionHook(waf.TxVar("level", "1"), waf.TxVar("level", "2")))
	f.MustAdd(fox.MethodGet, "/reversed", okHandler, waf.WithTransactionHook(waf.TxVar("level", "2"), waf.TxVar("level", "1")))

	f.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/recorded", nil))
	if want, have := []int{1, 2, 3}, calls; !slices.Equal(want, have) {
		t.Errorf("unexpected hook calls, want: %v, have: %v", want, have)
	}

	for path, want := range map[string]int{"/last-wins": http.StatusForbidden, "/reversed": http.StatusOK} {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			f.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if have := rec.Code; want != have {
				t.Errorf("unexpected status code, want: %d, have: %d", want, have)
			}
		})
	}
}

func TestTransactionHookReplaced(t *testing.T) {
	w := newWAF(t, `
SecRuleEngine On
SecRule TX:blocked "@eq 1" "id:1,phase:1,deny,status:403"
`)

	f := fox.MustRouter(fox.WithMiddleware(waf.Middleware(w)))
	f.MustAdd(fox.MethodGet, "/", okHandler,
		waf.WithTransactionHook(waf.TxVar("blocked", "1")),
		waf.WithTransactionHook(waf.TxVar("other", "1")),
	)

	rec := httptest.NewRecorder()
	f.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if want, have := http.StatusOK, rec.Code; want != have {
		t.Errorf("unexpected status code, want: %d, have: %d", want, have)
	}
}

func TestTransactionHookRequestState(t *testing.T) {
	w := newWAF(t, `
SecRuleEngine On
SecRule TX:name "@streq evil" "id:1,phase:1,deny,status:403"
`)

	hook := func(c waf.Context, tx types.Transaction) {
		vars := tx.(plugintypes.TransactionState).Variables()
		if want, have := c.Request().URL.Path, vars.RequestURI().Get(); want != have {
			t.Errorf("unexpected REQUEST_URI, want: %q, have: %q", want, have)
		}
		if want, have := []string{"value"}, vars.RequestHeaders().Get("X-Test"); !slices.Equal(want, have) {
			t.Errorf("unexpected REQUEST_HEADERS:X-Test, want: %v, have: %v", want, have)
		}
		waf.TxVar("name", c.Param("name"))(c, tx)
	}

	f := fox.MustRouter(fox.WithMiddleware(waf.Middleware(w)))
	f.MustAdd(fox.MethodGet, "/users/{name}", okHandler, waf.WithTransactionHook(hook))

	for path, want := range map[string]int{"/users/evil": http.StatusForbidden, "/users/fox": http.StatusOK} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set("X-Test", "value")
			rec := httptest.NewRecorder()
			f.ServeHTTP(rec, req)
			if have := rec.Code; want != have {
				t.Errorf("unexpected status code, want: %d, have: %d", want, have)
			}
		})
	}
}

func TestTransactionHookRuleEngineOff(t *testing.T) {
	w := newWAF(t, "SecRuleEngine Off")

	called := false
	f := fox.MustRouter(fox.WithMiddleware(waf.Middleware(w)))
	f.MustAdd(fox.MethodGet, "/", okHandler, waf.WithTransactionHook(func(waf.Context, types.Transaction) {
		called = true
	}))

	f.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if called {
		t.Error("expected the hook not to be called when the rule engine is off")
	}
}

func TestTransactionHookWithoutRoute(t *testing.T) {
	w := newWAF(t, "SecRuleEngine On")

	f := fox.MustRouter(fox.WithMiddleware(waf.Middleware(w)))
	f.MustAdd(fox.MethodGet, "/", okHandler, waf.WithTransactionHook(waf.TxVar("key", "value")))

	rec := httptest.NewRecorder()
	f.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/not-found", nil))
	if want, have := http.StatusNotFound, rec.Code; want != have {
		t.Errorf("unexpected status code, want: %d, have: %d", want, have)
	}
}

func TestWithTransactionHookNilHook(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected a panic for a nil hook")
		}
	}()
	waf.WithTransactionHook(waf.TxVar("key", "value"), nil)
}

func TestContext(t *testing.T) {
	w := newWAF(t, "SecRuleEngine On")

	called := false
	hook := func(c waf.Context, _ types.Transaction) {
		called = true
		if want, have := "/users/{name}", c.Route().Pattern(); want != have {
			t.Errorf("unexpected route pattern, want: %q, have: %q", want, have)
		}
		if want, have := "fox", c.Param("name"); want != have {
			t.Errorf("unexpected param, want: %q, have: %q", want, have)
		}
		if want, have := []fox.Param{{Key: "name", Value: "fox"}}, slices.Collect(c.Params()); !slices.Equal(want, have) {
			t.Errorf("unexpected params, want: %v, have: %v", want, have)
		}
		if want, have := "bar", c.QueryParam("foo"); want != have {
			t.Errorf("unexpected query param, want: %q, have: %q", want, have)
		}
		var rc any = c
		if _, ok := rc.(*fox.Context); ok {
			t.Error("expected the request context not to expose *fox.Context")
		}
		if _, ok := rc.(interface{ Writer() fox.ResponseWriter }); ok {
			t.Error("expected the request context not to expose the response writer")
		}
	}

	f := fox.MustRouter(fox.WithMiddleware(waf.Middleware(w)))
	f.MustAdd(fox.MethodGet, "/users/{name}", okHandler, waf.WithTransactionHook(hook))
	f.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/users/fox?foo=bar", nil))

	if !called {
		t.Error("expected the hook to be called")
	}
}

func TestTxVar(t *testing.T) {
	w := newWAF(t, "SecRuleEngine On")
	tx := w.NewTransaction()
	defer tx.Close()

	waf.TxVar("key", "value")(nil, tx)

	if want, have := []string{"value"}, tx.(plugintypes.TransactionState).Variables().TX().Get("key"); !slices.Equal(want, have) {
		t.Errorf("unexpected TX:key, want: %v, have: %v", want, have)
	}
}

func TestTxVarForeignTransaction(t *testing.T) {
	w := newWAF(t, "SecRuleEngine On")
	tx := w.NewTransaction()
	defer tx.Close()

	waf.TxVar("key", "value")(nil, struct{ types.Transaction }{tx})

	if have := tx.(plugintypes.TransactionState).Variables().TX().Get("key"); len(have) != 0 {
		t.Errorf("expected TX:key to be unset, have: %v", have)
	}
}

func TestRemoveRules(t *testing.T) {
	w := newWAF(t, `
SecRuleEngine On
SecRule REQUEST_URI "@contains evil" "id:1,phase:1,deny,status:403"
SecRule REQUEST_URI "@contains evil" "id:2,phase:1,deny,status:403"
SecRule REQUEST_URI "@contains evil" "id:3,phase:2,deny,status:403"
`)

	f := fox.MustRouter(fox.WithMiddleware(waf.Middleware(w)))
	f.MustAdd(fox.MethodGet, "/none/*{any}", okHandler)
	f.MustAdd(fox.MethodGet, "/some/*{any}", okHandler, waf.WithTransactionHook(waf.RemoveRules(1, 2)))
	f.MustAdd(fox.MethodGet, "/all/*{any}", okHandler, waf.WithTransactionHook(waf.RemoveRules(1, 2, 3)))
	f.MustAdd(fox.MethodGet, "/partial-range/*{any}", okHandler, waf.WithTransactionHook(waf.RemoveRuleRange(1, 2)))
	f.MustAdd(fox.MethodGet, "/full-range/*{any}", okHandler, waf.WithTransactionHook(waf.RemoveRuleRange(1, 3)))

	cases := map[string]int{
		"/none/evil":          http.StatusForbidden,
		"/some/evil":          http.StatusForbidden,
		"/all/evil":           http.StatusOK,
		"/partial-range/evil": http.StatusForbidden,
		"/full-range/evil":    http.StatusOK,
	}
	for path, want := range cases {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			f.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if have := rec.Code; want != have {
				t.Errorf("unexpected status code, want: %d, have: %d", want, have)
			}
		})
	}
}

func TestRemoveRulesForeignTransaction(t *testing.T) {
	w := newWAF(t, "SecRuleEngine On")
	tx := w.NewTransaction()
	defer tx.Close()

	foreign := struct{ types.Transaction }{tx}
	waf.RemoveRules(1)(nil, foreign)
	waf.RemoveRuleRange(1, 2)(nil, foreign)
}

func TestRemoveRuleRangeInvalid(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected a panic for an invalid range")
		}
	}()
	waf.RemoveRuleRange(2, 1)
}

func TestClientAddr(t *testing.T) {
	xRealIP, err := clientip.NewSingleIPHeader("X-Real-IP")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name       string
		resolver   fox.ClientIPResolver
		remoteAddr string
		xRealIP    string
		wantAddr   string
		wantPort   string
	}{
		{
			name:       "no resolver",
			remoteAddr: "192.0.2.1:1234",
			xRealIP:    "203.0.113.7",
			wantAddr:   "192.0.2.1",
			wantPort:   "1234",
		},
		{
			name:       "resolved from header",
			resolver:   xRealIP,
			remoteAddr: "192.0.2.1:1234",
			xRealIP:    "203.0.113.7",
			wantAddr:   "203.0.113.7",
			wantPort:   "0",
		},
		{
			name:       "resolver error falls back to the peer",
			resolver:   xRealIP,
			remoteAddr: "192.0.2.1:1234",
			wantAddr:   "192.0.2.1",
			wantPort:   "1234",
		},
		{
			name: "invalid resolved ip falls back to the peer",
			resolver: fox.ClientIPResolverFunc(func(fox.RequestContext) (netip.Addr, error) {
				return netip.Addr{}, nil
			}),
			remoteAddr: "192.0.2.1:1234",
			wantAddr:   "192.0.2.1",
			wantPort:   "1234",
		},
		{
			name:       "resolved ipv6",
			resolver:   clientip.NewRemoteAddr(),
			remoteAddr: "[2001:db8::1]:1234",
			wantAddr:   "2001:db8::1",
			wantPort:   "0",
		},
		{
			name:       "resolved ipv6 with zone",
			resolver:   clientip.NewRemoteAddr(),
			remoteAddr: "[fe80::1%eth0]:1234",
			wantAddr:   "fe80::1",
			wantPort:   "0",
		},
		{
			name: "resolved ipv4-mapped ipv6",
			resolver: fox.ClientIPResolverFunc(func(fox.RequestContext) (netip.Addr, error) {
				return netip.MustParseAddr("::ffff:203.0.113.7"), nil
			}),
			remoteAddr: "192.0.2.1:1234",
			wantAddr:   "203.0.113.7",
			wantPort:   "0",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var addr, port string
			capture := func(_ waf.Context, tx types.Transaction) {
				vars := tx.(plugintypes.TransactionState).Variables()
				addr, port = vars.RemoteAddr().Get(), vars.RemotePort().Get()
			}

			f := fox.MustRouter(fox.WithMiddleware(waf.Middleware(newWAF(t, "SecRuleEngine On"))))
			f.MustAdd(fox.MethodGet, "/", okHandler, waf.WithTransactionHook(capture), fox.WithClientIPResolver(tc.resolver))

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.xRealIP != "" {
				req.Header.Set("X-Real-IP", tc.xRealIP)
			}
			f.ServeHTTP(httptest.NewRecorder(), req)

			if addr != tc.wantAddr {
				t.Errorf("unexpected REMOTE_ADDR, want: %q, have: %q", tc.wantAddr, addr)
			}
			if port != tc.wantPort {
				t.Errorf("unexpected REMOTE_PORT, want: %q, have: %q", tc.wantPort, port)
			}
		})
	}
}

func TestClientAddrIPMatch(t *testing.T) {
	w := newWAF(t, `
SecRuleEngine On
SecRule REMOTE_ADDR "@ipMatch 2001:db8::/32,fe80::/10" "id:1,phase:1,deny,status:403"
`)

	f := fox.MustRouter(
		fox.WithMiddleware(waf.Middleware(w)),
		fox.WithClientIPResolver(clientip.NewRemoteAddr()),
	)
	f.MustAdd(fox.MethodGet, "/", okHandler)

	for _, remoteAddr := range []string{"[2001:db8::1]:1234", "[fe80::1%eth0]:1234"} {
		t.Run(remoteAddr, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = remoteAddr
			rec := httptest.NewRecorder()
			f.ServeHTTP(rec, req)
			if want, have := http.StatusForbidden, rec.Code; want != have {
				t.Errorf("unexpected status code, want: %d, have: %d", want, have)
			}
		})
	}
}
