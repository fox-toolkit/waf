// Copyright 2024 Sylvain Müller.
// SPDX-License-Identifier: Apache-2.0

package waf_test

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/fox-toolkit/fox"
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
