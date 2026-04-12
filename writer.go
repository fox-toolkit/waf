// Copyright 2024 Sylvain Müller.
// SPDX-License-Identifier: Apache-2.0

// Part of the code in this package is derivative of https://github.com/corazawaf/coraza (all credit to Juan Pablo Tosso
// and the OWASP Coraza contributors). Mount of this source code is governed by an Apache-2.0 that can be found
// at https://github.com/corazawaf/coraza/blob/main/LICENSE.

package waf

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"path"
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3/types"
	"github.com/fox-toolkit/fox"
)

var _ fox.ResponseWriter = (*rwInterceptor)(nil)

var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

const notWritten = -1

type rwInterceptor struct {
	w                             fox.ResponseWriter
	tx                            types.Transaction
	proto                         string
	statusCode                    int
	size                          int
	isWriteHeaderFlush            bool
	wroteHeader                   bool
	wroteBufferedBodyToDownstream bool
	isHijacked                    bool
	allowFlushing                 bool
}

// Status recorded after Write and WriteHeader.
func (w *rwInterceptor) Status() int {
	return w.statusCode
}

// Written returns true if the response has been written.
func (w *rwInterceptor) Written() bool {
	return w.size != notWritten
}

// Size returns the size of the written response.
func (w *rwInterceptor) Size() int {
	if w.size < 0 {
		return 0
	}
	return w.size
}

// WriteHeader records the status code to be sent right before the moment
// the body is being written.
func (w *rwInterceptor) WriteHeader(statusCode int) {
	if w.wroteHeader {
		caller := relevantCaller()
		w.tx.DebugLogger().Warn().
			Str("caller", caller.Function).
			Str("file", path.Base(caller.File)).
			Int("line", caller.Line).
			Msg("http: superfluous response.WriteHeader call")
		return
	}

	w.wroteHeader = true

	for k, vv := range w.w.Header() {
		for _, v := range vv {
			w.tx.AddResponseHeader(k, v)
		}
	}

	w.statusCode = statusCode
	w.size = 0
	if it := w.tx.ProcessResponseHeaders(statusCode, w.proto); it != nil {
		w.cleanHeaders()
		w.Header().Set("Content-Length", "0")
		w.statusCode = obtainStatusCodeFromInterruptionOrDefault(it, w.statusCode)
		w.flushWriteHeader()
		return
	}

	// For WebSocket upgrades (101 Switching Protocols), flush the headers
	// immediately. The connection is about to be hijacked for bidirectional
	// communication and there will be no HTTP response body to process.
	if statusCode == http.StatusSwitchingProtocols {
		w.flushWriteHeader()
	}
	if !w.tx.IsResponseBodyAccessible() || !w.tx.IsResponseBodyProcessable() {
		// if the response body isn't accessible or processable we can already allow flushing
		// we need to set this flag before the first call to Flush()
		w.allowFlushing = true
	}
}

// Write buffers the response body until the request body limit is reach or an
// interruption is triggered, this buffer is later used to analyse the body in
// the response processor.
// If the body isn't accessible or the mime type isn't processable, the response
// body is being writen to the delegate response writer directly.
func (w *rwInterceptor) Write(b []byte) (int, error) {
	if w.tx.IsInterrupted() {
		// if there is an interruption it must be from at least phase 4 and hence
		// WriteHeader or Write should have been called and hence the status code
		// has been flushed to the delegated response writer.
		return 0, nil
	}

	if !w.wroteHeader {
		// if no header has been wrote at this point we aim to return 200
		w.WriteHeader(http.StatusOK)
	}

	if w.tx.IsResponseBodyAccessible() && w.tx.IsResponseBodyProcessable() && !w.wroteBufferedBodyToDownstream {
		// we only buffer the response body if we are going to access
		// to it, otherwise we just send it to the response writer.
		it, n, err := w.tx.WriteResponseBody(b)
		if it != nil {
			// if there is an interruption we must clean the headers and override the status code
			w.cleanHeaders()
			w.Header().Set("Content-Length", "0")
			w.overrideWriteHeader(obtainStatusCodeFromInterruptionOrDefault(it, w.statusCode))
			// We only flush the status code after an interruption.
			w.flushWriteHeader()
			return 0, nil
		}
		if err != nil || n == len(b) {
			w.size += n
			return n, err
		}
		if err := w.writeBufferedResponseBodyToDownstream(); err != nil {
			w.size += n
			return n, err
		}
		n2, err := w.w.Write(b[n:])
		w.size += n + n2
		return n + n2, err
	}

	// flush the status code before writing
	w.flushWriteHeader()

	// if response body isn't accesible or processable we write the response bytes
	// directly to the caller.
	n, err := w.w.Write(b)
	w.size += n
	return n, err
}

// WriteString writes the provided string to the underlying connection
// as part of an HTTP reply. The method returns the number of bytes written
// and an error, if any.
func (w *rwInterceptor) WriteString(s string) (n int, err error) {
	return io.WriteString(onlyWrite{w}, s)
}

// ReadFrom reads data from src until EOF or error. The return value n is the number of bytes read.
// Any error except EOF encountered during the read is also returned.
func (w *rwInterceptor) ReadFrom(src io.Reader) (n int64, err error) {
	bufp := copyBufPool.Get().(*[]byte)
	buf := *bufp
	// onlyWrite hide "ReadFrom" from w.
	n, err = io.CopyBuffer(onlyWrite{w}, src, buf)
	copyBufPool.Put(bufp)
	return
}

// FlushError flushes buffered data to the client.
func (w *rwInterceptor) FlushError() error {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}

	if w.allowFlushing && w.isWriteHeaderFlush {
		// only propagate flush if the headers have been flushed already
		return w.w.FlushError()
	}
	return nil
}

// Push initiates an HTTP/2 server push. Push returns http.ErrNotSupported if the client has disabled push or if push
// is not supported on the underlying connection. See http.Pusher for more details.
func (w *rwInterceptor) Push(target string, opts *http.PushOptions) error {
	return w.w.Push(target, opts)
}

// Hijack lets the caller take over the connection. If hijacking the connection is not supported, Hijack returns
// an error matching http.ErrNotSupported. See http.Hijacker for more details.
func (w *rwInterceptor) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := w.w.Hijack()
	if err != nil {
		return conn, rw, err
	}
	w.isHijacked = true
	return conn, rw, nil
}

func (w *rwInterceptor) Header() http.Header {
	return w.w.Header()
}

// SetReadDeadline sets the deadline for reading the entire request, including the body. Reads from the request
// body after the deadline has been exceeded will return an error. A zero value means no deadline. Setting the read
// deadline after it has been exceeded will not extend it. If SetReadDeadline is not supported, it returns
// an error matching http.ErrNotSupported.
func (w *rwInterceptor) SetReadDeadline(deadline time.Time) error {
	return w.w.SetReadDeadline(deadline)
}

// SetWriteDeadline sets the deadline for writing the response. Writes to the response body after the deadline has
// been exceeded will not block, but may succeed if the data has been buffered. A zero value means no deadline.
// Setting the write deadline after it has been exceeded will not extend it. If SetWriteDeadline is not supported,
// it returns an error matching http.ErrNotSupported.
func (w *rwInterceptor) SetWriteDeadline(deadline time.Time) error {
	return w.w.SetWriteDeadline(deadline)
}

func (w *rwInterceptor) EnableFullDuplex() error {
	return fox.ErrNotSupported()
}

func (w *rwInterceptor) reset(tx types.Transaction, writer fox.ResponseWriter, proto string) {
	w.w = writer
	w.tx = tx
	w.statusCode = http.StatusOK
	w.proto = proto
	w.size = notWritten
	w.isWriteHeaderFlush = false
	w.wroteHeader = false
	w.wroteBufferedBodyToDownstream = false
	w.isHijacked = false
	w.allowFlushing = false
}

// overrideWriteHeader overrides the recorded status code
func (w *rwInterceptor) overrideWriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.size = 0
}

// flushWriteHeader sends the status code to the delegate writers
func (w *rwInterceptor) flushWriteHeader() {
	if !w.isWriteHeaderFlush {
		w.w.WriteHeader(w.statusCode)
		w.isWriteHeaderFlush = true
	}
}

// cleanHeaders removes all headers from the response
func (w *rwInterceptor) cleanHeaders() {
	for k := range w.w.Header() {
		w.w.Header().Del(k)
	}
}

// writeBufferedResponseBodyToDownstream releases the buffered response body
// to the underlying writer. It is idempotent.
func (w *rwInterceptor) writeBufferedResponseBodyToDownstream() error {
	if w.wroteBufferedBodyToDownstream {
		return nil
	}

	// we release the buffer
	reader, err := w.tx.ResponseBodyReader()
	if err != nil {
		w.overrideWriteHeader(http.StatusInternalServerError)
		w.flushWriteHeader()
		return fmt.Errorf("failed to release the response body reader: %v", err)
	}

	// this is the last opportunity we have to report the resolved status code
	// as next step is write into the response writer (triggering a 200 in the
	// response status code.)
	w.flushWriteHeader()
	if _, err := io.Copy(w.w, reader); err != nil {
		return fmt.Errorf("failed to copy the response body: %v", err)
	}

	w.wroteBufferedBodyToDownstream = true
	return nil
}

type onlyWrite struct {
	io.Writer
}
