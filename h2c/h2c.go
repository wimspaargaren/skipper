// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package h2c implements the unencrypted "h2c" form of HTTP/2.
//
// The h2c protocol is the non-TLS version of HTTP/2
//
// The implementation is based on the golang.org/x/net/http2/h2c
package h2c

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
)

type Handler interface {
	// Shutdown gracefully shuts down the handler by waiting
	// indefinitely for h2c connections to close.
	// If the provided context expires before the shutdown is complete,
	// Shutdown returns the context's error.
	//
	// Shutdown should be called after http.Server Shutdown returns.
	Shutdown(context.Context) error
}

type Options struct{}

type h2cHandler struct {
	handler http.Handler
	s1      *http.Server
	s2      *http2.Server
	conns   int64
}

// Enable creates an http2.Server s2, wraps http.Server s1 original handler
// with a handler intercepting any h2c traffic and registers s2
// startGracefulShutdown on s1 Shutdown. It returns H2CHandler to be called
// after s1.Shutdown returns.
//
// If a request is an h2c connection, it is hijacked and redirected to the
// s2.ServeConn along with the original s1 handler. Otherwise the handler just
// forwards requests to the original s1 handler. This works because h2c is
// designed to be parsable as a valid HTTP/1, but ignored by any HTTP server
// that does not handle h2c. Therefore we leverage the HTTP/1 compatible parts
// of the Go http library to parse and recognize h2c requests.
//
// There are two ways to begin an h2c connection (RFC 7540 Section 3.2 and 3.4):
// (1) Starting with Prior Knowledge - this works by starting an h2c connection
// with a string of bytes that is valid HTTP/1, but unlikely to occur in
// practice and (2) Upgrading from HTTP/1 to h2c.
//
// This implementation workarounds several issues of the golang.org/x/net/http2/h2c:
// 	* drops support for upgrading from HTTP/1 to h2c, see https://github.com/golang/go/issues/38064
// 	* implements graceful shutdown, see https://github.com/golang/go/issues/26682
// 	* remove closing of the hijacked connection because s2.ServeConn closes it
// 	* removes buffered connection write
func Enable(s1 *http.Server, reserved *Options) Handler {
	s2 := &http2.Server{}
	h := &h2cHandler{handler: s1.Handler, s1: s1, s2: s2}

	// register s2 startGracefulShutdown on s1 Shutdown
	http2.ConfigureServer(s1, s2)
	s1.Handler = h

	return h
}

func (s *h2cHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Handle h2c with prior knowledge (RFC 7540 Section 3.4)
	if r.Method == "PRI" && len(r.Header) == 0 && r.URL.Path == "*" && r.Proto == "HTTP/2.0" {
		conn, err := initH2CWithPriorKnowledge(w)
		if err != nil {
			return
		}
		n := atomic.AddInt64(&s.conns, 1)
		log.Debugf("h2c start: %d connections", n)

		s.s2.ServeConn(conn, &http2.ServeConnOpts{Handler: s.handler, BaseConfig: s.s1})

		n = atomic.AddInt64(&s.conns, -1)
		log.Debugf("h2c done: %d connections", n)
	} else {
		s.handler.ServeHTTP(w, r)
	}
}

// initH2CWithPriorKnowledge implements creating an h2c connection with prior
// knowledge (Section 3.4) and creates a net.Conn suitable for http2.ServeConn.
// All we have to do is look for the client preface that is supposed to be a part
// of the body, and reforward the client preface on the net.Conn this function
// creates.
func initH2CWithPriorKnowledge(w http.ResponseWriter) (net.Conn, error) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("hijack is not supported")
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, err
	}
	r := rw.Reader

	const expectedBody = "SM\r\n\r\n"

	buf := make([]byte, len(expectedBody))
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return nil, err
	}

	if string(buf[:n]) == expectedBody {
		return &h2cConn{
			Conn:   conn,
			Reader: io.MultiReader(strings.NewReader(http2.ClientPreface), r),
		}, nil
	}

	conn.Close()
	return nil, errors.New("invalid client preface")
}

func (s *h2cHandler) Shutdown(ctx context.Context) error {
	timer := time.NewTicker(500 * time.Millisecond)
	defer timer.Stop()
	for {
		n := atomic.LoadInt64(&s.conns)
		log.Debugf("h2c close: %d connections", n)

		if n == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}

type h2cConn struct {
	net.Conn
	io.Reader
}

func (c *h2cConn) Read(p []byte) (int, error) {
	return c.Reader.Read(p)
}
