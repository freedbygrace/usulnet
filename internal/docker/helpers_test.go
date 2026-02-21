// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package docker

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/client"
)

// versionPrefixRE matches the Docker API version prefix (e.g., /v1.45/).
var versionPrefixRE = regexp.MustCompile(`^/v\d+\.\d+`)

// versionStripHandler wraps an http.Handler and strips the /vN.NN version
// prefix from request URLs before dispatching. The Docker SDK client
// prepends a version prefix to every API call (e.g., /v1.45/containers/json),
// but our test mux registers patterns without it (e.g., /containers/json).
type versionStripHandler struct {
	inner http.Handler
}

func (h *versionStripHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.URL.Path = versionPrefixRE.ReplaceAllString(r.URL.Path, "")
	r.RequestURI = versionPrefixRE.ReplaceAllString(r.RequestURI, "")
	if r.URL.Path == "" {
		r.URL.Path = "/"
	}
	h.inner.ServeHTTP(w, r)
}

// newTestClient builds a Client backed by a mock HTTP server.
// The mux is pre-wired with /_ping so the Docker SDK's version
// negotiation succeeds. Callers register additional handlers on
// the returned mux for the endpoints they want to test.
// Handlers should use bare paths (e.g., "/containers/json"), without
// the /vN.NN version prefix -- it is stripped automatically.
func newTestClient(t *testing.T) (*Client, *http.ServeMux) {
	t.Helper()

	mux := http.NewServeMux()

	// Docker SDK calls /_ping during version negotiation.
	mux.HandleFunc("/_ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("API-Version", "1.45")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	srv := httptest.NewServer(&versionStripHandler{inner: mux})
	t.Cleanup(srv.Close)

	// Build a real Docker SDK client pointing at our test server.
	sdkClient, err := client.NewClientWithOpts(
		client.WithHost("tcp://"+strings.TrimPrefix(srv.URL, "http://")),
		client.WithHTTPClient(srv.Client()),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		t.Fatalf("creating SDK client: %v", err)
	}

	c := &Client{
		cli:        sdkClient,
		host:       srv.URL,
		apiVersion: "1.45",
		timeout:    DefaultTimeout,
	}
	t.Cleanup(func() { c.Close() })

	return c, mux
}

// jsonResponse writes v as JSON with the given status code.
func jsonResponse(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// newClosedClient returns a Client whose closed flag is true.
func newClosedClient(t *testing.T) *Client {
	t.Helper()
	c, _ := newTestClient(t)
	c.Close()
	return c
}

// ptr returns a pointer to v. Useful for optional int parameters.
func ptr[T any](v T) *T {
	return &v
}

// mustParseTime parses an RFC3339 string or panics.
func mustParseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic("mustParseTime: " + err.Error())
	}
	return t
}
