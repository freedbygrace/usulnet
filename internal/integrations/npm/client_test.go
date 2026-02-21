// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package npm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

// newTestClient creates a Client backed by an httptest.Server.
// The server always handles POST /api/tokens with a valid token response.
// The caller may register additional routes via the setup callback.
func newTestClient(t *testing.T, setup func(mux *http.ServeMux)) *Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/tokens", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{Token: "test-tok"})
	})
	if setup != nil {
		setup(mux)
	}
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return NewClient(&Config{BaseURL: ts.URL, Email: "a@b.com", Password: "p"}, zap.NewNop())
}

// requireAuth is a helper that asserts the Authorization header is "Bearer test-tok".
func requireAuth(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.Header.Get("Authorization"); got != "Bearer test-tok" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer test-tok")
	}
}

// =============================================================================
// NewClient
// =============================================================================

func TestNewClient(t *testing.T) {
	cfg := &Config{
		BaseURL:  "http://npm:81",
		Email:    "admin@example.com",
		Password: "secret",
		Timeout:  10 * time.Second,
	}
	c := NewClient(cfg, zap.NewNop())

	if c.baseURL != cfg.BaseURL {
		t.Errorf("baseURL = %q, want %q", c.baseURL, cfg.BaseURL)
	}
	if c.email != cfg.Email {
		t.Errorf("email = %q, want %q", c.email, cfg.Email)
	}
	if c.password != cfg.Password {
		t.Errorf("password = %q, want %q", c.password, cfg.Password)
	}
	if c.httpClient.Timeout != 10*time.Second {
		t.Errorf("timeout = %v, want %v", c.httpClient.Timeout, 10*time.Second)
	}
}

func TestNewClient_DefaultTimeout(t *testing.T) {
	c := NewClient(&Config{BaseURL: "http://npm:81"}, zap.NewNop())
	if c.httpClient.Timeout != 30*time.Second {
		t.Errorf("default timeout = %v, want %v", c.httpClient.Timeout, 30*time.Second)
	}
}

// =============================================================================
// Authentication
// =============================================================================

func TestAuthenticate_Success(t *testing.T) {
	c := newTestClient(t, nil)
	ctx := context.Background()

	if err := c.authenticate(ctx); err != nil {
		t.Fatalf("authenticate() error = %v", err)
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.token != "test-tok" {
		t.Errorf("token = %q, want %q", c.token, "test-tok")
	}
	if c.tokenExp.IsZero() {
		t.Error("tokenExp should not be zero after successful auth")
	}
}

func TestAuthenticate_Failure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/tokens", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	c := NewClient(&Config{BaseURL: ts.URL, Email: "bad@b.com", Password: "wrong"}, zap.NewNop())

	err := c.authenticate(context.Background())
	if err == nil {
		t.Fatal("expected error on 401, got nil")
	}
	if !strings.Contains(err.Error(), "UNAUTHORIZED") {
		t.Errorf("error = %v, want UNAUTHORIZED code", err)
	}
}

func TestAuthenticate_TokenCaching(t *testing.T) {
	var authCalls atomic.Int64

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/tokens", func(w http.ResponseWriter, _ *http.Request) {
		authCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{Token: "test-tok"})
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	c := NewClient(&Config{BaseURL: ts.URL, Email: "a@b.com", Password: "p"}, zap.NewNop())
	ctx := context.Background()

	if err := c.authenticate(ctx); err != nil {
		t.Fatalf("first authenticate() error = %v", err)
	}
	if err := c.authenticate(ctx); err != nil {
		t.Fatalf("second authenticate() error = %v", err)
	}

	if n := authCalls.Load(); n != 1 {
		t.Errorf("auth endpoint hit %d times, want 1 (token should be cached)", n)
	}
}

// =============================================================================
// 401 Retry
// =============================================================================

func TestDoRequest_RetryOn401(t *testing.T) {
	var requestCount atomic.Int64

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/tokens", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{Token: "test-tok"})
	})
	mux.HandleFunc("GET /api/test", func(w http.ResponseWriter, r *http.Request) {
		n := requestCount.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	c := NewClient(&Config{BaseURL: ts.URL, Email: "a@b.com", Password: "p"}, zap.NewNop())
	resp, err := c.doRequest(context.Background(), "GET", "/api/test", nil)
	if err != nil {
		t.Fatalf("doRequest error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 after retry", resp.StatusCode)
	}
	if n := requestCount.Load(); n != 2 {
		t.Errorf("request endpoint hit %d times, want 2 (initial + retry)", n)
	}
}

// =============================================================================
// Proxy Hosts
// =============================================================================

func TestClient_ListProxyHosts(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("GET /api/nginx/proxy-hosts", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]*ProxyHost{
				{ID: 1, DomainNames: []string{"a.example.com"}, ForwardHost: "10.0.0.1", ForwardPort: 80},
				{ID: 2, DomainNames: []string{"b.example.com"}, ForwardHost: "10.0.0.2", ForwardPort: 443},
			})
		})
	})

	hosts, err := c.ListProxyHosts(context.Background())
	if err != nil {
		t.Fatalf("ListProxyHosts() error = %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("got %d hosts, want 2", len(hosts))
	}
	if hosts[0].ForwardHost != "10.0.0.1" {
		t.Errorf("host[0].ForwardHost = %q, want %q", hosts[0].ForwardHost, "10.0.0.1")
	}
}

func TestClient_GetProxyHost(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("GET /api/nginx/proxy-hosts/{id}", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(&ProxyHost{
				ID:          42,
				DomainNames: []string{"test.example.com"},
				ForwardHost: "192.168.1.1",
				ForwardPort: 8080,
			})
		})
	})

	host, err := c.GetProxyHost(context.Background(), 42)
	if err != nil {
		t.Fatalf("GetProxyHost() error = %v", err)
	}
	if host.ID != 42 {
		t.Errorf("ID = %d, want 42", host.ID)
	}
	if host.ForwardPort != 8080 {
		t.Errorf("ForwardPort = %d, want 8080", host.ForwardPort)
	}
}

func TestClient_GetProxyHost_NotFound(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("GET /api/nginx/proxy-hosts/{id}", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})
	})

	_, err := c.GetProxyHost(context.Background(), 999)
	if err == nil {
		t.Fatal("expected error on 404, got nil")
	}
	if !strings.Contains(err.Error(), "NOT_FOUND") {
		t.Errorf("error = %v, want NOT_FOUND code", err)
	}
}

func TestClient_CreateProxyHost(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("POST /api/nginx/proxy-hosts", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			var input ProxyHost
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Errorf("decode body: %v", err)
			}
			if input.ForwardHost != "10.0.0.5" {
				t.Errorf("ForwardHost = %q, want %q", input.ForwardHost, "10.0.0.5")
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			input.ID = 10
			json.NewEncoder(w).Encode(&input)
		})
	})

	host := &ProxyHost{
		DomainNames:   []string{"new.example.com"},
		ForwardScheme: "http",
		ForwardHost:   "10.0.0.5",
		ForwardPort:   3000,
	}
	created, err := c.CreateProxyHost(context.Background(), host)
	if err != nil {
		t.Fatalf("CreateProxyHost() error = %v", err)
	}
	if created.ID != 10 {
		t.Errorf("created.ID = %d, want 10", created.ID)
	}
}

func TestClient_UpdateProxyHost(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("PUT /api/nginx/proxy-hosts/{id}", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(&ProxyHost{
				ID:          5,
				DomainNames: []string{"updated.example.com"},
				ForwardHost: "10.0.0.99",
				ForwardPort: 9090,
			})
		})
	})

	updated, err := c.UpdateProxyHost(context.Background(), 5, &ProxyHost{
		DomainNames: []string{"updated.example.com"},
		ForwardHost: "10.0.0.99",
		ForwardPort: 9090,
	})
	if err != nil {
		t.Fatalf("UpdateProxyHost() error = %v", err)
	}
	if updated.ForwardHost != "10.0.0.99" {
		t.Errorf("ForwardHost = %q, want %q", updated.ForwardHost, "10.0.0.99")
	}
}

func TestClient_DeleteProxyHost(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("DELETE /api/nginx/proxy-hosts/{id}", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			w.WriteHeader(http.StatusNoContent)
		})
	})

	if err := c.DeleteProxyHost(context.Background(), 5); err != nil {
		t.Fatalf("DeleteProxyHost() error = %v", err)
	}
}

func TestClient_EnableDisableProxyHost(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("POST /api/nginx/proxy-hosts/{id}/enable", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			w.WriteHeader(http.StatusOK)
		})
		mux.HandleFunc("POST /api/nginx/proxy-hosts/{id}/disable", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			w.WriteHeader(http.StatusOK)
		})
	})

	ctx := context.Background()
	if err := c.EnableProxyHost(ctx, 7); err != nil {
		t.Fatalf("EnableProxyHost() error = %v", err)
	}
	if err := c.DisableProxyHost(ctx, 7); err != nil {
		t.Fatalf("DisableProxyHost() error = %v", err)
	}
}

// =============================================================================
// Redirection Hosts
// =============================================================================

func TestClient_ListRedirectionHosts(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("GET /api/nginx/redirection-hosts", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]*RedirectionHost{
				{ID: 1, DomainNames: []string{"old.example.com"}, ForwardDomainName: "new.example.com", ForwardHTTPCode: 301},
			})
		})
	})

	hosts, err := c.ListRedirectionHosts(context.Background())
	if err != nil {
		t.Fatalf("ListRedirectionHosts() error = %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(hosts))
	}
	if hosts[0].ForwardHTTPCode != 301 {
		t.Errorf("ForwardHTTPCode = %d, want 301", hosts[0].ForwardHTTPCode)
	}
}

func TestClient_GetRedirectionHost_NotFound(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("GET /api/nginx/redirection-hosts/{id}", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})
	})

	_, err := c.GetRedirectionHost(context.Background(), 999)
	if err == nil {
		t.Fatal("expected error on 404, got nil")
	}
	if !strings.Contains(err.Error(), "NOT_FOUND") {
		t.Errorf("error = %v, want NOT_FOUND code", err)
	}
}

func TestClient_CreateRedirectionHost(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("POST /api/nginx/redirection-hosts", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(&RedirectionHost{
				ID:                20,
				DomainNames:       []string{"redir.example.com"},
				ForwardDomainName: "target.example.com",
				ForwardHTTPCode:   302,
			})
		})
	})

	host := &RedirectionHost{
		DomainNames:       []string{"redir.example.com"},
		ForwardDomainName: "target.example.com",
		ForwardHTTPCode:   302,
	}
	created, err := c.CreateRedirectionHost(context.Background(), host)
	if err != nil {
		t.Fatalf("CreateRedirectionHost() error = %v", err)
	}
	if created.ID != 20 {
		t.Errorf("ID = %d, want 20", created.ID)
	}
}

func TestClient_DeleteRedirectionHost(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("DELETE /api/nginx/redirection-hosts/{id}", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			w.WriteHeader(http.StatusNoContent)
		})
	})

	if err := c.DeleteRedirectionHost(context.Background(), 20); err != nil {
		t.Fatalf("DeleteRedirectionHost() error = %v", err)
	}
}

// =============================================================================
// Streams
// =============================================================================

func TestClient_ListStreams(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("GET /api/nginx/streams", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]*Stream{
				{ID: 1, IncomingPort: 3306, ForwardingHost: "db.local", ForwardingPort: 3306, TCPForwarding: true},
			})
		})
	})

	streams, err := c.ListStreams(context.Background())
	if err != nil {
		t.Fatalf("ListStreams() error = %v", err)
	}
	if len(streams) != 1 {
		t.Fatalf("got %d streams, want 1", len(streams))
	}
	if streams[0].IncomingPort != 3306 {
		t.Errorf("IncomingPort = %d, want 3306", streams[0].IncomingPort)
	}
}

func TestClient_GetStream(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("GET /api/nginx/streams/{id}", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(&Stream{
				ID:             3,
				IncomingPort:   5432,
				ForwardingHost: "pg.local",
				ForwardingPort: 5432,
				TCPForwarding:  true,
			})
		})
	})

	stream, err := c.GetStream(context.Background(), 3)
	if err != nil {
		t.Fatalf("GetStream() error = %v", err)
	}
	if stream.ID != 3 {
		t.Errorf("ID = %d, want 3", stream.ID)
	}
	if stream.ForwardingHost != "pg.local" {
		t.Errorf("ForwardingHost = %q, want %q", stream.ForwardingHost, "pg.local")
	}
}

func TestClient_CreateStream(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("POST /api/nginx/streams", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			var input Stream
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Errorf("decode body: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			input.ID = 50
			json.NewEncoder(w).Encode(&input)
		})
	})

	stream := &Stream{
		IncomingPort:   8443,
		ForwardingHost: "backend.local",
		ForwardingPort: 443,
		TCPForwarding:  true,
	}
	created, err := c.CreateStream(context.Background(), stream)
	if err != nil {
		t.Fatalf("CreateStream() error = %v", err)
	}
	if created.ID != 50 {
		t.Errorf("ID = %d, want 50", created.ID)
	}
}

func TestClient_DeleteStream(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("DELETE /api/nginx/streams/{id}", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			w.WriteHeader(http.StatusNoContent)
		})
	})

	if err := c.DeleteStream(context.Background(), 50); err != nil {
		t.Fatalf("DeleteStream() error = %v", err)
	}
}

// =============================================================================
// Dead Hosts
// =============================================================================

func TestClient_ListDeadHosts(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("GET /api/nginx/dead-hosts", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]*DeadHost{
				{ID: 1, DomainNames: []string{"dead.example.com"}, Enabled: true},
				{ID: 2, DomainNames: []string{"gone.example.com"}, Enabled: false},
			})
		})
	})

	hosts, err := c.ListDeadHosts(context.Background())
	if err != nil {
		t.Fatalf("ListDeadHosts() error = %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("got %d hosts, want 2", len(hosts))
	}
	if hosts[0].DomainNames[0] != "dead.example.com" {
		t.Errorf("DomainNames[0] = %q, want %q", hosts[0].DomainNames[0], "dead.example.com")
	}
}

func TestClient_CreateDeadHost(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("POST /api/nginx/dead-hosts", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(&DeadHost{
				ID:          30,
				DomainNames: []string{"block.example.com"},
				Enabled:     true,
			})
		})
	})

	host := &DeadHost{
		DomainNames: []string{"block.example.com"},
	}
	created, err := c.CreateDeadHost(context.Background(), host)
	if err != nil {
		t.Fatalf("CreateDeadHost() error = %v", err)
	}
	if created.ID != 30 {
		t.Errorf("ID = %d, want 30", created.ID)
	}
}

func TestClient_DeleteDeadHost(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("DELETE /api/nginx/dead-hosts/{id}", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			w.WriteHeader(http.StatusOK)
		})
	})

	if err := c.DeleteDeadHost(context.Background(), 30); err != nil {
		t.Fatalf("DeleteDeadHost() error = %v", err)
	}
}

// =============================================================================
// Certificates
// =============================================================================

func TestClient_ListCertificates(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("GET /api/nginx/certificates", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]*Certificate{
				{ID: 1, Provider: "letsencrypt", NiceName: "main cert", DomainNames: []string{"example.com"}},
				{ID: 2, Provider: "other", NiceName: "custom cert", DomainNames: []string{"internal.local"}},
			})
		})
	})

	certs, err := c.ListCertificates(context.Background())
	if err != nil {
		t.Fatalf("ListCertificates() error = %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("got %d certs, want 2", len(certs))
	}
	if certs[0].Provider != "letsencrypt" {
		t.Errorf("Provider = %q, want %q", certs[0].Provider, "letsencrypt")
	}
}

func TestClient_GetCertificate_NotFound(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("GET /api/nginx/certificates/{id}", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})
	})

	_, err := c.GetCertificate(context.Background(), 999)
	if err == nil {
		t.Fatal("expected error on 404, got nil")
	}
	if !strings.Contains(err.Error(), "NOT_FOUND") {
		t.Errorf("error = %v, want NOT_FOUND code", err)
	}
}

func TestClient_RequestLetsEncryptCertificate(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("POST /api/nginx/certificates", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			var input CertificateRequest
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Errorf("decode body: %v", err)
			}
			if !input.LetsencryptAgree {
				t.Error("LetsencryptAgree should be true")
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(&Certificate{
				ID:          100,
				Provider:    "letsencrypt",
				NiceName:    "LE cert",
				DomainNames: input.DomainNames,
			})
		})
	})

	req := &CertificateRequest{
		DomainNames:      []string{"secure.example.com"},
		LetsencryptEmail: "admin@example.com",
		LetsencryptAgree: true,
	}
	cert, err := c.RequestLetsEncryptCertificate(context.Background(), req)
	if err != nil {
		t.Fatalf("RequestLetsEncryptCertificate() error = %v", err)
	}
	if cert.ID != 100 {
		t.Errorf("ID = %d, want 100", cert.ID)
	}
	if cert.Provider != "letsencrypt" {
		t.Errorf("Provider = %q, want %q", cert.Provider, "letsencrypt")
	}
}

func TestClient_UploadCustomCertificate(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("POST /api/nginx/certificates", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			var payload map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode body: %v", err)
			}
			if payload["provider"] != "other" {
				t.Errorf("provider = %v, want %q", payload["provider"], "other")
			}
			if payload["nice_name"] != "My Custom Cert" {
				t.Errorf("nice_name = %v, want %q", payload["nice_name"], "My Custom Cert")
			}
			meta, ok := payload["meta"].(map[string]interface{})
			if !ok {
				t.Fatal("meta is not a map")
			}
			if meta["certificate"] != "CERT-DATA" {
				t.Errorf("certificate = %v, want %q", meta["certificate"], "CERT-DATA")
			}
			if meta["certificate_key"] != "KEY-DATA" {
				t.Errorf("certificate_key = %v, want %q", meta["certificate_key"], "KEY-DATA")
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(&Certificate{
				ID:       200,
				Provider: "other",
				NiceName: "My Custom Cert",
			})
		})
	})

	cert, err := c.UploadCustomCertificate(context.Background(), "My Custom Cert", []byte("CERT-DATA"), []byte("KEY-DATA"), []byte("INTER-DATA"))
	if err != nil {
		t.Fatalf("UploadCustomCertificate() error = %v", err)
	}
	if cert.ID != 200 {
		t.Errorf("ID = %d, want 200", cert.ID)
	}
	if cert.Provider != "other" {
		t.Errorf("Provider = %q, want %q", cert.Provider, "other")
	}
}

func TestClient_RenewCertificate(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("POST /api/nginx/certificates/{id}/renew", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(&Certificate{
				ID:        10,
				Provider:  "letsencrypt",
				NiceName:  "renewed",
				ExpiresOn: "2027-01-01",
			})
		})
	})

	cert, err := c.RenewCertificate(context.Background(), 10)
	if err != nil {
		t.Fatalf("RenewCertificate() error = %v", err)
	}
	if cert.ExpiresOn != "2027-01-01" {
		t.Errorf("ExpiresOn = %q, want %q", cert.ExpiresOn, "2027-01-01")
	}
}

// =============================================================================
// Access Lists
// =============================================================================

func TestClient_ListAccessLists(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("GET /api/nginx/access-lists", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			if q := r.URL.Query().Get("expand"); q != "items,clients" {
				t.Errorf("expand query = %q, want %q", q, "items,clients")
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]*AccessList{
				{
					ID:   1,
					Name: "Admin ACL",
					Items: []AccessListItem{
						{Username: "admin", Password: "hashed"},
					},
					Clients: []AccessListClient{
						{Address: "192.168.1.0/24", Directive: "allow"},
					},
				},
			})
		})
	})

	lists, err := c.ListAccessLists(context.Background())
	if err != nil {
		t.Fatalf("ListAccessLists() error = %v", err)
	}
	if len(lists) != 1 {
		t.Fatalf("got %d lists, want 1", len(lists))
	}
	if lists[0].Name != "Admin ACL" {
		t.Errorf("Name = %q, want %q", lists[0].Name, "Admin ACL")
	}
	if len(lists[0].Clients) != 1 {
		t.Fatalf("got %d clients, want 1", len(lists[0].Clients))
	}
	if lists[0].Clients[0].Directive != "allow" {
		t.Errorf("Directive = %q, want %q", lists[0].Clients[0].Directive, "allow")
	}
}

func TestClient_GetAccessList(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("GET /api/nginx/access-lists/{id}", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(&AccessList{
				ID:         5,
				Name:       "Dev ACL",
				SatisfyAny: true,
			})
		})
	})

	list, err := c.GetAccessList(context.Background(), 5)
	if err != nil {
		t.Fatalf("GetAccessList() error = %v", err)
	}
	if list.ID != 5 {
		t.Errorf("ID = %d, want 5", list.ID)
	}
	if !list.SatisfyAny {
		t.Error("SatisfyAny should be true")
	}
}

func TestClient_CreateAccessList(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("POST /api/nginx/access-lists", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			var input AccessList
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Errorf("decode body: %v", err)
			}
			if input.Name != "New ACL" {
				t.Errorf("Name = %q, want %q", input.Name, "New ACL")
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			input.ID = 15
			json.NewEncoder(w).Encode(&input)
		})
	})

	list := &AccessList{
		Name:       "New ACL",
		SatisfyAny: false,
		Items: []AccessListItem{
			{Username: "user1", Password: "pass1"},
		},
	}
	created, err := c.CreateAccessList(context.Background(), list)
	if err != nil {
		t.Fatalf("CreateAccessList() error = %v", err)
	}
	if created.ID != 15 {
		t.Errorf("ID = %d, want 15", created.ID)
	}
}

func TestClient_DeleteAccessList(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("DELETE /api/nginx/access-lists/{id}", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			w.WriteHeader(http.StatusNoContent)
		})
	})

	if err := c.DeleteAccessList(context.Background(), 15); err != nil {
		t.Fatalf("DeleteAccessList() error = %v", err)
	}
}

// =============================================================================
// Reports / Stats
// =============================================================================

func TestClient_GetHostsCount(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("GET /api/reports/hosts", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(&HostsCount{
				Proxy:       10,
				Redirection: 3,
				Stream:      2,
				Dead:        1,
			})
		})
	})

	count, err := c.GetHostsCount(context.Background())
	if err != nil {
		t.Fatalf("GetHostsCount() error = %v", err)
	}
	if count.Proxy != 10 {
		t.Errorf("Proxy = %d, want 10", count.Proxy)
	}
	if count.Redirection != 3 {
		t.Errorf("Redirection = %d, want 3", count.Redirection)
	}
	if count.Stream != 2 {
		t.Errorf("Stream = %d, want 2", count.Stream)
	}
	if count.Dead != 1 {
		t.Errorf("Dead = %d, want 1", count.Dead)
	}
}

// =============================================================================
// Settings
// =============================================================================

func TestClient_GetSettings(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("GET /api/settings", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]*Setting{
				{ID: "default-site", Name: "Default Site", Value: "congratulations"},
				{ID: "some-other", Name: "Other Setting", Value: true},
			})
		})
	})

	settings, err := c.GetSettings(context.Background())
	if err != nil {
		t.Fatalf("GetSettings() error = %v", err)
	}
	if len(settings) != 2 {
		t.Fatalf("got %d settings, want 2", len(settings))
	}
	if settings[0].ID != "default-site" {
		t.Errorf("ID = %q, want %q", settings[0].ID, "default-site")
	}
}

func TestClient_UpdateSetting(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("PUT /api/settings/{id}", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			var payload map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode body: %v", err)
			}
			if payload["value"] != "redirect" {
				t.Errorf("value = %v, want %q", payload["value"], "redirect")
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(&Setting{
				ID:    "default-site",
				Name:  "Default Site",
				Value: "redirect",
			})
		})
	})

	setting, err := c.UpdateSetting(context.Background(), "default-site", "redirect")
	if err != nil {
		t.Fatalf("UpdateSetting() error = %v", err)
	}
	if setting.Value != "redirect" {
		t.Errorf("Value = %v, want %q", setting.Value, "redirect")
	}
}

// =============================================================================
// Nginx Control
// =============================================================================

func TestClient_ReloadNginx(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("POST /api/nginx/reload", func(w http.ResponseWriter, r *http.Request) {
			requireAuth(t, r)
			w.WriteHeader(http.StatusOK)
		})
	})

	if err := c.ReloadNginx(context.Background()); err != nil {
		t.Fatalf("ReloadNginx() error = %v", err)
	}
}

// =============================================================================
// Health
// =============================================================================

func TestClient_Health(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	c := NewClient(&Config{BaseURL: ts.URL}, zap.NewNop())

	if err := c.Health(context.Background()); err != nil {
		t.Fatalf("Health() error = %v", err)
	}
}

func TestClient_Health_Unreachable(t *testing.T) {
	// Point at a server that is already closed.
	ts := httptest.NewServer(http.NewServeMux())
	ts.Close()

	c := NewClient(&Config{BaseURL: ts.URL}, zap.NewNop())

	err := c.Health(context.Background())
	if err == nil {
		t.Fatal("expected error for unreachable server, got nil")
	}
	if !strings.Contains(err.Error(), "NPM_CONNECTION_FAILED") {
		t.Errorf("error = %v, want NPM_CONNECTION_FAILED code", err)
	}
}

// =============================================================================
// Error Handling
// =============================================================================

func TestHandleError_JSONMessage(t *testing.T) {
	c := newTestClient(t, nil)

	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "application/json")
	rec.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(rec).Encode(APIError{Message: "domain already taken"})

	resp := rec.Result()
	defer resp.Body.Close()

	err := c.handleError(resp)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "domain already taken") {
		t.Errorf("error = %v, want message containing %q", err, "domain already taken")
	}
}

func TestHandleError_PlainText(t *testing.T) {
	c := newTestClient(t, nil)

	rec := httptest.NewRecorder()
	rec.WriteHeader(http.StatusInternalServerError)
	io.WriteString(rec, "nginx: unexpected failure")

	resp := rec.Result()
	defer resp.Body.Close()

	err := c.handleError(resp)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "nginx: unexpected failure") {
		t.Errorf("error = %v, want message containing raw body text", err)
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %v, want status code 500 in message", err)
	}
}

func TestHandleError_AuthFailure(t *testing.T) {
	c := newTestClient(t, nil)

	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		rec := httptest.NewRecorder()
		rec.WriteHeader(code)
		io.WriteString(rec, "access denied")

		resp := rec.Result()
		err := c.handleError(resp)
		resp.Body.Close()

		if err == nil {
			t.Fatalf("status %d: expected error, got nil", code)
		}
		if !strings.Contains(err.Error(), "UNAUTHORIZED") {
			t.Errorf("status %d: error = %v, want UNAUTHORIZED code", code, err)
		}
	}
}

// =============================================================================
// Struct Types
// =============================================================================

func TestProxyHost_JSON(t *testing.T) {
	original := &ProxyHost{
		ID:                    1,
		DomainNames:           []string{"a.example.com", "b.example.com"},
		ForwardScheme:         "https",
		ForwardHost:           "10.0.0.1",
		ForwardPort:           8443,
		SSLForced:             true,
		HSTSEnabled:           true,
		HTTP2Support:          true,
		BlockExploits:         true,
		AllowWebsocketUpgrade: true,
		Enabled:               true,
		AdvancedConfig:        "proxy_set_header X-Real-IP $remote_addr;",
		Locations: []ProxyHostLocation{
			{Path: "/api", ForwardScheme: "http", ForwardHost: "api.local", ForwardPort: 3000},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}

	var decoded ProxyHost
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}

	if decoded.ID != original.ID {
		t.Errorf("ID = %d, want %d", decoded.ID, original.ID)
	}
	if len(decoded.DomainNames) != 2 {
		t.Errorf("DomainNames length = %d, want 2", len(decoded.DomainNames))
	}
	if decoded.ForwardScheme != "https" {
		t.Errorf("ForwardScheme = %q, want %q", decoded.ForwardScheme, "https")
	}
	if !decoded.SSLForced {
		t.Error("SSLForced should be true after round-trip")
	}
	if !decoded.AllowWebsocketUpgrade {
		t.Error("AllowWebsocketUpgrade should be true after round-trip")
	}
	if len(decoded.Locations) != 1 {
		t.Fatalf("Locations length = %d, want 1", len(decoded.Locations))
	}
	if decoded.Locations[0].Path != "/api" {
		t.Errorf("Location.Path = %q, want %q", decoded.Locations[0].Path, "/api")
	}
	if decoded.AdvancedConfig != original.AdvancedConfig {
		t.Errorf("AdvancedConfig = %q, want %q", decoded.AdvancedConfig, original.AdvancedConfig)
	}
}

func TestConfig_Defaults(t *testing.T) {
	var cfg Config

	if cfg.BaseURL != "" {
		t.Errorf("BaseURL zero value = %q, want empty", cfg.BaseURL)
	}
	if cfg.Email != "" {
		t.Errorf("Email zero value = %q, want empty", cfg.Email)
	}
	if cfg.Password != "" {
		t.Errorf("Password zero value = %q, want empty", cfg.Password)
	}
	if cfg.Timeout != 0 {
		t.Errorf("Timeout zero value = %v, want 0", cfg.Timeout)
	}

	// NewClient should apply the default timeout of 30s when Timeout is zero.
	c := NewClient(&cfg, zap.NewNop())
	if c.httpClient.Timeout != 30*time.Second {
		t.Errorf("client timeout = %v, want %v", c.httpClient.Timeout, 30*time.Second)
	}
}
