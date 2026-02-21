// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package nginx

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

func testHost(id uuid.UUID) *models.ProxyHost {
	return &models.ProxyHost{
		ID:                id,
		Name:              "test-app",
		Domains:           []string{"app.example.com"},
		Enabled:           true,
		UpstreamScheme:    "http",
		UpstreamHost:      "10.0.0.5",
		UpstreamPort:      8080,
		SSLMode:           models.ProxySSLModeNone,
		EnableWebSocket:   false,
		EnableCompression: false,
		EnableHSTS:        false,
		EnableHTTP2:       false,
	}
}

func TestBuildConfig_EmptyHosts(t *testing.T) {
	config := BuildConfig(nil, nil, "admin@example.com", "", "", "/certs", "/acme")
	if !strings.Contains(config, "# Hosts: 0") {
		t.Error("expected host count 0 in header")
	}
	if !strings.Contains(config, "default_server") {
		t.Error("expected default server block")
	}
}

func TestBuildConfig_DefaultPorts(t *testing.T) {
	config := BuildConfig(nil, nil, "", "", "", "/certs", "/acme")
	if !strings.Contains(config, "listen 80 default_server") {
		t.Errorf("expected default HTTP port 80, got:\n%s", config)
	}
}

func TestBuildConfig_StripColonFromPorts(t *testing.T) {
	config := BuildConfig(nil, nil, "", ":8080", ":8443", "/certs", "/acme")
	if !strings.Contains(config, "listen 8080 default_server") {
		t.Error("expected colon stripped from listen port")
	}
}

func TestBuildConfig_DisabledHostSkipped(t *testing.T) {
	id := uuid.New()
	h := testHost(id)
	h.Enabled = false
	config := BuildConfig([]*models.ProxyHost{h}, nil, "", "", "", "/certs", "/acme")
	if strings.Contains(config, "app.example.com") {
		t.Error("disabled host should not appear in config")
	}
}

func TestBuildConfig_PlainHTTPHost(t *testing.T) {
	id := uuid.New()
	h := testHost(id)
	config := BuildConfig([]*models.ProxyHost{h}, nil, "", "80", "443", "/certs", "/acme")

	if !strings.Contains(config, "server_name app.example.com") {
		t.Error("expected server_name directive")
	}
	if !strings.Contains(config, "listen 80;") {
		t.Error("expected HTTP listen directive")
	}
	if strings.Contains(config, "ssl") {
		t.Error("plain HTTP host should not have ssl directives")
	}
	if !strings.Contains(config, "proxy_pass http://") {
		t.Error("expected proxy_pass directive")
	}
}

func TestBuildConfig_SSLHost(t *testing.T) {
	id := uuid.New()
	h := testHost(id)
	h.SSLMode = models.ProxySSLModeAuto
	h.SSLForceHTTPS = true
	h.EnableHTTP2 = true
	h.EnableHSTS = true

	config := BuildConfig([]*models.ProxyHost{h}, nil, "", "80", "443", "/certs", "/acme")

	if !strings.Contains(config, "listen 443 ssl http2") {
		t.Error("expected HTTPS listen with http2")
	}
	if !strings.Contains(config, "return 301 https://$host$request_uri") {
		t.Error("expected HTTP to HTTPS redirect")
	}
	if !strings.Contains(config, "ssl_certificate") {
		t.Error("expected ssl_certificate directive")
	}
	if !strings.Contains(config, "ssl_protocols TLSv1.2 TLSv1.3") {
		t.Error("expected TLS protocol directives")
	}
	if !strings.Contains(config, "Strict-Transport-Security") {
		t.Error("expected HSTS header")
	}
}

func TestBuildConfig_SSLNonForceHTTPS(t *testing.T) {
	id := uuid.New()
	h := testHost(id)
	h.SSLMode = models.ProxySSLModeAuto
	h.SSLForceHTTPS = false

	config := BuildConfig([]*models.ProxyHost{h}, nil, "", "80", "443", "/certs", "/acme")

	// Should NOT have redirect block
	if strings.Contains(config, "return 301 https://") {
		t.Error("should not redirect when SSLForceHTTPS is false")
	}
	// Should listen on both HTTP and HTTPS
	if !strings.Contains(config, "listen 80;") {
		t.Error("expected HTTP listen on non-force SSL")
	}
	if !strings.Contains(config, "listen 443 ssl") {
		t.Error("expected HTTPS listen")
	}
	// Should have ACME challenge in main block
	if !strings.Contains(config, "acme-challenge") {
		t.Error("expected ACME challenge location in main block")
	}
}

func TestBuildConfig_WebSocket(t *testing.T) {
	id := uuid.New()
	h := testHost(id)
	h.EnableWebSocket = true

	config := BuildConfig([]*models.ProxyHost{h}, nil, "", "80", "443", "/certs", "/acme")

	if !strings.Contains(config, "proxy_http_version 1.1") {
		t.Error("expected WebSocket proxy_http_version")
	}
	if !strings.Contains(config, "Upgrade $http_upgrade") {
		t.Error("expected WebSocket Upgrade header")
	}
	if !strings.Contains(config, "$connection_upgrade") {
		t.Error("expected WebSocket Connection header")
	}
	if !strings.Contains(config, "proxy_read_timeout 86400s") {
		t.Error("expected WebSocket read timeout")
	}
}

func TestBuildConfig_Compression(t *testing.T) {
	id := uuid.New()
	h := testHost(id)
	h.EnableCompression = true

	config := BuildConfig([]*models.ProxyHost{h}, nil, "", "80", "443", "/certs", "/acme")

	if !strings.Contains(config, "gzip on") {
		t.Error("expected gzip on")
	}
	if !strings.Contains(config, "gzip_vary on") {
		t.Error("expected gzip_vary")
	}
	if !strings.Contains(config, "gzip_types") {
		t.Error("expected gzip_types")
	}
}

func TestBuildConfig_UpstreamPath(t *testing.T) {
	id := uuid.New()
	h := testHost(id)
	h.UpstreamPath = "/api/v1/"

	config := BuildConfig([]*models.ProxyHost{h}, nil, "", "80", "443", "/certs", "/acme")

	if !strings.Contains(config, "/api/v1;") {
		t.Error("expected upstream path with trailing slash trimmed")
	}
}

func TestBuildConfig_CustomHeadersRequest(t *testing.T) {
	id := uuid.New()
	h := testHost(id)
	h.CustomHeaders = []models.ProxyHeader{
		{Direction: "request", Operation: "set", Name: "X-Custom", Value: "test-val"},
		{Direction: "request", Operation: "delete", Name: "X-Remove"},
		{Direction: "response", Operation: "set", Name: "X-Frame-Options", Value: "DENY"},
		{Direction: "response", Operation: "delete", Name: "Server"},
	}

	config := BuildConfig([]*models.ProxyHost{h}, nil, "", "80", "443", "/certs", "/acme")

	if !strings.Contains(config, `proxy_set_header X-Custom "test-val"`) {
		t.Error("expected request set header")
	}
	if !strings.Contains(config, `proxy_set_header X-Remove ""`) {
		t.Error("expected request delete header")
	}
	if !strings.Contains(config, `add_header X-Frame-Options "DENY" always`) {
		t.Error("expected response set header")
	}
	if !strings.Contains(config, `proxy_hide_header Server`) {
		t.Error("expected response delete header")
	}
}

func TestBuildConfig_MultipleHosts(t *testing.T) {
	h1 := testHost(uuid.New())
	h2 := testHost(uuid.New())
	h2.Domains = []string{"api.example.com"}
	h2.UpstreamHost = "10.0.0.6"
	h2.UpstreamPort = 3000

	config := BuildConfig([]*models.ProxyHost{h1, h2}, nil, "", "80", "443", "/certs", "/acme")

	if !strings.Contains(config, "# Hosts: 2") {
		t.Error("expected host count 2")
	}
	if !strings.Contains(config, "server_name app.example.com") {
		t.Error("expected first host server_name")
	}
	if !strings.Contains(config, "server_name api.example.com") {
		t.Error("expected second host server_name")
	}
	if !strings.Contains(config, "10.0.0.5:8080") {
		t.Error("expected first upstream")
	}
	if !strings.Contains(config, "10.0.0.6:3000") {
		t.Error("expected second upstream")
	}
}

func TestBuildConfig_MultipleDomains(t *testing.T) {
	h := testHost(uuid.New())
	h.Domains = []string{"example.com", "www.example.com"}

	config := BuildConfig([]*models.ProxyHost{h}, nil, "", "80", "443", "/certs", "/acme")

	if !strings.Contains(config, "server_name example.com www.example.com") {
		t.Error("expected both domains in server_name")
	}
}

func TestUpstreamName(t *testing.T) {
	id := uuid.MustParse("12345678-1234-1234-1234-123456789abc")
	h := &models.ProxyHost{ID: id}
	name := upstreamName(h)
	if name != "usulnet_12345678" {
		t.Errorf("expected usulnet_12345678, got %s", name)
	}
}

func TestCertPaths_AutoSSL(t *testing.T) {
	h := &models.ProxyHost{
		Domains: []string{"example.com"},
		SSLMode: models.ProxySSLModeAuto,
	}
	certPath, keyPath := certPaths(h, nil, "/certs")
	if certPath != "/certs/live/example.com/fullchain.pem" {
		t.Errorf("unexpected cert path: %s", certPath)
	}
	if keyPath != "/certs/live/example.com/privkey.pem" {
		t.Errorf("unexpected key path: %s", keyPath)
	}
}

func TestCertPaths_CustomSSL(t *testing.T) {
	certID := uuid.New()
	h := &models.ProxyHost{
		Domains:       []string{"example.com"},
		SSLMode:       models.ProxySSLModeCustom,
		CertificateID: &certID,
	}
	certPath, keyPath := certPaths(h, nil, "/certs")
	expected := "/certs/custom/" + certID.String() + "/fullchain.pem"
	if certPath != expected {
		t.Errorf("expected %s, got %s", expected, certPath)
	}
	if !strings.Contains(keyPath, "privkey.pem") {
		t.Error("expected privkey.pem in key path")
	}
}

func TestCertPaths_InternalSSL(t *testing.T) {
	h := &models.ProxyHost{
		Domains: []string{"internal.local"},
		SSLMode: models.ProxySSLModeInternal,
	}
	certPath, keyPath := certPaths(h, nil, "/certs")
	if certPath != "/certs/internal/internal.local/fullchain.pem" {
		t.Errorf("unexpected cert path: %s", certPath)
	}
	if keyPath != "/certs/internal/internal.local/privkey.pem" {
		t.Errorf("unexpected key path: %s", keyPath)
	}
}

func TestCertPaths_CustomNoID_FallsBackToACME(t *testing.T) {
	h := &models.ProxyHost{
		Domains:       []string{"example.com"},
		SSLMode:       models.ProxySSLModeCustom,
		CertificateID: nil,
	}
	certPath, _ := certPaths(h, nil, "/certs")
	if !strings.Contains(certPath, "/live/") {
		t.Errorf("expected fallback to ACME paths when CertificateID is nil, got: %s", certPath)
	}
}

func TestBuildDefaultServer(t *testing.T) {
	s := buildDefaultServer("80", "443", "/certs")
	if !strings.Contains(s, "listen 80 default_server") {
		t.Error("expected HTTP default_server")
	}
	if !strings.Contains(s, "server_name _") {
		t.Error("expected catch-all server_name")
	}
	if !strings.Contains(s, "return 444") {
		t.Error("expected 444 return")
	}
}

func TestBuildConfig_HealthCheck(t *testing.T) {
	id := uuid.New()
	h := testHost(id)
	h.HealthCheckEnabled = true
	h.HealthCheckPath = "/healthz"

	config := BuildConfig([]*models.ProxyHost{h}, nil, "", "80", "443", "/certs", "/acme")

	if !strings.Contains(config, "# Health check path: /healthz") {
		t.Error("expected health check comment")
	}
}

func TestBuildConfig_UpstreamSchemeH2C(t *testing.T) {
	id := uuid.New()
	h := testHost(id)
	h.UpstreamScheme = "h2c"

	config := BuildConfig([]*models.ProxyHost{h}, nil, "", "80", "443", "/certs", "/acme")

	// h2c should be normalized to "http" for proxy_pass
	if !strings.Contains(config, "proxy_pass http://") {
		t.Error("expected h2c normalized to http in proxy_pass")
	}
}

func TestBuildConfig_ACMEChallenge_ForceHTTPS(t *testing.T) {
	id := uuid.New()
	h := testHost(id)
	h.SSLMode = models.ProxySSLModeAuto
	h.SSLForceHTTPS = true

	config := BuildConfig([]*models.ProxyHost{h}, nil, "", "80", "443", "/certs", "/var/acme")

	// The HTTP redirect block should still serve ACME challenges
	if !strings.Contains(config, "root /var/acme") {
		t.Error("expected ACME webroot in redirect block")
	}
}

func TestBuildConfig_StandardProxyHeaders(t *testing.T) {
	id := uuid.New()
	h := testHost(id)

	config := BuildConfig([]*models.ProxyHost{h}, nil, "", "80", "443", "/certs", "/acme")

	headers := []string{
		"proxy_set_header Host $host",
		"proxy_set_header X-Real-IP $remote_addr",
		"proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for",
		"proxy_set_header X-Forwarded-Proto $scheme",
		"proxy_set_header X-Forwarded-Host $host",
	}
	for _, h := range headers {
		if !strings.Contains(config, h) {
			t.Errorf("expected standard header: %s", h)
		}
	}
}
