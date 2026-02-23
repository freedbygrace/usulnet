// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package nginx generates nginx configuration from proxy host definitions
// and manages the nginx process lifecycle for the usulnet reverse proxy.
package nginx

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/fr4nsys/usulnet/internal/models"
)

// BuildInput holds everything needed to produce the http{} config.
type BuildInput struct {
	Hosts        []*models.ProxyHost
	Redirections []*models.ProxyRedirection
	DeadHosts    []*models.ProxyDeadHost
	AccessLists  []*models.ProxyAccessList
	CustomCerts  map[string]*models.ProxyCertificate
	ACMEEmail    string
	ListenHTTP   string
	ListenHTTPS  string
	CertDir      string
	ACMEWebRoot  string
	ACLDir       string // directory to write htpasswd files
}

// BuildConfig generates a complete nginx configuration for all proxy hosts,
// redirections, and dead hosts. Stream blocks are built separately via BuildStreamConfig.
func BuildConfig(hosts []*models.ProxyHost, customCerts map[string]*models.ProxyCertificate, acmeEmail, listenHTTP, listenHTTPS, certDir, acmeWebRoot string) string {
	return BuildConfigFull(&BuildInput{
		Hosts:       hosts,
		CustomCerts: customCerts,
		ACMEEmail:   acmeEmail,
		ListenHTTP:  listenHTTP,
		ListenHTTPS: listenHTTPS,
		CertDir:     certDir,
		ACMEWebRoot: acmeWebRoot,
	})
}

// BuildConfigFull generates a complete nginx configuration from the full input.
func BuildConfigFull(in *BuildInput) string {
	if in.ListenHTTP == "" {
		in.ListenHTTP = "80"
	}
	if in.ListenHTTPS == "" {
		in.ListenHTTPS = "443"
	}
	// Strip leading colon if present (e.g. ":80" → "80")
	in.ListenHTTP = strings.TrimPrefix(in.ListenHTTP, ":")
	in.ListenHTTPS = strings.TrimPrefix(in.ListenHTTPS, ":")

	// Build access list lookup
	aclMap := make(map[string]*models.ProxyAccessList)
	for _, al := range in.AccessLists {
		if al.Enabled {
			aclMap[al.ID.String()] = al
		}
	}

	var b strings.Builder

	b.WriteString("# Managed by usulnet — do not edit manually\n")
	b.WriteString(fmt.Sprintf("# Generated at: %s\n", time.Now().UTC().Format(time.RFC3339)))

	hostCount := len(in.Hosts)
	for _, h := range in.Hosts {
		if !h.Enabled {
			hostCount--
		}
	}
	b.WriteString(fmt.Sprintf("# Hosts: %d\n\n", hostCount))

	// Map: build unique upstreams
	for _, h := range in.Hosts {
		if !h.Enabled {
			continue
		}
		b.WriteString(buildUpstream(h))
		b.WriteByte('\n')
	}

	// Server blocks for proxy hosts
	for _, h := range in.Hosts {
		if !h.Enabled {
			continue
		}
		var acl *models.ProxyAccessList
		if h.AccessListID != nil {
			acl = aclMap[h.AccessListID.String()]
		}
		b.WriteString(buildServerBlock(h, in.CustomCerts, in.ListenHTTP, in.ListenHTTPS, in.CertDir, in.ACMEWebRoot, acl, in.ACLDir))
		b.WriteByte('\n')
	}

	// Redirection server blocks
	for _, rd := range in.Redirections {
		if !rd.Enabled {
			continue
		}
		b.WriteString(buildRedirectionBlock(rd, in.CustomCerts, in.ListenHTTP, in.ListenHTTPS, in.CertDir, in.ACMEWebRoot))
		b.WriteByte('\n')
	}

	// Dead host (404) server blocks
	for _, dh := range in.DeadHosts {
		if !dh.Enabled {
			continue
		}
		b.WriteString(buildDeadHostBlock(dh, in.CustomCerts, in.ListenHTTP, in.ListenHTTPS, in.CertDir, in.ACMEWebRoot))
		b.WriteByte('\n')
	}

	// Default server block — catch-all that returns 444 for unmatched requests
	b.WriteString(buildDefaultServer(in.ListenHTTP, in.ListenHTTPS, in.CertDir))

	return b.String()
}

// BuildStreamConfig generates the nginx stream{} configuration for TCP/UDP forwarding.
// This content should be included in a separate file that the main nginx.conf
// includes within a stream{} block.
func BuildStreamConfig(streams []*models.ProxyStream) string {
	var b strings.Builder
	b.WriteString("# Managed by usulnet — stream config\n")
	b.WriteString(fmt.Sprintf("# Generated at: %s\n\n", time.Now().UTC().Format(time.RFC3339)))

	for _, st := range streams {
		if !st.Enabled {
			continue
		}
		if st.TCPForwarding {
			b.WriteString(fmt.Sprintf("server {\n"))
			b.WriteString(fmt.Sprintf("    listen %d;\n", st.IncomingPort))
			b.WriteString(fmt.Sprintf("    listen [::]:%d;\n", st.IncomingPort))
			b.WriteString(fmt.Sprintf("    proxy_pass %s:%d;\n", st.ForwardingHost, st.ForwardingPort))
			b.WriteString(fmt.Sprintf("    proxy_connect_timeout 10s;\n"))
			b.WriteString(fmt.Sprintf("    proxy_timeout 300s;\n"))
			b.WriteString(fmt.Sprintf("}\n\n"))
		}
		if st.UDPForwarding {
			b.WriteString(fmt.Sprintf("server {\n"))
			b.WriteString(fmt.Sprintf("    listen %d udp;\n", st.IncomingPort))
			b.WriteString(fmt.Sprintf("    listen [::]:%d udp;\n", st.IncomingPort))
			b.WriteString(fmt.Sprintf("    proxy_pass %s:%d;\n", st.ForwardingHost, st.ForwardingPort))
			b.WriteString(fmt.Sprintf("    proxy_timeout 300s;\n"))
			b.WriteString(fmt.Sprintf("}\n\n"))
		}
	}

	return b.String()
}

func upstreamName(h *models.ProxyHost) string {
	return "usulnet_" + h.ID.String()[:8]
}

func buildUpstream(h *models.ProxyHost) string {
	var b strings.Builder
	name := upstreamName(h)
	b.WriteString(fmt.Sprintf("upstream %s {\n", name))
	b.WriteString(fmt.Sprintf("    server %s:%d;\n", h.UpstreamHost, h.UpstreamPort))

	if h.HealthCheckEnabled && h.HealthCheckPath != "" {
		// nginx plus has health checks; for open-source nginx, use passive checks
		b.WriteString("    # Health check path: " + h.HealthCheckPath + "\n")
	}

	b.WriteString("}\n")
	return b.String()
}

func buildServerBlock(h *models.ProxyHost, customCerts map[string]*models.ProxyCertificate, listenHTTP, listenHTTPS, certDir, acmeWebRoot string, acl *models.ProxyAccessList, aclDir string) string {
	hasSSL := h.SSLMode != models.ProxySSLModeNone
	domains := strings.Join(h.Domains, " ")

	var b strings.Builder

	// HTTP server block
	if hasSSL && h.SSLForceHTTPS {
		// HTTP → HTTPS redirect
		b.WriteString(fmt.Sprintf("server {\n"))
		b.WriteString(fmt.Sprintf("    listen %s;\n", listenHTTP))
		b.WriteString(fmt.Sprintf("    listen [::]:%s;\n", listenHTTP))
		b.WriteString(fmt.Sprintf("    server_name %s;\n\n", domains))
		// ACME challenge location (always serve, even during redirect)
		b.WriteString(fmt.Sprintf("    location /.well-known/acme-challenge/ {\n"))
		b.WriteString(fmt.Sprintf("        root %s;\n", acmeWebRoot))
		b.WriteString(fmt.Sprintf("    }\n\n"))
		b.WriteString(fmt.Sprintf("    location / {\n"))
		b.WriteString(fmt.Sprintf("        return 301 https://$host$request_uri;\n"))
		b.WriteString(fmt.Sprintf("    }\n"))
		b.WriteString(fmt.Sprintf("}\n\n"))
	}

	// Main server block (HTTPS or plain HTTP)
	b.WriteString("server {\n")

	if hasSSL {
		b.WriteString(fmt.Sprintf("    listen %s ssl", listenHTTPS))
		if h.EnableHTTP2 {
			b.WriteString(" http2")
		}
		b.WriteString(";\n")
		b.WriteString(fmt.Sprintf("    listen [::]:%s ssl", listenHTTPS))
		if h.EnableHTTP2 {
			b.WriteString(" http2")
		}
		b.WriteString(";\n")

		// Also listen on HTTP if not forcing redirect (to serve both)
		if !h.SSLForceHTTPS {
			b.WriteString(fmt.Sprintf("    listen %s;\n", listenHTTP))
			b.WriteString(fmt.Sprintf("    listen [::]:%s;\n", listenHTTP))
		}
	} else {
		b.WriteString(fmt.Sprintf("    listen %s;\n", listenHTTP))
		b.WriteString(fmt.Sprintf("    listen [::]:%s;\n", listenHTTP))
	}

	b.WriteString(fmt.Sprintf("    server_name %s;\n\n", domains))

	// SSL configuration
	if hasSSL {
		certPath, keyPath := certPaths(h, customCerts, certDir)
		b.WriteString(fmt.Sprintf("    ssl_certificate %s;\n", certPath))
		b.WriteString(fmt.Sprintf("    ssl_certificate_key %s;\n", keyPath))
		b.WriteString("    ssl_protocols TLSv1.2 TLSv1.3;\n")
		b.WriteString("    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;\n")
		b.WriteString("    ssl_prefer_server_ciphers on;\n")
		b.WriteString("    ssl_session_cache shared:SSL:10m;\n")
		b.WriteString("    ssl_session_timeout 10m;\n\n")
	}

	// HSTS
	if h.EnableHSTS && hasSSL {
		if h.HSTSSubdomains {
			b.WriteString("    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n\n")
		} else {
			b.WriteString("    add_header Strict-Transport-Security \"max-age=31536000\" always;\n\n")
		}
	}

	// Compression
	if h.EnableCompression {
		b.WriteString("    gzip on;\n")
		b.WriteString("    gzip_vary on;\n")
		b.WriteString("    gzip_proxied any;\n")
		b.WriteString("    gzip_comp_level 6;\n")
		b.WriteString("    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript image/svg+xml;\n\n")
	}

	// Block common exploits
	if h.BlockExploits {
		b.WriteString(blockExploitsSnippet())
	}

	// Asset caching
	if h.CachingEnabled {
		b.WriteString(cachingSnippet())
	}

	// Access list (HTTP basic auth + IP allow/deny)
	if acl != nil {
		b.WriteString(accessListSnippet(acl, aclDir))
	}

	// ACME challenge (in case SSL block serves HTTP too)
	if hasSSL && !h.SSLForceHTTPS {
		b.WriteString(fmt.Sprintf("    location /.well-known/acme-challenge/ {\n"))
		b.WriteString(fmt.Sprintf("        root %s;\n", acmeWebRoot))
		b.WriteString(fmt.Sprintf("    }\n\n"))
	}

	// Custom locations (path-specific upstreams)
	for _, loc := range h.Locations {
		if !loc.Enabled {
			continue
		}
		scheme := loc.UpstreamScheme
		if scheme == "" || scheme == "h2c" {
			scheme = "http"
		}
		b.WriteString(fmt.Sprintf("    location %s {\n", loc.Path))
		b.WriteString(fmt.Sprintf("        proxy_pass %s://%s:%d;\n", scheme, loc.UpstreamHost, loc.UpstreamPort))
		b.WriteString("        proxy_set_header Host $host;\n")
		b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
		b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
		b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
		if h.EnableWebSocket {
			b.WriteString("        proxy_http_version 1.1;\n")
			b.WriteString("        proxy_set_header Upgrade $http_upgrade;\n")
			b.WriteString("        proxy_set_header Connection $connection_upgrade;\n")
		}
		b.WriteString("    }\n\n")
	}

	// Default proxy location
	upName := upstreamName(h)
	proxyScheme := string(h.UpstreamScheme)
	if proxyScheme == "" || proxyScheme == "h2c" {
		proxyScheme = "http"
	}

	b.WriteString("    location / {\n")
	b.WriteString(fmt.Sprintf("        proxy_pass %s://%s", proxyScheme, upName))
	if h.UpstreamPath != "" {
		b.WriteString(strings.TrimRight(h.UpstreamPath, "/"))
	}
	b.WriteString(";\n")

	// Standard proxy headers
	b.WriteString("        proxy_set_header Host $host;\n")
	b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
	b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
	b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
	b.WriteString("        proxy_set_header X-Forwarded-Host $host;\n")

	// WebSocket support
	if h.EnableWebSocket {
		b.WriteString("\n        # WebSocket support\n")
		b.WriteString("        proxy_http_version 1.1;\n")
		b.WriteString("        proxy_set_header Upgrade $http_upgrade;\n")
		b.WriteString("        proxy_set_header Connection $connection_upgrade;\n")
		b.WriteString("        proxy_read_timeout 86400s;\n")
		b.WriteString("        proxy_send_timeout 86400s;\n")
	}

	// Custom headers
	for _, ch := range h.CustomHeaders {
		switch ch.Direction {
		case "request":
			switch ch.Operation {
			case "set":
				b.WriteString(fmt.Sprintf("        proxy_set_header %s %q;\n", ch.Name, ch.Value))
			case "add":
				b.WriteString(fmt.Sprintf("        proxy_set_header %s %q;\n", ch.Name, ch.Value))
			case "delete":
				b.WriteString(fmt.Sprintf("        proxy_set_header %s \"\";\n", ch.Name))
			}
		case "response":
			switch ch.Operation {
			case "set":
				b.WriteString(fmt.Sprintf("        add_header %s %q always;\n", ch.Name, ch.Value))
			case "add":
				b.WriteString(fmt.Sprintf("        add_header %s %q;\n", ch.Name, ch.Value))
			case "delete":
				b.WriteString(fmt.Sprintf("        proxy_hide_header %s;\n", ch.Name))
			}
		}
	}

	b.WriteString("    }\n")

	// Custom nginx configuration (injected at the end of the server block)
	if h.CustomNginxConfig != "" {
		b.WriteString("\n    # Custom configuration\n")
		for _, line := range strings.Split(h.CustomNginxConfig, "\n") {
			trimmed := strings.TrimRight(line, " \t\r")
			if trimmed == "" {
				b.WriteString("\n")
			} else {
				b.WriteString("    " + trimmed + "\n")
			}
		}
	}

	b.WriteString("}\n")

	return b.String()
}

// buildRedirectionBlock generates a server block for a redirection host.
func buildRedirectionBlock(rd *models.ProxyRedirection, customCerts map[string]*models.ProxyCertificate, listenHTTP, listenHTTPS, certDir, acmeWebRoot string) string {
	hasSSL := rd.SSLMode != models.ProxySSLModeNone
	domains := strings.Join(rd.Domains, " ")

	var b strings.Builder

	// HTTP → HTTPS redirect block (if SSL + force)
	if hasSSL && rd.SSLForceHTTPS {
		b.WriteString("server {\n")
		b.WriteString(fmt.Sprintf("    listen %s;\n", listenHTTP))
		b.WriteString(fmt.Sprintf("    listen [::]:%s;\n", listenHTTP))
		b.WriteString(fmt.Sprintf("    server_name %s;\n\n", domains))
		b.WriteString(fmt.Sprintf("    location /.well-known/acme-challenge/ {\n"))
		b.WriteString(fmt.Sprintf("        root %s;\n", acmeWebRoot))
		b.WriteString("    }\n\n")
		b.WriteString("    location / {\n")
		b.WriteString("        return 301 https://$host$request_uri;\n")
		b.WriteString("    }\n")
		b.WriteString("}\n\n")
	}

	// Main redirection server block
	b.WriteString("server {\n")
	if hasSSL {
		b.WriteString(fmt.Sprintf("    listen %s ssl;\n", listenHTTPS))
		b.WriteString(fmt.Sprintf("    listen [::]:%s ssl;\n", listenHTTPS))
		if !rd.SSLForceHTTPS {
			b.WriteString(fmt.Sprintf("    listen %s;\n", listenHTTP))
			b.WriteString(fmt.Sprintf("    listen [::]:%s;\n", listenHTTP))
		}
	} else {
		b.WriteString(fmt.Sprintf("    listen %s;\n", listenHTTP))
		b.WriteString(fmt.Sprintf("    listen [::]:%s;\n", listenHTTP))
	}
	b.WriteString(fmt.Sprintf("    server_name %s;\n\n", domains))

	// SSL configuration
	if hasSSL {
		certPath, keyPath := redirectionCertPaths(rd, customCerts, certDir)
		b.WriteString(fmt.Sprintf("    ssl_certificate %s;\n", certPath))
		b.WriteString(fmt.Sprintf("    ssl_certificate_key %s;\n", keyPath))
		b.WriteString("    ssl_protocols TLSv1.2 TLSv1.3;\n\n")
	}

	// Build return directive
	target := fmt.Sprintf("%s://%s", rd.ForwardScheme, rd.ForwardDomain)
	if rd.PreservePath {
		target += "$request_uri"
	}
	b.WriteString("    location / {\n")
	b.WriteString(fmt.Sprintf("        return %d %s;\n", rd.ForwardHTTPCode, target))
	b.WriteString("    }\n")
	b.WriteString("}\n")

	return b.String()
}

// buildDeadHostBlock generates a server block for a dead host (404 catch-all).
func buildDeadHostBlock(dh *models.ProxyDeadHost, customCerts map[string]*models.ProxyCertificate, listenHTTP, listenHTTPS, certDir, acmeWebRoot string) string {
	hasSSL := dh.SSLMode != models.ProxySSLModeNone
	domains := strings.Join(dh.Domains, " ")

	var b strings.Builder

	// HTTP → HTTPS redirect block (if SSL + force)
	if hasSSL && dh.SSLForceHTTPS {
		b.WriteString("server {\n")
		b.WriteString(fmt.Sprintf("    listen %s;\n", listenHTTP))
		b.WriteString(fmt.Sprintf("    listen [::]:%s;\n", listenHTTP))
		b.WriteString(fmt.Sprintf("    server_name %s;\n\n", domains))
		b.WriteString(fmt.Sprintf("    location /.well-known/acme-challenge/ {\n"))
		b.WriteString(fmt.Sprintf("        root %s;\n", acmeWebRoot))
		b.WriteString("    }\n\n")
		b.WriteString("    location / {\n")
		b.WriteString("        return 301 https://$host$request_uri;\n")
		b.WriteString("    }\n")
		b.WriteString("}\n\n")
	}

	// Main dead host server block
	b.WriteString("server {\n")
	if hasSSL {
		b.WriteString(fmt.Sprintf("    listen %s ssl;\n", listenHTTPS))
		b.WriteString(fmt.Sprintf("    listen [::]:%s ssl;\n", listenHTTPS))
		if !dh.SSLForceHTTPS {
			b.WriteString(fmt.Sprintf("    listen %s;\n", listenHTTP))
			b.WriteString(fmt.Sprintf("    listen [::]:%s;\n", listenHTTP))
		}
	} else {
		b.WriteString(fmt.Sprintf("    listen %s;\n", listenHTTP))
		b.WriteString(fmt.Sprintf("    listen [::]:%s;\n", listenHTTP))
	}
	b.WriteString(fmt.Sprintf("    server_name %s;\n\n", domains))

	// SSL configuration
	if hasSSL {
		certPath, keyPath := deadHostCertPaths(dh, customCerts, certDir)
		b.WriteString(fmt.Sprintf("    ssl_certificate %s;\n", certPath))
		b.WriteString(fmt.Sprintf("    ssl_certificate_key %s;\n", keyPath))
		b.WriteString("    ssl_protocols TLSv1.2 TLSv1.3;\n\n")
	}

	b.WriteString("    location / {\n")
	b.WriteString("        return 404;\n")
	b.WriteString("    }\n")
	b.WriteString("}\n")

	return b.String()
}

// ============================================================================
// Snippets
// ============================================================================

// blockExploitsSnippet returns nginx config directives to block common exploits.
func blockExploitsSnippet() string {
	return `    # Block common exploits
    location ~* "(eval\()" { deny all; }
    location ~* "\.(aspx|asp|cgi)" { deny all; }
    location ~* "(~|\.bak|\.old|\.orig|\.save|\.swp|\.dist|\.tmp)" { deny all; }
    location ~ /\.ht { deny all; }
    location ~ /\.git { deny all; }
    location ~ /\.svn { deny all; }
    location ~ /\.env { deny all; }
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;

`
}

// cachingSnippet returns nginx config directives for static asset caching.
func cachingSnippet() string {
	return `    # Static asset caching
    location ~* \.(jpg|jpeg|png|gif|ico|svg|webp|avif)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
        proxy_pass http://$proxy_upstream;
    }
    location ~* \.(css|js|woff|woff2|ttf|eot)$ {
        expires 7d;
        add_header Cache-Control "public";
        proxy_pass http://$proxy_upstream;
    }

`
}

// accessListSnippet returns nginx config directives for an access list.
func accessListSnippet(acl *models.ProxyAccessList, aclDir string) string {
	var b strings.Builder

	if acl.SatisfyAny {
		b.WriteString("    satisfy any;\n")
	}

	// HTTP basic auth
	if len(acl.Items) > 0 {
		htpasswdPath := filepath.Join(aclDir, acl.ID.String()+".htpasswd")
		b.WriteString(fmt.Sprintf("    auth_basic \"Restricted\";\n"))
		b.WriteString(fmt.Sprintf("    auth_basic_user_file %s;\n", htpasswdPath))
		if acl.PassAuth {
			b.WriteString("    proxy_set_header Authorization $http_authorization;\n")
		}
	}

	// IP allow/deny
	for _, client := range acl.Clients {
		b.WriteString(fmt.Sprintf("    %s %s;\n", client.Directive, client.Address))
	}
	if len(acl.Clients) > 0 {
		b.WriteString("    deny all;\n")
	}

	b.WriteString("\n")
	return b.String()
}

// ============================================================================
// Certificate path helpers
// ============================================================================

// certPaths resolves the SSL certificate and key file paths for a host.
func certPaths(h *models.ProxyHost, customCerts map[string]*models.ProxyCertificate, certDir string) (certPath, keyPath string) {
	primaryDomain := h.Domains[0]

	switch h.SSLMode {
	case models.ProxySSLModeCustom:
		if h.CertificateID != nil {
			certPath = filepath.Join(certDir, "custom", h.CertificateID.String(), "fullchain.pem")
			keyPath = filepath.Join(certDir, "custom", h.CertificateID.String(), "privkey.pem")
			return
		}
	case models.ProxySSLModeInternal:
		certPath = filepath.Join(certDir, "internal", primaryDomain, "fullchain.pem")
		keyPath = filepath.Join(certDir, "internal", primaryDomain, "privkey.pem")
		return
	}

	// Default: ACME (Let's Encrypt) — auto or dns mode
	certPath = filepath.Join(certDir, "live", primaryDomain, "fullchain.pem")
	keyPath = filepath.Join(certDir, "live", primaryDomain, "privkey.pem")
	return
}

// redirectionCertPaths resolves cert paths for a redirection host.
func redirectionCertPaths(rd *models.ProxyRedirection, customCerts map[string]*models.ProxyCertificate, certDir string) (certPath, keyPath string) {
	primaryDomain := rd.Domains[0]

	if rd.SSLMode == models.ProxySSLModeCustom && rd.CertificateID != nil {
		certPath = filepath.Join(certDir, "custom", rd.CertificateID.String(), "fullchain.pem")
		keyPath = filepath.Join(certDir, "custom", rd.CertificateID.String(), "privkey.pem")
		return
	}

	certPath = filepath.Join(certDir, "live", primaryDomain, "fullchain.pem")
	keyPath = filepath.Join(certDir, "live", primaryDomain, "privkey.pem")
	return
}

// deadHostCertPaths resolves cert paths for a dead host.
func deadHostCertPaths(dh *models.ProxyDeadHost, customCerts map[string]*models.ProxyCertificate, certDir string) (certPath, keyPath string) {
	primaryDomain := dh.Domains[0]

	if dh.SSLMode == models.ProxySSLModeCustom && dh.CertificateID != nil {
		certPath = filepath.Join(certDir, "custom", dh.CertificateID.String(), "fullchain.pem")
		keyPath = filepath.Join(certDir, "custom", dh.CertificateID.String(), "privkey.pem")
		return
	}

	certPath = filepath.Join(certDir, "live", primaryDomain, "fullchain.pem")
	keyPath = filepath.Join(certDir, "live", primaryDomain, "privkey.pem")
	return
}

func buildDefaultServer(listenHTTP, listenHTTPS, certDir string) string {
	var b strings.Builder
	b.WriteString("# Default server — reject unmatched requests\n")
	b.WriteString("server {\n")
	b.WriteString(fmt.Sprintf("    listen %s default_server;\n", listenHTTP))
	b.WriteString(fmt.Sprintf("    listen [::]:%s default_server;\n", listenHTTP))
	b.WriteString("    server_name _;\n")
	b.WriteString("    return 444;\n")
	b.WriteString("}\n")
	return b.String()
}

// GenerateHtpasswd generates an htpasswd file content from access list auth items.
func GenerateHtpasswd(items []models.ProxyAccessListAuth) string {
	var b strings.Builder
	for _, item := range items {
		b.WriteString(fmt.Sprintf("%s:%s\n", item.Username, item.PasswordHash))
	}
	return b.String()
}
