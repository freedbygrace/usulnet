// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package nginx

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/fr4nsys/usulnet/internal/models"
	proxy "github.com/fr4nsys/usulnet/internal/services/proxy"
)

// Backend implements proxy.SyncBackend for nginx.
// It generates nginx configuration files, writes them to disk,
// validates the config, and reloads the nginx process.
type Backend struct {
	client *Client
	acme   *ACMEClient
}

// NewBackend creates an nginx SyncBackend.
func NewBackend(cfg Config) *Backend {
	client := NewClient(cfg)
	acmeClient := NewACMEClient(cfg.ACMEAccountDir, cfg.ACMEWebRoot, false)

	// Ensure all directories exist
	if err := client.EnsureDirectories(); err != nil {
		slog.Error("nginx: failed to create directories", "error", err)
	}

	// Write the WebSocket upgrade map
	if err := client.WriteWebSocketUpgradeMap(); err != nil {
		slog.Error("nginx: failed to write websocket map", "error", err)
	}

	return &Backend{
		client: client,
		acme:   acmeClient,
	}
}

// SetDockerExecer configures the backend to execute nginx commands (test, reload)
// inside a Docker container via the Docker API instead of local shell execution.
func (b *Backend) SetDockerExecer(d DockerExecer) {
	b.client.SetDockerExecer(d)
}

func (b *Backend) Sync(ctx context.Context, data *proxy.SyncData) error {
	// Write custom certificates to disk (nginx reads them from files)
	for id, cert := range data.CustomCerts {
		if cert.CertPEM == "" {
			continue
		}
		var chain []byte
		if cert.ChainPEM != "" {
			chain = []byte(cert.ChainPEM)
		}
		if err := b.client.WriteCustomCertificate(id, []byte(cert.CertPEM), []byte(cert.KeyPEM), chain); err != nil {
			slog.Error("nginx: failed to write custom certificate", "cert_id", id, "error", err)
		}
	}

	// Write htpasswd files for access lists
	aclDir := filepath.Join(b.client.cfg.ConfigDir, "acl")
	for _, al := range data.AccessLists {
		if !al.Enabled || len(al.Items) == 0 {
			continue
		}
		content := GenerateHtpasswd(al.Items)
		if err := b.client.WriteFile(filepath.Join(aclDir, al.ID.String()+".htpasswd"), []byte(content)); err != nil {
			slog.Error("nginx: failed to write htpasswd", "acl_id", al.ID, "error", err)
		}
	}

	// Build nginx http{} configuration
	config := BuildConfigFull(&BuildInput{
		Hosts:        data.Hosts,
		Redirections: data.Redirections,
		DeadHosts:    data.DeadHosts,
		AccessLists:  data.AccessLists,
		CustomCerts:  data.CustomCerts,
		ACMEEmail:    data.ACMEEmail,
		ListenHTTP:   data.ListenHTTP,
		ListenHTTPS:  data.ListenHTTPS,
		CertDir:      b.client.cfg.CertDir,
		ACMEWebRoot:  b.client.cfg.ACMEWebRoot,
		ACLDir:       aclDir,
	})

	// Write config, validate, and reload nginx
	if err := b.client.WriteAndReload(ctx, config); err != nil {
		return fmt.Errorf("nginx sync: %w", err)
	}

	// Build and write stream config if there are any streams
	if len(data.Streams) > 0 {
		streamConfig := BuildStreamConfig(data.Streams)
		if err := b.client.WriteStreamConfig(streamConfig); err != nil {
			slog.Error("nginx: failed to write stream config", "error", err)
		}
	}

	slog.Info("nginx: proxy configuration synced", "host_count", len(data.Hosts))
	return nil
}

func (b *Backend) Healthy(ctx context.Context) (bool, error) {
	return b.client.Healthy(ctx)
}

func (b *Backend) Mode() string {
	return "nginx"
}

// RequestCertificate obtains a Let's Encrypt certificate.
// If dnsProvider is non-nil or any domain is a wildcard, DNS-01 challenge is used.
// Otherwise HTTP-01 is used. The certificate is written to disk for nginx.
func (b *Backend) RequestCertificate(ctx context.Context, domains []string, email string, dnsProvider *models.ProxyDNSProvider) (certPEM, keyPEM string, err error) {
	useDNS01 := dnsProvider != nil
	if !useDNS01 {
		for _, d := range domains {
			if strings.HasPrefix(d, "*.") {
				useDNS01 = true
				break
			}
		}
	}

	if useDNS01 {
		if dnsProvider == nil {
			return "", "", fmt.Errorf("DNS provider required for wildcard certificate")
		}
		dnsCfg := &DNSProviderConfig{
			Provider:    dnsProvider.Provider,
			APIToken:    dnsProvider.APIToken,
			Zone:        dnsProvider.Zone,
			Propagation: dnsProvider.Propagation,
		}
		certPEM, keyPEM, err = b.acme.RequestCertificateDNS01(ctx, domains, email, dnsCfg)
	} else {
		certPEM, keyPEM, err = b.acme.RequestCertificate(ctx, domains, email)
	}

	if err != nil {
		return "", "", err
	}

	// Write certificate files for nginx
	primaryDomain := domains[0]
	if err := b.client.WriteCertificate("live", primaryDomain, []byte(certPEM), []byte(keyPEM)); err != nil {
		return "", "", fmt.Errorf("write certificate: %w", err)
	}

	slog.Info("nginx: certificate obtained and written", "domains", domains, "dns01", useDNS01)
	return certPEM, keyPEM, nil
}

// RenewCertificate renews a certificate — same as requesting a new one.
func (b *Backend) RenewCertificate(ctx context.Context, domains []string, email string, dnsProvider *models.ProxyDNSProvider) (certPEM, keyPEM string, err error) {
	return b.RequestCertificate(ctx, domains, email, dnsProvider)
}
