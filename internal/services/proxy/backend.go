// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package proxy

import (
	"context"

	"github.com/fr4nsys/usulnet/internal/models"
)

// SyncBackend abstracts the reverse proxy configuration backend (nginx).
// The proxy service loads all configuration from the database, then delegates
// the config build + push/reload to the backend.
type SyncBackend interface {
	// Sync builds the proxy configuration from the provided data and
	// pushes it to the running backend (nginx config write + reload).
	Sync(ctx context.Context, data *SyncData) error

	// Healthy checks if the backend process is running and reachable.
	Healthy(ctx context.Context) (bool, error)

	// Mode returns the backend identifier ("nginx").
	Mode() string

	// RequestCertificate requests a Let's Encrypt certificate for the given domains.
	// If dnsProvider is non-nil, DNS-01 challenge is used (required for wildcards).
	// Otherwise, HTTP-01 challenge is used.
	// Returns the PEM-encoded certificate chain and private key.
	RequestCertificate(ctx context.Context, domains []string, email string, dnsProvider *models.ProxyDNSProvider) (certPEM, keyPEM string, err error)

	// RenewCertificate renews an existing certificate.
	// If dnsProvider is non-nil, DNS-01 challenge is used.
	RenewCertificate(ctx context.Context, domains []string, email string, dnsProvider *models.ProxyDNSProvider) (certPEM, keyPEM string, err error)
}

// SyncData holds all the data needed to build a proxy configuration.
// The proxy service populates this from the database; backends consume it
// to generate their native configuration format.
type SyncData struct {
	Hosts        []*models.ProxyHost
	Redirections []*models.ProxyRedirection
	Streams      []*models.ProxyStream
	DeadHosts    []*models.ProxyDeadHost
	AccessLists  []*models.ProxyAccessList
	DNSProviders map[string]*models.ProxyDNSProvider
	CustomCerts  map[string]*models.ProxyCertificate
	ACMEEmail    string
	ListenHTTP   string
	ListenHTTPS  string
}
