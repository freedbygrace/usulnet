// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package nginx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tempConfig(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	return Config{
		ConfigDir:      filepath.Join(dir, "conf.d"),
		CertDir:        filepath.Join(dir, "certs"),
		ACMEWebRoot:    filepath.Join(dir, "acme"),
		ACMEAccountDir: filepath.Join(dir, "acme", "account"),
	}
}

func TestNewClient_DefaultBin(t *testing.T) {
	cfg := Config{}
	c := NewClient(cfg)
	if c.bin == "" {
		t.Error("expected non-empty binary path")
	}
}

func TestNewClient_CustomBin(t *testing.T) {
	cfg := Config{NginxBin: "/custom/nginx"}
	c := NewClient(cfg)
	if c.bin != "/custom/nginx" {
		t.Errorf("expected /custom/nginx, got %s", c.bin)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ConfigDir == "" {
		t.Error("expected non-empty ConfigDir")
	}
	if cfg.CertDir == "" {
		t.Error("expected non-empty CertDir")
	}
	if cfg.ACMEWebRoot == "" {
		t.Error("expected non-empty ACMEWebRoot")
	}
	if cfg.ACMEAccountDir == "" {
		t.Error("expected non-empty ACMEAccountDir")
	}
}

func TestWriteConfig(t *testing.T) {
	cfg := tempConfig(t)
	c := NewClient(cfg)

	content := "server { listen 80; }"
	if err := c.WriteConfig(content); err != nil {
		t.Fatalf("WriteConfig failed: %v", err)
	}

	configPath := filepath.Join(cfg.ConfigDir, "usulnet-proxy.conf")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read config file: %v", err)
	}
	if string(data) != content {
		t.Errorf("expected %q, got %q", content, string(data))
	}
}

func TestWriteConfig_CreatesDir(t *testing.T) {
	cfg := tempConfig(t)
	c := NewClient(cfg)

	if err := c.WriteConfig("test"); err != nil {
		t.Fatalf("WriteConfig should create directory: %v", err)
	}

	info, err := os.Stat(cfg.ConfigDir)
	if err != nil {
		t.Fatalf("config dir should exist: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory")
	}
}

func TestEnsureDirectories(t *testing.T) {
	cfg := tempConfig(t)
	c := NewClient(cfg)

	if err := c.EnsureDirectories(); err != nil {
		t.Fatalf("EnsureDirectories failed: %v", err)
	}

	dirs := []string{
		cfg.ConfigDir,
		cfg.CertDir,
		cfg.ACMEWebRoot,
		filepath.Join(cfg.ACMEWebRoot, ".well-known", "acme-challenge"),
		cfg.ACMEAccountDir,
	}
	for _, d := range dirs {
		info, err := os.Stat(d)
		if err != nil {
			t.Errorf("directory %s should exist: %v", d, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("%s should be a directory", d)
		}
	}
}

func TestWriteCertificate(t *testing.T) {
	cfg := tempConfig(t)
	c := NewClient(cfg)

	cert := []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
	key := []byte("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----")

	if err := c.WriteCertificate("live", "example.com", cert, key); err != nil {
		t.Fatalf("WriteCertificate failed: %v", err)
	}

	certPath := filepath.Join(cfg.CertDir, "live", "example.com", "fullchain.pem")
	keyPath := filepath.Join(cfg.CertDir, "live", "example.com", "privkey.pem")

	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}
	if string(data) != string(cert) {
		t.Error("cert content mismatch")
	}

	data, err = os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("failed to read key: %v", err)
	}
	if string(data) != string(key) {
		t.Error("key content mismatch")
	}

	// Verify key file permissions are restricted
	info, _ := os.Stat(keyPath)
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected key file permissions 0600, got %o", info.Mode().Perm())
	}
}

func TestWriteCustomCertificate(t *testing.T) {
	cfg := tempConfig(t)
	c := NewClient(cfg)

	cert := []byte("cert-pem")
	key := []byte("key-pem")
	chain := []byte("chain-pem")

	if err := c.WriteCustomCertificate("cert-123", cert, key, chain); err != nil {
		t.Fatalf("WriteCustomCertificate failed: %v", err)
	}

	certPath := filepath.Join(cfg.CertDir, "custom", "cert-123", "fullchain.pem")
	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read custom cert: %v", err)
	}
	// Should be cert + newline + chain
	if !strings.Contains(string(data), "cert-pem") {
		t.Error("expected cert PEM in fullchain")
	}
	if !strings.Contains(string(data), "chain-pem") {
		t.Error("expected chain PEM in fullchain")
	}
}

func TestWriteCustomCertificate_NoChain(t *testing.T) {
	cfg := tempConfig(t)
	c := NewClient(cfg)

	cert := []byte("cert-pem")
	key := []byte("key-pem")

	if err := c.WriteCustomCertificate("cert-456", cert, key, nil); err != nil {
		t.Fatalf("WriteCustomCertificate failed: %v", err)
	}

	certPath := filepath.Join(cfg.CertDir, "custom", "cert-456", "fullchain.pem")
	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}
	if string(data) != "cert-pem" {
		t.Errorf("expected just cert-pem, got %q", string(data))
	}
}

func TestWriteWebSocketUpgradeMap(t *testing.T) {
	cfg := tempConfig(t)
	c := NewClient(cfg)

	// Need to create config dir first
	os.MkdirAll(cfg.ConfigDir, 0755)

	if err := c.WriteWebSocketUpgradeMap(); err != nil {
		t.Fatalf("WriteWebSocketUpgradeMap failed: %v", err)
	}

	mapPath := filepath.Join(cfg.ConfigDir, "usulnet-websocket-map.conf")
	data, err := os.ReadFile(mapPath)
	if err != nil {
		t.Fatalf("failed to read websocket map: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "$http_upgrade") {
		t.Error("expected $http_upgrade in map")
	}
	if !strings.Contains(content, "$connection_upgrade") {
		t.Error("expected $connection_upgrade in map")
	}
	if !strings.Contains(content, "default upgrade") {
		t.Error("expected default upgrade")
	}
}

func TestFindNginxBinary(t *testing.T) {
	// This test verifies the function doesn't panic and returns something
	result := findNginxBinary()
	if result == "" {
		t.Error("expected non-empty result from findNginxBinary")
	}
}
