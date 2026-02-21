// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package agent

import (
	"testing"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// DefaultConfig Tests
// ============================================================================

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	// AgentID should be a non-empty UUID
	if cfg.AgentID == "" {
		t.Error("expected non-empty AgentID (generated UUID)")
	}
	// UUID v4 format: 8-4-4-4-12 hex chars = 36 chars total
	if len(cfg.AgentID) != 36 {
		t.Errorf("expected UUID-length AgentID (36 chars), got %d: %q", len(cfg.AgentID), cfg.AgentID)
	}

	if cfg.GatewayURL != "nats://localhost:4222" {
		t.Errorf("expected GatewayURL 'nats://localhost:4222', got %q", cfg.GatewayURL)
	}

	expectedDockerHost := "unix://" + docker.LocalSocketPath()
	if cfg.DockerHost != expectedDockerHost {
		t.Errorf("expected DockerHost %q, got %q", expectedDockerHost, cfg.DockerHost)
	}

	// Hostname should be non-empty (os.Hostname may fail, but usually doesn't)
	// We don't assert a specific value since it varies by environment.

	if cfg.Labels == nil {
		t.Error("expected non-nil Labels map")
	}
	if len(cfg.Labels) != 0 {
		t.Errorf("expected empty Labels map, got %v", cfg.Labels)
	}

	if cfg.LogLevel != "info" {
		t.Errorf("expected LogLevel 'info', got %q", cfg.LogLevel)
	}

	if cfg.DataDir != "/var/lib/usulnet-agent" {
		t.Errorf("expected DataDir '/var/lib/usulnet-agent', got %q", cfg.DataDir)
	}

	// Boolean defaults
	if cfg.BackupEnabled {
		t.Error("expected BackupEnabled false by default")
	}
	if cfg.ScannerEnabled {
		t.Error("expected ScannerEnabled false by default")
	}
	if cfg.TLSEnabled {
		t.Error("expected TLSEnabled false by default")
	}

	// String defaults that should be empty
	if cfg.Token != "" {
		t.Errorf("expected empty Token, got %q", cfg.Token)
	}
	if cfg.TLSCertFile != "" {
		t.Errorf("expected empty TLSCertFile, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected empty TLSKeyFile, got %q", cfg.TLSKeyFile)
	}
	if cfg.TLSCAFile != "" {
		t.Errorf("expected empty TLSCAFile, got %q", cfg.TLSCAFile)
	}
}

func TestDefaultConfigUniqueIDs(t *testing.T) {
	cfg1 := DefaultConfig()
	cfg2 := DefaultConfig()

	if cfg1.AgentID == cfg2.AgentID {
		t.Errorf("expected unique AgentIDs, both got %q", cfg1.AgentID)
	}
}

// ============================================================================
// Config Struct Tests
// ============================================================================

func TestConfigFields(t *testing.T) {
	cfg := Config{
		AgentID:        "agent-abc",
		Token:          "secret",
		GatewayURL:     "nats://10.0.0.1:4222",
		DockerHost:     "tcp://localhost:2375",
		Hostname:       "worker-1",
		Labels:         map[string]string{"env": "prod", "zone": "us-east"},
		LogLevel:       "debug",
		DataDir:        "/opt/agent/data",
		BackupEnabled:  true,
		ScannerEnabled: true,
		TLSEnabled:     true,
		TLSCertFile:    "/certs/tls.pem",
		TLSKeyFile:     "/certs/tls-key.pem",
		TLSCAFile:      "/certs/ca.pem",
	}

	if cfg.AgentID != "agent-abc" {
		t.Errorf("unexpected AgentID: %q", cfg.AgentID)
	}
	if cfg.Token != "secret" {
		t.Errorf("unexpected Token: %q", cfg.Token)
	}
	if cfg.GatewayURL != "nats://10.0.0.1:4222" {
		t.Errorf("unexpected GatewayURL: %q", cfg.GatewayURL)
	}
	if cfg.DockerHost != "tcp://localhost:2375" {
		t.Errorf("unexpected DockerHost: %q", cfg.DockerHost)
	}
	if cfg.Hostname != "worker-1" {
		t.Errorf("unexpected Hostname: %q", cfg.Hostname)
	}
	if len(cfg.Labels) != 2 {
		t.Errorf("expected 2 labels, got %d", len(cfg.Labels))
	}
	if cfg.Labels["env"] != "prod" {
		t.Errorf("expected label env=prod, got %q", cfg.Labels["env"])
	}
	if cfg.Labels["zone"] != "us-east" {
		t.Errorf("expected label zone=us-east, got %q", cfg.Labels["zone"])
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("unexpected LogLevel: %q", cfg.LogLevel)
	}
	if cfg.DataDir != "/opt/agent/data" {
		t.Errorf("unexpected DataDir: %q", cfg.DataDir)
	}
	if !cfg.BackupEnabled {
		t.Error("expected BackupEnabled true")
	}
	if !cfg.ScannerEnabled {
		t.Error("expected ScannerEnabled true")
	}
	if !cfg.TLSEnabled {
		t.Error("expected TLSEnabled true")
	}
	if cfg.TLSCertFile != "/certs/tls.pem" {
		t.Errorf("unexpected TLSCertFile: %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/certs/tls-key.pem" {
		t.Errorf("unexpected TLSKeyFile: %q", cfg.TLSKeyFile)
	}
	if cfg.TLSCAFile != "/certs/ca.pem" {
		t.Errorf("unexpected TLSCAFile: %q", cfg.TLSCAFile)
	}
}

// ============================================================================
// New (constructor) Tests
// ============================================================================

func TestNewAgentRequiresToken(t *testing.T) {
	log := logger.Nop()
	cfg := Config{
		AgentID:    "test",
		GatewayURL: "nats://localhost:4222",
		// Token intentionally empty
	}

	a, err := New(cfg, log)
	if err == nil {
		t.Fatal("expected error when Token is empty")
	}
	if a != nil {
		t.Error("expected nil agent on error")
	}
}

func TestNewAgentDefaults(t *testing.T) {
	log := logger.Nop()
	cfg := Config{
		Token: "mytoken",
		// All other fields empty - constructor should fill defaults
	}

	a, err := New(cfg, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a == nil {
		t.Fatal("expected non-nil agent")
	}

	// GatewayURL defaults to localhost
	if a.config.GatewayURL != "nats://localhost:4222" {
		t.Errorf("expected default GatewayURL, got %q", a.config.GatewayURL)
	}

	// AgentID should be generated
	if a.id == "" {
		t.Error("expected non-empty agent ID")
	}
	if len(a.id) != 36 {
		t.Errorf("expected UUID-length agent ID, got %d: %q", len(a.id), a.id)
	}

	// Hostname should be set
	if a.config.Hostname == "" {
		// os.Hostname() can theoretically fail, but it usually doesn't.
		// We just check it's not panicking.
		t.Log("Hostname is empty (os.Hostname may have failed)")
	}
}

func TestNewAgentPreservesExplicitConfig(t *testing.T) {
	log := logger.Nop()
	cfg := Config{
		AgentID:    "explicit-id",
		Token:      "mytoken",
		GatewayURL: "nats://custom:5222",
		Hostname:   "custom-host",
	}

	a, err := New(cfg, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if a.id != "explicit-id" {
		t.Errorf("expected agent ID 'explicit-id', got %q", a.id)
	}
	if a.config.GatewayURL != "nats://custom:5222" {
		t.Errorf("expected GatewayURL 'nats://custom:5222', got %q", a.config.GatewayURL)
	}
	if a.config.Hostname != "custom-host" {
		t.Errorf("expected Hostname 'custom-host', got %q", a.config.Hostname)
	}
}

func TestNewAgentID(t *testing.T) {
	log := logger.Nop()
	cfg := Config{
		AgentID: "my-agent",
		Token:   "t",
	}

	a, err := New(cfg, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if a.ID() != "my-agent" {
		t.Errorf("expected ID() to return 'my-agent', got %q", a.ID())
	}
}

// ============================================================================
// Version Tests
// ============================================================================

func TestVersionDefault(t *testing.T) {
	if Version != "dev" {
		t.Errorf("expected default Version 'dev', got %q", Version)
	}
}
