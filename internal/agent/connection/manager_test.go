// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package connection

import (
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// State Tests
// ============================================================================

func TestStateString(t *testing.T) {
	tests := []struct {
		state State
		want  string
	}{
		{StateDisconnected, "disconnected"},
		{StateConnecting, "connecting"},
		{StateConnected, "connected"},
		{StateReconnecting, "reconnecting"},
		{StateClosed, "closed"},
		{State(99), "unknown"},
		{State(-1), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.state.String()
			if got != tt.want {
				t.Errorf("State(%d).String() = %q, want %q", tt.state, got, tt.want)
			}
		})
	}
}

func TestStateIotaValues(t *testing.T) {
	// Verify iota ordering is as expected
	if StateDisconnected != 0 {
		t.Errorf("expected StateDisconnected=0, got %d", StateDisconnected)
	}
	if StateConnecting != 1 {
		t.Errorf("expected StateConnecting=1, got %d", StateConnecting)
	}
	if StateConnected != 2 {
		t.Errorf("expected StateConnected=2, got %d", StateConnected)
	}
	if StateReconnecting != 3 {
		t.Errorf("expected StateReconnecting=3, got %d", StateReconnecting)
	}
	if StateClosed != 4 {
		t.Errorf("expected StateClosed=4, got %d", StateClosed)
	}
}

// ============================================================================
// DefaultConfig Tests
// ============================================================================

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.URL != nats.DefaultURL {
		t.Errorf("expected URL %q, got %q", nats.DefaultURL, cfg.URL)
	}
	if cfg.MaxReconnects != -1 {
		t.Errorf("expected MaxReconnects -1 (infinite), got %d", cfg.MaxReconnects)
	}
	if cfg.ReconnectWait != 5*time.Second {
		t.Errorf("expected ReconnectWait 5s, got %v", cfg.ReconnectWait)
	}
	if cfg.PingInterval != 2*time.Minute {
		t.Errorf("expected PingInterval 2m, got %v", cfg.PingInterval)
	}
	if cfg.MaxPingsOut != 2 {
		t.Errorf("expected MaxPingsOut 2, got %d", cfg.MaxPingsOut)
	}
	if cfg.Timeout != 10*time.Second {
		t.Errorf("expected Timeout 10s, got %v", cfg.Timeout)
	}

	// Defaults that should be zero/empty
	if cfg.Token != "" {
		t.Errorf("expected empty Token, got %q", cfg.Token)
	}
	if cfg.Name != "" {
		t.Errorf("expected empty Name, got %q", cfg.Name)
	}
	if cfg.TLSEnabled {
		t.Error("expected TLSEnabled false")
	}
	if cfg.TLSCert != "" {
		t.Errorf("expected empty TLSCert, got %q", cfg.TLSCert)
	}
	if cfg.TLSKey != "" {
		t.Errorf("expected empty TLSKey, got %q", cfg.TLSKey)
	}
	if cfg.TLSCA != "" {
		t.Errorf("expected empty TLSCA, got %q", cfg.TLSCA)
	}
	if cfg.TLSSkipVerify {
		t.Error("expected TLSSkipVerify false")
	}
}

// ============================================================================
// Config Struct Tests
// ============================================================================

func TestConfigFields(t *testing.T) {
	cfg := Config{
		URL:           "nats://10.0.0.1:4222",
		Token:         "secret-token",
		Name:          "agent-1",
		MaxReconnects: 10,
		ReconnectWait: 3 * time.Second,
		PingInterval:  1 * time.Minute,
		MaxPingsOut:   5,
		Timeout:       30 * time.Second,
		TLSEnabled:    true,
		TLSCert:       "/certs/client.pem",
		TLSKey:        "/certs/client-key.pem",
		TLSCA:         "/certs/ca.pem",
		TLSSkipVerify: true,
	}

	if cfg.URL != "nats://10.0.0.1:4222" {
		t.Errorf("unexpected URL: %q", cfg.URL)
	}
	if cfg.Token != "secret-token" {
		t.Errorf("unexpected Token: %q", cfg.Token)
	}
	if cfg.Name != "agent-1" {
		t.Errorf("unexpected Name: %q", cfg.Name)
	}
	if cfg.MaxReconnects != 10 {
		t.Errorf("unexpected MaxReconnects: %d", cfg.MaxReconnects)
	}
	if cfg.ReconnectWait != 3*time.Second {
		t.Errorf("unexpected ReconnectWait: %v", cfg.ReconnectWait)
	}
	if cfg.PingInterval != 1*time.Minute {
		t.Errorf("unexpected PingInterval: %v", cfg.PingInterval)
	}
	if cfg.MaxPingsOut != 5 {
		t.Errorf("unexpected MaxPingsOut: %d", cfg.MaxPingsOut)
	}
	if cfg.Timeout != 30*time.Second {
		t.Errorf("unexpected Timeout: %v", cfg.Timeout)
	}
	if !cfg.TLSEnabled {
		t.Error("expected TLSEnabled true")
	}
	if cfg.TLSCert != "/certs/client.pem" {
		t.Errorf("unexpected TLSCert: %q", cfg.TLSCert)
	}
	if cfg.TLSKey != "/certs/client-key.pem" {
		t.Errorf("unexpected TLSKey: %q", cfg.TLSKey)
	}
	if cfg.TLSCA != "/certs/ca.pem" {
		t.Errorf("unexpected TLSCA: %q", cfg.TLSCA)
	}
	if !cfg.TLSSkipVerify {
		t.Error("expected TLSSkipVerify true")
	}
}

// ============================================================================
// NewManager Tests
// ============================================================================

func TestNewManager(t *testing.T) {
	log := logger.Nop()
	cfg := DefaultConfig()

	m := NewManager(cfg, log)

	if m == nil {
		t.Fatal("expected non-nil Manager")
	}

	// Initial state should be disconnected
	if m.State() != StateDisconnected {
		t.Errorf("expected initial state StateDisconnected, got %v", m.State())
	}

	// Config should be stored
	if m.config.URL != cfg.URL {
		t.Errorf("expected config URL %q, got %q", cfg.URL, m.config.URL)
	}
	if m.config.MaxReconnects != cfg.MaxReconnects {
		t.Errorf("expected config MaxReconnects %d, got %d", cfg.MaxReconnects, m.config.MaxReconnects)
	}

	// Connection should be nil
	if m.Conn() != nil {
		t.Error("expected nil Conn before connecting")
	}

	// IsConnected should be false
	if m.IsConnected() {
		t.Error("expected IsConnected false before connecting")
	}
}

func TestNewManagerWithCustomConfig(t *testing.T) {
	log := logger.Nop()
	cfg := Config{
		URL:           "nats://custom:4222",
		Token:         "mytoken",
		Name:          "test-agent",
		MaxReconnects: 5,
		ReconnectWait: 2 * time.Second,
		PingInterval:  30 * time.Second,
		MaxPingsOut:   3,
		Timeout:       15 * time.Second,
	}

	m := NewManager(cfg, log)

	if m.config.URL != "nats://custom:4222" {
		t.Errorf("expected URL nats://custom:4222, got %q", m.config.URL)
	}
	if m.config.Token != "mytoken" {
		t.Errorf("expected Token mytoken, got %q", m.config.Token)
	}
	if m.config.Name != "test-agent" {
		t.Errorf("expected Name test-agent, got %q", m.config.Name)
	}
}

// ============================================================================
// Manager Callback Tests
// ============================================================================

func TestManagerCallbacks(t *testing.T) {
	log := logger.Nop()
	m := NewManager(DefaultConfig(), log)

	connectCalled := false
	disconnectCalled := false
	reconnectCalled := false

	m.OnConnect(func() {
		connectCalled = true
	})
	m.OnDisconnect(func(err error) {
		disconnectCalled = true
	})
	m.OnReconnect(func() {
		reconnectCalled = true
	})

	// Callbacks are stored but not called until events occur
	if connectCalled {
		t.Error("expected connect callback not called yet")
	}
	if disconnectCalled {
		t.Error("expected disconnect callback not called yet")
	}
	if reconnectCalled {
		t.Error("expected reconnect callback not called yet")
	}

	// Verify callbacks were set (non-nil)
	if m.onConnect == nil {
		t.Error("expected onConnect callback set")
	}
	if m.onDisconnect == nil {
		t.Error("expected onDisconnect callback set")
	}
	if m.onReconnect == nil {
		t.Error("expected onReconnect callback set")
	}
}

// ============================================================================
// Manager State Tests
// ============================================================================

func TestManagerSetState(t *testing.T) {
	log := logger.Nop()
	m := NewManager(DefaultConfig(), log)

	states := []State{
		StateConnecting,
		StateConnected,
		StateReconnecting,
		StateDisconnected,
		StateClosed,
	}

	for _, s := range states {
		m.setState(s)
		if m.State() != s {
			t.Errorf("expected state %v after setState, got %v", s, m.State())
		}
	}
}

func TestManagerCloseWithoutConnect(t *testing.T) {
	log := logger.Nop()
	m := NewManager(DefaultConfig(), log)

	err := m.Close()
	if err != nil {
		t.Errorf("expected no error closing without connection, got %v", err)
	}

	if m.State() != StateClosed {
		t.Errorf("expected StateClosed after Close, got %v", m.State())
	}
}

// ============================================================================
// Stats Struct Tests
// ============================================================================

func TestStatsStruct(t *testing.T) {
	s := Stats{
		State:           StateConnected,
		ConnectCount:    3,
		DisconnectCount: 1,
		LastConnectTime: time.Now(),
		LastError:       nil,
		RTT:             5 * time.Millisecond,
		InMsgs:          100,
		OutMsgs:         50,
		InBytes:         4096,
		OutBytes:        2048,
	}

	if s.State != StateConnected {
		t.Errorf("unexpected State: %v", s.State)
	}
	if s.ConnectCount != 3 {
		t.Errorf("unexpected ConnectCount: %d", s.ConnectCount)
	}
	if s.DisconnectCount != 1 {
		t.Errorf("unexpected DisconnectCount: %d", s.DisconnectCount)
	}
	if s.InMsgs != 100 {
		t.Errorf("unexpected InMsgs: %d", s.InMsgs)
	}
	if s.OutMsgs != 50 {
		t.Errorf("unexpected OutMsgs: %d", s.OutMsgs)
	}
	if s.InBytes != 4096 {
		t.Errorf("unexpected InBytes: %d", s.InBytes)
	}
	if s.OutBytes != 2048 {
		t.Errorf("unexpected OutBytes: %d", s.OutBytes)
	}
}

func TestManagerStatsWithoutConnection(t *testing.T) {
	log := logger.Nop()
	m := NewManager(DefaultConfig(), log)

	stats := m.Stats()

	if stats.State != StateDisconnected {
		t.Errorf("expected StateDisconnected, got %v", stats.State)
	}
	if stats.ConnectCount != 0 {
		t.Errorf("expected ConnectCount 0, got %d", stats.ConnectCount)
	}
	if stats.DisconnectCount != 0 {
		t.Errorf("expected DisconnectCount 0, got %d", stats.DisconnectCount)
	}
	if stats.LastError != nil {
		t.Errorf("expected nil LastError, got %v", stats.LastError)
	}
	if stats.InMsgs != 0 {
		t.Errorf("expected InMsgs 0, got %d", stats.InMsgs)
	}
	if stats.OutMsgs != 0 {
		t.Errorf("expected OutMsgs 0, got %d", stats.OutMsgs)
	}
}
