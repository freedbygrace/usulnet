// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package monitoring

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// Mock: SystemNotifier
// ============================================================================

type mockSystemNotifier struct {
	mu     sync.Mutex
	alerts []systemAlertCall
	err    error
}

type systemAlertCall struct {
	Title    string
	Body     string
	Severity string
}

func newMockSystemNotifier() *mockSystemNotifier {
	return &mockSystemNotifier{}
}

func (n *mockSystemNotifier) SendSystemAlert(_ context.Context, title, body, severity string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.err != nil {
		return n.err
	}
	n.alerts = append(n.alerts, systemAlertCall{
		Title:    title,
		Body:     body,
		Severity: severity,
	})
	return nil
}

func (n *mockSystemNotifier) alertCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.alerts)
}

func (n *mockSystemNotifier) lastAlert() systemAlertCall {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.alerts) == 0 {
		return systemAlertCall{}
	}
	return n.alerts[len(n.alerts)-1]
}

// ============================================================================
// DefaultSystemAlertConfig
// ============================================================================

func TestDefaultSystemAlertConfig(t *testing.T) {
	cfg := DefaultSystemAlertConfig()

	if !cfg.Enabled {
		t.Error("expected Enabled=true")
	}
	if cfg.Interval != 60*time.Second {
		t.Errorf("expected Interval=60s, got %v", cfg.Interval)
	}
	if cfg.CooldownPeriod != 1*time.Hour {
		t.Errorf("expected CooldownPeriod=1h, got %v", cfg.CooldownPeriod)
	}
}

// ============================================================================
// SystemAlertConfig struct fields
// ============================================================================

func TestSystemAlertConfig_Fields(t *testing.T) {
	cfg := SystemAlertConfig{
		Enabled:        false,
		Interval:       30 * time.Second,
		CooldownPeriod: 5 * time.Minute,
	}

	if cfg.Enabled {
		t.Error("expected Enabled=false")
	}
	if cfg.Interval != 30*time.Second {
		t.Errorf("expected Interval=30s, got %v", cfg.Interval)
	}
	if cfg.CooldownPeriod != 5*time.Minute {
		t.Errorf("expected CooldownPeriod=5m, got %v", cfg.CooldownPeriod)
	}
}

// ============================================================================
// HealthProbe struct fields
// ============================================================================

func TestHealthProbe_Fields(t *testing.T) {
	called := false
	probe := HealthProbe{
		ID:       "test-probe",
		Name:     "Test Probe",
		Severity: "critical",
		Check: func(_ context.Context) error {
			called = true
			return nil
		},
	}

	if probe.ID != "test-probe" {
		t.Errorf("ID: expected 'test-probe', got %q", probe.ID)
	}
	if probe.Name != "Test Probe" {
		t.Errorf("Name: expected 'Test Probe', got %q", probe.Name)
	}
	if probe.Severity != "critical" {
		t.Errorf("Severity: expected 'critical', got %q", probe.Severity)
	}

	err := probe.Check(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("expected Check function to be called")
	}
}

// ============================================================================
// NewSystemAlertChecker constructor
// ============================================================================

func TestNewSystemAlertChecker(t *testing.T) {
	cfg := DefaultSystemAlertConfig()
	notify := newMockSystemNotifier()
	log := logger.Nop()
	probes := []HealthProbe{
		{ID: "pg", Name: "PostgreSQL", Severity: "critical", Check: func(_ context.Context) error { return nil }},
	}

	checker := NewSystemAlertChecker(cfg, probes, notify, log)
	if checker == nil {
		t.Fatal("expected non-nil checker")
	}
	if len(checker.probes) != 1 {
		t.Errorf("expected 1 probe, got %d", len(checker.probes))
	}
	if checker.lastNotified == nil {
		t.Error("expected lastNotified map to be initialized")
	}
	if checker.stopCh == nil {
		t.Error("expected stopCh channel to be initialized")
	}
}

func TestNewSystemAlertChecker_NoProbes(t *testing.T) {
	cfg := DefaultSystemAlertConfig()
	notify := newMockSystemNotifier()
	log := logger.Nop()

	checker := NewSystemAlertChecker(cfg, nil, notify, log)
	if checker == nil {
		t.Fatal("expected non-nil checker with nil probes")
	}
	if checker.probes != nil {
		t.Errorf("expected nil probes, got %d", len(checker.probes))
	}
}

// ============================================================================
// runChecks — all healthy
// ============================================================================

func TestRunChecks_AllHealthy(t *testing.T) {
	notify := newMockSystemNotifier()
	probes := []HealthProbe{
		{ID: "pg", Name: "PostgreSQL", Severity: "critical", Check: func(_ context.Context) error { return nil }},
		{ID: "redis", Name: "Redis", Severity: "critical", Check: func(_ context.Context) error { return nil }},
	}

	checker := NewSystemAlertChecker(DefaultSystemAlertConfig(), probes, notify, logger.Nop())
	checker.runChecks(context.Background())

	if notify.alertCount() != 0 {
		t.Errorf("expected 0 notifications for all-healthy, got %d", notify.alertCount())
	}
}

// ============================================================================
// runChecks — all unhealthy
// ============================================================================

func TestRunChecks_AllUnhealthy(t *testing.T) {
	notify := newMockSystemNotifier()
	probes := []HealthProbe{
		{ID: "pg", Name: "PostgreSQL", Severity: "critical", Check: func(_ context.Context) error {
			return errors.New("connection refused")
		}},
		{ID: "redis", Name: "Redis", Severity: "warning", Check: func(_ context.Context) error {
			return errors.New("timeout")
		}},
	}

	checker := NewSystemAlertChecker(DefaultSystemAlertConfig(), probes, notify, logger.Nop())
	checker.runChecks(context.Background())

	if notify.alertCount() != 2 {
		t.Errorf("expected 2 notifications for all-unhealthy, got %d", notify.alertCount())
	}
}

// ============================================================================
// runChecks — mixed healthy/unhealthy
// ============================================================================

func TestRunChecks_Mixed(t *testing.T) {
	notify := newMockSystemNotifier()
	probes := []HealthProbe{
		{ID: "pg", Name: "PostgreSQL", Severity: "critical", Check: func(_ context.Context) error { return nil }},
		{ID: "redis", Name: "Redis", Severity: "critical", Check: func(_ context.Context) error {
			return errors.New("connection lost")
		}},
		{ID: "nats", Name: "NATS", Severity: "warning", Check: func(_ context.Context) error { return nil }},
	}

	checker := NewSystemAlertChecker(DefaultSystemAlertConfig(), probes, notify, logger.Nop())
	checker.runChecks(context.Background())

	if notify.alertCount() != 1 {
		t.Errorf("expected 1 notification for mixed health, got %d", notify.alertCount())
	}

	alert := notify.lastAlert()
	if alert.Severity != "critical" {
		t.Errorf("expected severity 'critical', got %q", alert.Severity)
	}
}

// ============================================================================
// runChecks — alert message formatting
// ============================================================================

func TestRunChecks_AlertMessageFormat(t *testing.T) {
	notify := newMockSystemNotifier()
	probes := []HealthProbe{
		{ID: "pg", Name: "PostgreSQL", Severity: "critical", Check: func(_ context.Context) error {
			return errors.New("dial tcp: connection refused")
		}},
	}

	checker := NewSystemAlertChecker(DefaultSystemAlertConfig(), probes, notify, logger.Nop())
	checker.runChecks(context.Background())

	if notify.alertCount() != 1 {
		t.Fatalf("expected 1 notification, got %d", notify.alertCount())
	}

	alert := notify.lastAlert()
	// Title should include severity and probe name
	if !containsSubstr(alert.Title, "critical") {
		t.Errorf("expected title to contain 'critical', got %q", alert.Title)
	}
	if !containsSubstr(alert.Title, "PostgreSQL") {
		t.Errorf("expected title to contain 'PostgreSQL', got %q", alert.Title)
	}
	// Body should include the error
	if !containsSubstr(alert.Body, "connection refused") {
		t.Errorf("expected body to contain error message, got %q", alert.Body)
	}
}

// ============================================================================
// Cooldown debouncing
// ============================================================================

func TestRunChecks_CooldownDebounce(t *testing.T) {
	notify := newMockSystemNotifier()
	probes := []HealthProbe{
		{ID: "pg", Name: "PostgreSQL", Severity: "critical", Check: func(_ context.Context) error {
			return errors.New("unavailable")
		}},
	}

	cfg := SystemAlertConfig{
		Enabled:        true,
		Interval:       1 * time.Second,
		CooldownPeriod: 1 * time.Hour, // long cooldown
	}
	checker := NewSystemAlertChecker(cfg, probes, notify, logger.Nop())

	// First run: should notify
	checker.runChecks(context.Background())
	if notify.alertCount() != 1 {
		t.Fatalf("expected 1 notification on first failure, got %d", notify.alertCount())
	}

	// Second run: within cooldown, should NOT notify again
	checker.runChecks(context.Background())
	if notify.alertCount() != 1 {
		t.Errorf("expected still 1 notification (cooldown debounce), got %d", notify.alertCount())
	}

	// Third run: still within cooldown
	checker.runChecks(context.Background())
	if notify.alertCount() != 1 {
		t.Errorf("expected still 1 notification after third run, got %d", notify.alertCount())
	}
}

func TestRunChecks_CooldownExpires(t *testing.T) {
	notify := newMockSystemNotifier()
	probes := []HealthProbe{
		{ID: "pg", Name: "PostgreSQL", Severity: "critical", Check: func(_ context.Context) error {
			return errors.New("unavailable")
		}},
	}

	cfg := SystemAlertConfig{
		Enabled:        true,
		Interval:       1 * time.Second,
		CooldownPeriod: 1 * time.Millisecond, // very short cooldown for testing
	}
	checker := NewSystemAlertChecker(cfg, probes, notify, logger.Nop())

	// First failure
	checker.runChecks(context.Background())
	if notify.alertCount() != 1 {
		t.Fatalf("expected 1 notification, got %d", notify.alertCount())
	}

	// Wait for cooldown to expire
	time.Sleep(5 * time.Millisecond)

	// Second failure after cooldown: should notify again
	checker.runChecks(context.Background())
	if notify.alertCount() != 2 {
		t.Errorf("expected 2 notifications after cooldown expired, got %d", notify.alertCount())
	}
}

func TestRunChecks_CooldownPerProbe(t *testing.T) {
	notify := newMockSystemNotifier()
	probes := []HealthProbe{
		{ID: "pg", Name: "PostgreSQL", Severity: "critical", Check: func(_ context.Context) error {
			return errors.New("pg error")
		}},
		{ID: "redis", Name: "Redis", Severity: "warning", Check: func(_ context.Context) error {
			return errors.New("redis error")
		}},
	}

	cfg := SystemAlertConfig{
		Enabled:        true,
		Interval:       1 * time.Second,
		CooldownPeriod: 1 * time.Hour,
	}
	checker := NewSystemAlertChecker(cfg, probes, notify, logger.Nop())

	// First run: both probes fail, both notified
	checker.runChecks(context.Background())
	if notify.alertCount() != 2 {
		t.Fatalf("expected 2 notifications, got %d", notify.alertCount())
	}

	// Second run: both still fail, both suppressed independently
	checker.runChecks(context.Background())
	if notify.alertCount() != 2 {
		t.Errorf("expected still 2 notifications (both cooldowns active), got %d", notify.alertCount())
	}
}

// ============================================================================
// Recovery clears debounce
// ============================================================================

func TestRunChecks_RecoveryClearsCooldown(t *testing.T) {
	failPg := true
	notify := newMockSystemNotifier()
	probes := []HealthProbe{
		{ID: "pg", Name: "PostgreSQL", Severity: "critical", Check: func(_ context.Context) error {
			if failPg {
				return errors.New("unavailable")
			}
			return nil
		}},
	}

	cfg := SystemAlertConfig{
		Enabled:        true,
		Interval:       1 * time.Second,
		CooldownPeriod: 1 * time.Hour,
	}
	checker := NewSystemAlertChecker(cfg, probes, notify, logger.Nop())

	// First run: failure, notified
	checker.runChecks(context.Background())
	if notify.alertCount() != 1 {
		t.Fatalf("expected 1 notification, got %d", notify.alertCount())
	}

	// Probe recovers
	failPg = false
	checker.runChecks(context.Background())
	// Recovery should clear the debounce entry
	checker.mu.Lock()
	_, exists := checker.lastNotified["pg"]
	checker.mu.Unlock()
	if exists {
		t.Error("expected lastNotified entry to be cleared after recovery")
	}

	// Probe fails again: should notify despite being within original cooldown window
	failPg = true
	checker.runChecks(context.Background())
	if notify.alertCount() != 2 {
		t.Errorf("expected 2 notifications after recovery and re-failure, got %d", notify.alertCount())
	}
}

// ============================================================================
// Notifier error handling
// ============================================================================

func TestRunChecks_NotifierError(t *testing.T) {
	notify := newMockSystemNotifier()
	notify.err = errors.New("notification service down")

	probes := []HealthProbe{
		{ID: "pg", Name: "PostgreSQL", Severity: "critical", Check: func(_ context.Context) error {
			return errors.New("pg down")
		}},
	}

	checker := NewSystemAlertChecker(DefaultSystemAlertConfig(), probes, notify, logger.Nop())

	// Should not panic even when notifier fails
	checker.runChecks(context.Background())

	// Cooldown entry should still be recorded (notification was attempted)
	checker.mu.Lock()
	_, exists := checker.lastNotified["pg"]
	checker.mu.Unlock()
	if !exists {
		t.Error("expected lastNotified entry even when notification fails")
	}
}

// ============================================================================
// Start / Stop lifecycle
// ============================================================================

func TestStart_Disabled(t *testing.T) {
	notify := newMockSystemNotifier()
	cfg := SystemAlertConfig{
		Enabled:  false,
		Interval: 10 * time.Millisecond,
	}
	checker := NewSystemAlertChecker(cfg, nil, notify, logger.Nop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	checker.Start(ctx)

	// Should not be running
	checker.mu.Lock()
	running := checker.running
	checker.mu.Unlock()
	if running {
		t.Error("expected checker NOT to be running when disabled")
	}
}

func TestStart_Stop(t *testing.T) {
	notify := newMockSystemNotifier()
	probes := []HealthProbe{
		{ID: "pg", Name: "PostgreSQL", Severity: "critical", Check: func(_ context.Context) error { return nil }},
	}

	cfg := SystemAlertConfig{
		Enabled:        true,
		Interval:       50 * time.Millisecond,
		CooldownPeriod: 1 * time.Hour,
	}
	checker := NewSystemAlertChecker(cfg, probes, notify, logger.Nop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	checker.Start(ctx)

	// Let it run briefly
	time.Sleep(100 * time.Millisecond)

	checker.mu.Lock()
	running := checker.running
	checker.mu.Unlock()
	if !running {
		t.Error("expected checker to be running after Start")
	}

	checker.Stop()

	checker.mu.Lock()
	running = checker.running
	checker.mu.Unlock()
	if running {
		t.Error("expected checker NOT to be running after Stop")
	}
}

func TestStart_DoubleStart(t *testing.T) {
	notify := newMockSystemNotifier()
	cfg := SystemAlertConfig{
		Enabled:        true,
		Interval:       1 * time.Hour, // long interval to avoid ticks
		CooldownPeriod: 1 * time.Hour,
	}
	checker := NewSystemAlertChecker(cfg, nil, notify, logger.Nop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	checker.Start(ctx)
	// Second Start should be a no-op (idempotent)
	checker.Start(ctx)

	checker.mu.Lock()
	running := checker.running
	checker.mu.Unlock()
	if !running {
		t.Error("expected checker to still be running after double Start")
	}

	checker.Stop()
}

func TestStop_WithoutStart(t *testing.T) {
	notify := newMockSystemNotifier()
	cfg := DefaultSystemAlertConfig()
	checker := NewSystemAlertChecker(cfg, nil, notify, logger.Nop())

	// Should not panic
	checker.Stop()
}

func TestStart_ContextCancel(t *testing.T) {
	notify := newMockSystemNotifier()
	probes := []HealthProbe{
		{ID: "pg", Name: "PostgreSQL", Severity: "critical", Check: func(_ context.Context) error { return nil }},
	}

	cfg := SystemAlertConfig{
		Enabled:        true,
		Interval:       50 * time.Millisecond,
		CooldownPeriod: 1 * time.Hour,
	}
	checker := NewSystemAlertChecker(cfg, probes, notify, logger.Nop())

	ctx, cancel := context.WithCancel(context.Background())
	checker.Start(ctx)

	// Let it run briefly
	time.Sleep(100 * time.Millisecond)

	// Cancel context should cause the loop to exit
	cancel()

	// Give goroutine time to exit
	time.Sleep(100 * time.Millisecond)
}

// ============================================================================
// Built-in probe constructors
// ============================================================================

func TestPostgresProbe(t *testing.T) {
	probe := PostgresProbe(func(_ context.Context) error { return nil })
	if probe.ID != "postgres" {
		t.Errorf("expected ID 'postgres', got %q", probe.ID)
	}
	if probe.Name != "PostgreSQL" {
		t.Errorf("expected Name 'PostgreSQL', got %q", probe.Name)
	}
	if probe.Severity != "critical" {
		t.Errorf("expected Severity 'critical', got %q", probe.Severity)
	}
	if err := probe.Check(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRedisProbe(t *testing.T) {
	probe := RedisProbe(func(_ context.Context) error { return errors.New("redis down") })
	if probe.ID != "redis" {
		t.Errorf("expected ID 'redis', got %q", probe.ID)
	}
	if probe.Name != "Redis" {
		t.Errorf("expected Name 'Redis', got %q", probe.Name)
	}
	if probe.Severity != "critical" {
		t.Errorf("expected Severity 'critical', got %q", probe.Severity)
	}
	if err := probe.Check(context.Background()); err == nil {
		t.Fatal("expected error from failing redis probe")
	}
}

func TestNATSProbe(t *testing.T) {
	probe := NATSProbe(func(_ context.Context) error { return nil })
	if probe.ID != "nats" {
		t.Errorf("expected ID 'nats', got %q", probe.ID)
	}
	if probe.Severity != "critical" {
		t.Errorf("expected Severity 'critical', got %q", probe.Severity)
	}
}

func TestDiskUsageProbe(t *testing.T) {
	probe := DiskUsageProbe(func(_ context.Context) error { return nil })
	if probe.ID != "disk_usage" {
		t.Errorf("expected ID 'disk_usage', got %q", probe.ID)
	}
	if probe.Severity != "critical" {
		t.Errorf("expected Severity 'critical', got %q", probe.Severity)
	}
}

func TestAgentConnectivityProbe(t *testing.T) {
	probe := AgentConnectivityProbe(func(_ context.Context) error { return nil })
	if probe.ID != "agent_connectivity" {
		t.Errorf("expected ID 'agent_connectivity', got %q", probe.ID)
	}
	if probe.Severity != "warning" {
		t.Errorf("expected Severity 'warning', got %q", probe.Severity)
	}
}

func TestTLSCertExpiryProbe(t *testing.T) {
	probe := TLSCertExpiryProbe(func(_ context.Context) error { return nil })
	if probe.ID != "tls_cert_expiry" {
		t.Errorf("expected ID 'tls_cert_expiry', got %q", probe.ID)
	}
	if probe.Severity != "warning" {
		t.Errorf("expected Severity 'warning', got %q", probe.Severity)
	}
}

func TestLicenseExpiryProbe(t *testing.T) {
	probe := LicenseExpiryProbe(func(_ context.Context) error { return nil })
	if probe.ID != "license_expiry" {
		t.Errorf("expected ID 'license_expiry', got %q", probe.ID)
	}
	if probe.Severity != "warning" {
		t.Errorf("expected Severity 'warning', got %q", probe.Severity)
	}
}

// ============================================================================
// No probes — runChecks is a no-op
// ============================================================================

func TestRunChecks_NoProbes(t *testing.T) {
	notify := newMockSystemNotifier()
	checker := NewSystemAlertChecker(DefaultSystemAlertConfig(), nil, notify, logger.Nop())

	// Should not panic
	checker.runChecks(context.Background())
	if notify.alertCount() != 0 {
		t.Errorf("expected 0 notifications with no probes, got %d", notify.alertCount())
	}
}

// ============================================================================
// Helper
// ============================================================================

func containsSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
