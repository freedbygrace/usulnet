// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package monitoring

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// Proactive System Health Checker
// ============================================================================

// SystemAlertChecker runs periodic checks against core infrastructure
// components (PostgreSQL, Redis, NATS, disk, agents, TLS certs, license) and
// sends notifications through the notification service when issues are found.
//
// It implements debouncing so that the same alert is not sent more than once
// per CooldownPeriod (default: 1 hour).
type SystemAlertChecker struct {
	config SystemAlertConfig
	probes []HealthProbe
	notify SystemNotifier
	log    *logger.Logger

	mu           sync.Mutex
	lastNotified map[string]time.Time // probeID -> last notification time
	stopCh       chan struct{}
	running      bool
}

// SystemAlertConfig configures the proactive health checker.
type SystemAlertConfig struct {
	// Enabled activates the system health checker. Default: true.
	Enabled bool

	// Interval is the time between health check cycles. Default: 60s.
	Interval time.Duration

	// CooldownPeriod prevents re-sending the same alert within this window.
	// Default: 1 hour.
	CooldownPeriod time.Duration
}

// DefaultSystemAlertConfig returns sensible defaults.
func DefaultSystemAlertConfig() SystemAlertConfig {
	return SystemAlertConfig{
		Enabled:        true,
		Interval:       60 * time.Second,
		CooldownPeriod: 1 * time.Hour,
	}
}

// SystemNotifier is the interface the health checker uses to send
// notifications. In production this is backed by the notification service.
type SystemNotifier interface {
	// SendSystemAlert sends a system-level alert notification.
	SendSystemAlert(ctx context.Context, title, body, severity string) error
}

// HealthProbe represents a single health check.
type HealthProbe struct {
	// ID uniquely identifies the probe for debouncing (e.g., "postgres", "redis").
	ID string
	// Name is a human-readable label for the probe.
	Name string
	// Check performs the health check and returns an error if unhealthy.
	Check func(ctx context.Context) error
	// Severity is the alert severity when the probe fails ("critical" or "warning").
	Severity string
}

// NewSystemAlertChecker creates a new checker. Probes and the notifier must be
// provided by the caller (typically during application bootstrap).
func NewSystemAlertChecker(cfg SystemAlertConfig, probes []HealthProbe, notify SystemNotifier, log *logger.Logger) *SystemAlertChecker {
	return &SystemAlertChecker{
		config:       cfg,
		probes:       probes,
		notify:       notify,
		log:          log.Named("system-alerts"),
		lastNotified: make(map[string]time.Time),
		stopCh:       make(chan struct{}),
	}
}

// Start begins the periodic health check loop. It is non-blocking.
func (s *SystemAlertChecker) Start(ctx context.Context) {
	if !s.config.Enabled {
		s.log.Info("System health checker disabled")
		return
	}

	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()

	s.log.Info("System health checker started",
		"interval", s.config.Interval.String(),
		"cooldown", s.config.CooldownPeriod.String(),
		"probes", len(s.probes),
	)

	go s.loop(ctx)
}

// Stop gracefully stops the health check loop.
func (s *SystemAlertChecker) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}
	s.running = false
	close(s.stopCh)
	s.log.Info("System health checker stopped")
}

// loop runs the periodic check cycle.
func (s *SystemAlertChecker) loop(ctx context.Context) {
	// Run an initial check immediately on start.
	s.runChecks(ctx)

	ticker := time.NewTicker(s.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.runChecks(ctx)
		}
	}
}

// runChecks executes all registered probes and sends alerts for failures.
func (s *SystemAlertChecker) runChecks(ctx context.Context) {
	for _, probe := range s.probes {
		checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := probe.Check(checkCtx)
		cancel()

		if err != nil {
			s.handleFailure(ctx, probe, err)
		} else {
			// Clear debounce on recovery so the next failure is reported.
			s.mu.Lock()
			delete(s.lastNotified, probe.ID)
			s.mu.Unlock()
		}
	}
}

// handleFailure processes a failed health check with debouncing.
func (s *SystemAlertChecker) handleFailure(ctx context.Context, probe HealthProbe, err error) {
	s.mu.Lock()
	last, exists := s.lastNotified[probe.ID]
	now := time.Now()

	if exists && now.Sub(last) < s.config.CooldownPeriod {
		s.mu.Unlock()
		// Within cooldown - skip notification but still log.
		s.log.Warn("Health check failed (notification suppressed by cooldown)",
			"probe", probe.ID,
			"error", err.Error(),
		)
		return
	}

	s.lastNotified[probe.ID] = now
	s.mu.Unlock()

	title := fmt.Sprintf("[%s] %s health check failed", probe.Severity, probe.Name)
	body := fmt.Sprintf("The %s health probe failed:\n\n%s\n\nThis alert will not repeat for %s.",
		probe.Name, err.Error(), s.config.CooldownPeriod)

	s.log.Error("Health check failed - sending notification",
		"probe", probe.ID,
		"severity", probe.Severity,
		"error", err.Error(),
	)

	notifyCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if sendErr := s.notify.SendSystemAlert(notifyCtx, title, body, probe.Severity); sendErr != nil {
		s.log.Error("Failed to send system alert notification",
			"probe", probe.ID,
			"error", sendErr.Error(),
		)
	}
}

// ============================================================================
// Built-in Probe Constructors
// ============================================================================

// PostgresProbe returns a health probe that checks PostgreSQL connectivity.
// The pingFn should execute a simple query like "SELECT 1".
func PostgresProbe(pingFn func(ctx context.Context) error) HealthProbe {
	return HealthProbe{
		ID:       "postgres",
		Name:     "PostgreSQL",
		Severity: "critical",
		Check:    pingFn,
	}
}

// RedisProbe returns a health probe that checks Redis connectivity.
func RedisProbe(pingFn func(ctx context.Context) error) HealthProbe {
	return HealthProbe{
		ID:       "redis",
		Name:     "Redis",
		Severity: "critical",
		Check:    pingFn,
	}
}

// NATSProbe returns a health probe that checks NATS connectivity.
func NATSProbe(pingFn func(ctx context.Context) error) HealthProbe {
	return HealthProbe{
		ID:       "nats",
		Name:     "NATS",
		Severity: "critical",
		Check:    pingFn,
	}
}

// DiskUsageProbe returns a health probe that checks disk usage on a path.
// The checkFn should return an error if disk usage exceeds the threshold.
func DiskUsageProbe(checkFn func(ctx context.Context) error) HealthProbe {
	return HealthProbe{
		ID:       "disk_usage",
		Name:     "Disk Usage",
		Severity: "critical",
		Check:    checkFn,
	}
}

// AgentConnectivityProbe returns a health probe that checks whether any
// agents have reported within the expected heartbeat window.
func AgentConnectivityProbe(checkFn func(ctx context.Context) error) HealthProbe {
	return HealthProbe{
		ID:       "agent_connectivity",
		Name:     "Agent Connectivity",
		Severity: "warning",
		Check:    checkFn,
	}
}

// TLSCertExpiryProbe returns a health probe that checks TLS certificate
// expiration (warns if < 30 days).
func TLSCertExpiryProbe(checkFn func(ctx context.Context) error) HealthProbe {
	return HealthProbe{
		ID:       "tls_cert_expiry",
		Name:     "TLS Certificate Expiry",
		Severity: "warning",
		Check:    checkFn,
	}
}

// LicenseExpiryProbe returns a health probe that checks license expiration.
func LicenseExpiryProbe(checkFn func(ctx context.Context) error) HealthProbe {
	return HealthProbe{
		ID:       "license_expiry",
		Name:     "License Expiry",
		Severity: "warning",
		Check:    checkFn,
	}
}
