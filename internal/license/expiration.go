package license

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"
)

type ExpirationNotifier interface {
	NotifyLicenseExpiring(ctx context.Context, info *Info, daysRemaining int) error
	NotifyLicenseExpired(ctx context.Context, info *Info) error
	NotifyLimitApproaching(ctx context.Context, resource string, current, limit int) error
}

type ExpirationChecker struct {
	provider *Provider
	notifier ExpirationNotifier
	logger   Logger

	thresholds []int

	mu                 sync.Mutex
	notifiedThresholds map[int]time.Time
	expiredNotifiedAt  *time.Time

	checkInterval time.Duration
	stopCh        chan struct{}
}

type ExpirationCheckerConfig struct {
	Thresholds           []int
	CheckInterval        time.Duration
	NotificationCooldown time.Duration
}

func DefaultExpirationCheckerConfig() ExpirationCheckerConfig {
	return ExpirationCheckerConfig{
		Thresholds:           []int{30, 15, 7, 3, 1},
		CheckInterval:        1 * time.Hour,
		NotificationCooldown: 24 * time.Hour,
	}
}

func NewExpirationChecker(
	provider *Provider,
	notifier ExpirationNotifier,
	logger Logger,
	config ExpirationCheckerConfig,
) *ExpirationChecker {
	if len(config.Thresholds) == 0 {
		config.Thresholds = []int{30, 15, 7, 3, 1}
	}
	if config.CheckInterval <= 0 {
		config.CheckInterval = 1 * time.Hour
	}

	return &ExpirationChecker{
		provider:           provider,
		notifier:           notifier,
		logger:             logger,
		thresholds:         config.Thresholds,
		notifiedThresholds: make(map[int]time.Time),
		checkInterval:      config.CheckInterval,
		stopCh:             make(chan struct{}),
	}
}

func (ec *ExpirationChecker) Start() {
	go ec.run()
}

func (ec *ExpirationChecker) Stop() {
	close(ec.stopCh)
}

func (ec *ExpirationChecker) Check(ctx context.Context) {
	info := ec.provider.GetInfo()

	if info.Edition == CE {
		return
	}

	if info.ExpiresAt == nil {
		return
	}

	now := time.Now()
	expiresAt := *info.ExpiresAt

	if now.After(expiresAt) {
		ec.handleExpired(ctx, info)
		return
	}

	remaining := expiresAt.Sub(now)
	daysRemaining := int(math.Ceil(remaining.Hours() / 24))

	for _, threshold := range ec.thresholds {
		if daysRemaining <= threshold {
			ec.handleThreshold(ctx, info, threshold, daysRemaining)
			break
		}
	}
}

func (ec *ExpirationChecker) handleExpired(ctx context.Context, info *Info) {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	if ec.expiredNotifiedAt != nil {
		if time.Since(*ec.expiredNotifiedAt) < 24*time.Hour {
			return
		}
	}

	ec.logger.Warn("license: license has expired, sending notification",
		"license_id", info.LicenseID,
		"expired_at", info.ExpiresAt,
	)

	if err := ec.notifier.NotifyLicenseExpired(ctx, info); err != nil {
		ec.logger.Error("license: failed to send expiration notification", "error", err)
		return
	}

	now := time.Now()
	ec.expiredNotifiedAt = &now
}

func (ec *ExpirationChecker) handleThreshold(ctx context.Context, info *Info, threshold, daysRemaining int) {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	if lastNotified, ok := ec.notifiedThresholds[threshold]; ok {
		if time.Since(lastNotified) < 24*time.Hour {
			return
		}
	}

	ec.logger.Info("license: expiration approaching, sending notification",
		"license_id", info.LicenseID,
		"days_remaining", daysRemaining,
		"threshold", threshold,
	)

	if err := ec.notifier.NotifyLicenseExpiring(ctx, info, daysRemaining); err != nil {
		ec.logger.Error("license: failed to send expiring notification", "error", err)
		return
	}

	ec.notifiedThresholds[threshold] = time.Now()
}

func (ec *ExpirationChecker) run() {
	ec.Check(context.Background())

	ticker := time.NewTicker(ec.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ec.stopCh:
			return
		case <-ticker.C:
			ec.Check(context.Background())
		}
	}
}

func (ec *ExpirationChecker) ResetNotifications() {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.notifiedThresholds = make(map[int]time.Time)
	ec.expiredNotifiedAt = nil
}

func DaysUntilExpiration(info *Info) int {
	if info == nil || info.ExpiresAt == nil {
		return 0
	}

	remaining := time.Until(*info.ExpiresAt)
	if remaining <= 0 {
		return -1
	}

	return int(math.Ceil(remaining.Hours() / 24))
}

type GracefulDegradation struct {
	IsExpired        bool
	PreviousEdition  Edition
	ActiveLimits     Limits
	DisabledFeatures []Feature
	Message          string
}

func GetDegradationState(info *Info) *GracefulDegradation {
	if info == nil {
		return &GracefulDegradation{
			IsExpired:    false,
			ActiveLimits: CELimits(),
			Message:      "Running as Community Edition",
		}
	}

	if info.Valid && !info.IsExpired() {
		return &GracefulDegradation{
			IsExpired:       false,
			PreviousEdition: info.Edition,
			ActiveLimits:    info.Limits,
			Message:         fmt.Sprintf("License active (%s)", info.EditionName()),
		}
	}

	if info.IsExpired() || !info.Valid {
		degraded := &GracefulDegradation{
			IsExpired:        true,
			PreviousEdition:  info.Edition,
			ActiveLimits:     CELimits(),
			DisabledFeatures: info.Features,
			Message: fmt.Sprintf(
				"License expired. System operating in Community Edition mode. "+
					"Previous edition: %s. Renew your license to restore full functionality.",
				info.EditionName(),
			),
		}
		return degraded
	}

	return &GracefulDegradation{
		IsExpired:    false,
		ActiveLimits: info.Limits,
		Message:      "License active",
	}
}
