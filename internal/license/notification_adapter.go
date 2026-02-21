package license

import (
	"context"
	"fmt"
)

type NotificationSender interface {
	SendLicenseExpiring(ctx context.Context, edition, licenseID string, daysRemaining int) error
	SendLicenseExpired(ctx context.Context, edition, licenseID string) error
	SendResourceLimitApproaching(ctx context.Context, resource string, current, limit int, percentUsed float64) error
}

type NotificationAdapter struct {
	sender NotificationSender
}

func NewNotificationAdapter(sender NotificationSender) *NotificationAdapter {
	return &NotificationAdapter{sender: sender}
}

func (a *NotificationAdapter) NotifyLicenseExpiring(ctx context.Context, info *Info, daysRemaining int) error {
	if a.sender == nil {
		return nil
	}
	return a.sender.SendLicenseExpiring(ctx, string(info.Edition), info.LicenseID, daysRemaining)
}

func (a *NotificationAdapter) NotifyLicenseExpired(ctx context.Context, info *Info) error {
	if a.sender == nil {
		return nil
	}
	return a.sender.SendLicenseExpired(ctx, string(info.Edition), info.LicenseID)
}

func (a *NotificationAdapter) NotifyLimitApproaching(ctx context.Context, resource string, current, limit int) error {
	if a.sender == nil {
		return nil
	}
	percentUsed := 0.0
	if limit > 0 {
		percentUsed = float64(current) / float64(limit) * 100
	}
	return a.sender.SendResourceLimitApproaching(ctx, resource, current, limit, percentUsed)
}

var _ ExpirationNotifier = (*NotificationAdapter)(nil)

type LimitProximityChecker struct {
	provider  *Provider
	notifier  ExpirationNotifier
	logger    Logger
	threshold float64
}

func NewLimitProximityChecker(
	provider *Provider,
	notifier ExpirationNotifier,
	logger Logger,
	thresholdPercent float64,
) *LimitProximityChecker {
	if thresholdPercent <= 0 || thresholdPercent > 100 {
		thresholdPercent = 80
	}
	return &LimitProximityChecker{
		provider:  provider,
		notifier:  notifier,
		logger:    logger,
		threshold: thresholdPercent,
	}
}

func (lpc *LimitProximityChecker) CheckResourceProximity(
	ctx context.Context,
	resource string,
	current int,
	limit int,
) bool {
	if limit <= 0 {
		return false
	}

	percentUsed := float64(current) / float64(limit) * 100
	if percentUsed >= lpc.threshold {
		lpc.logger.Warn(fmt.Sprintf("license: resource %q at %.0f%% capacity (%d/%d)",
			resource, percentUsed, current, limit))

		if err := lpc.notifier.NotifyLimitApproaching(ctx, resource, current, limit); err != nil {
			lpc.logger.Error("license: failed to send limit proximity notification",
				"resource", resource, "error", err)
		}
		return true
	}
	return false
}
