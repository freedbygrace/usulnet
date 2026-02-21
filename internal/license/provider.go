// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package license

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"
)

type Logger interface {
	Info(msg string, keysAndValues ...any)
	Warn(msg string, keysAndValues ...any)
	Error(msg string, keysAndValues ...any)
}

type Provider struct {
	mu               sync.RWMutex
	info             *Info
	rawJWT           string
	rawReceipt       string
	validator        *Validator
	store            *Store
	receiptStore     *ReceiptStore
	activationClient *ActivationClient
	instanceID       string
	logger           Logger
	stopCh           chan struct{}
}

func NewProvider(dataDir string, logger Logger) (*Provider, error) {
	validator, err := NewValidator()
	if err != nil {
		return nil, fmt.Errorf("license provider: %w", err)
	}

	instanceID, err := GenerateInstanceID(dataDir)
	if err != nil {
		logger.Warn("license: could not generate instance ID, continuing without", "error", err)
		instanceID = "unknown"
	}

	store := NewStore(dataDir)
	receiptStore := NewReceiptStore(dataDir)
	activationClient := NewActivationClient()

	p := &Provider{
		info:             NewCEInfo(),
		validator:        validator,
		store:            store,
		receiptStore:     receiptStore,
		activationClient: activationClient,
		instanceID:       instanceID,
		logger:           logger,
		stopCh:           make(chan struct{}),
	}

	rawJWT, err := store.Load()
	if err != nil {
		logger.Warn("license: failed to load stored license", "error", err)
	} else if rawJWT != "" {
		rawReceipt, _ := receiptStore.Load()
		if err := p.loadWithReceipt(rawJWT, rawReceipt); err != nil {
			logger.Warn("license: stored license is invalid, falling back to CE", "error", err)
		} else {
			p.mu.RLock()
			info := p.info
			p.mu.RUnlock()
			logger.Info("license: loaded stored license",
				"edition", info.Edition,
				"license_id", info.LicenseID,
				"expires_at", info.ExpiresAt,
				"has_receipt", p.rawReceipt != "",
				"sync_warning", info.SyncWarning,
			)
		}
	}

	go p.backgroundValidator()

	return p, nil
}

func (p *Provider) loadWithReceipt(rawJWT, rawReceipt string) error {
	claims, err := p.validator.Validate(rawJWT)
	if err != nil {
		return err
	}

	info := ClaimsToInfo(claims, p.instanceID)
	if !info.Valid {
		return fmt.Errorf("license: token is expired")
	}

	if rawReceipt != "" {
		receiptClaims, receiptErr := p.validator.ValidateReceipt(rawReceipt, p.instanceID)
		if receiptErr == nil {
			info.Limits = receiptClaims.Limits.ToLimits()
			info.Features = resolveFeatures(receiptClaims.Features, info.Features)
			if receiptClaims.ExpiresAt != nil {
				t := receiptClaims.ExpiresAt.Time
				info.LastCheckinAt = &t
			}
		} else {
			expiredClaims, parseErr := p.validator.ParseReceiptClaims(rawReceipt)
			if parseErr == nil && expiredClaims.ExpiresAt != nil {
				receiptExp := expiredClaims.ExpiresAt.Time
				now := time.Now()
				degradeAt := receiptExp.Add(SyncGracePeriod)

				if now.After(degradeAt) {
					p.logger.Warn("license: activation receipt expired and grace period elapsed, reverting to CE",
						"license_id", claims.LicenseID,
						"receipt_expired_at", receiptExp,
						"grace_expired_at", degradeAt,
					)
					p.mu.Lock()
					p.info = NewCEInfo()
					p.rawJWT = ""
					p.rawReceipt = ""
					p.mu.Unlock()
					return nil
				}

				info.SyncWarning = true
				info.SyncDegradationAt = &degradeAt
				info.LastCheckinAt = &receiptExp
			} else {
				p.logger.Warn("license: activation receipt unreadable, attempting auto-activation",
					"error", parseErr)
				rawReceipt = ""
			}
		}
	}

	if rawReceipt == "" {
		hostname, _ := os.Hostname()
		receiptJWT, activateErr := p.activationClient.ActivateOnServer(claims.LicenseID, p.instanceID, hostname)
		if activateErr == nil {
			receiptClaims, validateErr := p.validator.ValidateReceipt(receiptJWT, p.instanceID)
			if validateErr == nil {
				info.Limits = receiptClaims.Limits.ToLimits()
				info.Features = resolveFeatures(receiptClaims.Features, info.Features)
				_ = p.receiptStore.Save(receiptJWT)
				rawReceipt = receiptJWT
				now := time.Now()
				info.LastCheckinAt = &now
				p.logger.Info("license: auto-activated with server", "license_id", claims.LicenseID)
			}
		} else {
			p.logger.Warn("license: no activation receipt found, grace period active",
				"license_id", claims.LicenseID,
				"error", activateErr,
			)
			now := time.Now()
			degradeAt := now.Add(SyncGracePeriod * 2)
			info.SyncWarning = true
			info.SyncDegradationAt = &degradeAt
		}
	}

	p.mu.Lock()
	p.info = info
	p.rawJWT = rawJWT
	p.rawReceipt = rawReceipt
	p.mu.Unlock()

	return nil
}

func (p *Provider) Activate(licenseKey string) error {
	claims, err := p.validator.Validate(licenseKey)
	if err != nil {
		return err
	}

	info := ClaimsToInfo(claims, p.instanceID)
	if !info.Valid {
		return fmt.Errorf("license: token is expired")
	}

	hostname, _ := os.Hostname()
	receiptJWT, err := p.activationClient.ActivateOnServer(claims.LicenseID, p.instanceID, hostname)
	if err != nil {
		return fmt.Errorf("license: %w", err)
	}

	receiptClaims, err := p.validator.ValidateReceipt(receiptJWT, p.instanceID)
	if err != nil {
		return fmt.Errorf("license: server returned an invalid activation receipt: %w", err)
	}

	info.Limits = receiptClaims.Limits.ToLimits()
	info.Features = resolveFeatures(receiptClaims.Features, info.Features)
	now := time.Now()
	info.ActivatedAt = &now
	info.LastCheckinAt = &now

	if err := p.store.Save(licenseKey); err != nil {
		p.logger.Error("license: failed to persist license JWT to disk", "error", err)
	}
	if err := p.receiptStore.Save(receiptJWT); err != nil {
		p.logger.Error("license: failed to persist activation receipt to disk", "error", err)
	}

	p.mu.Lock()
	p.info = info
	p.rawJWT = licenseKey
	p.rawReceipt = receiptJWT
	p.mu.Unlock()

	p.logger.Info("license: activated",
		"edition", info.Edition,
		"license_id", info.LicenseID,
		"nodes", info.Limits.MaxNodes,
		"users", info.Limits.MaxUsers,
		"instance_id", p.instanceID,
	)

	return nil
}

func (p *Provider) Deactivate() error {
	p.mu.RLock()
	rawJWT := p.rawJWT
	currentLicenseID := p.info.LicenseID
	p.mu.RUnlock()

	if rawJWT != "" && currentLicenseID != "" {
		if err := p.activationClient.DeactivateOnServer(currentLicenseID, p.instanceID); err != nil {
			p.logger.Warn("license: failed to notify server of deactivation (continuing anyway)", "error", err)
		}
	}

	return p.deactivateLocally()
}

func (p *Provider) deactivateLocally() error {
	p.mu.Lock()
	p.info = NewCEInfo()
	p.rawJWT = ""
	p.rawReceipt = ""
	p.mu.Unlock()

	if err := p.store.Remove(); err != nil {
		p.logger.Error("license: failed to remove license file", "error", err)
	}
	if err := p.receiptStore.Remove(); err != nil {
		p.logger.Error("license: failed to remove receipt file", "error", err)
	}

	p.logger.Info("license: deactivated, reverted to CE")
	return nil
}

func (p *Provider) GetInfo() *Info {
	p.mu.RLock()
	defer p.mu.RUnlock()
	cp := *p.info
	return &cp
}

func (p *Provider) GetLicense(ctx context.Context) (*Info, error) {
	return p.GetInfo(), nil
}

func (p *Provider) HasFeature(ctx context.Context, feature Feature) bool {
	return p.GetInfo().HasFeature(feature)
}

func (p *Provider) IsValid(ctx context.Context) bool {
	info := p.GetInfo()
	return info.Valid && !info.IsExpired()
}

func (p *Provider) GetLimits() Limits {
	return p.GetInfo().Limits
}

func (p *Provider) Edition() Edition {
	return p.GetInfo().Edition
}

func (p *Provider) InstanceID() string {
	return p.instanceID
}

func (p *Provider) RawJWT() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.rawJWT
}

func (p *Provider) Stop() {
	close(p.stopCh)
}

func (p *Provider) backgroundValidator() {
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.mu.RLock()
			rawJWT := p.rawJWT
			rawReceipt := p.rawReceipt
			currentLicenseID := p.info.LicenseID
			p.mu.RUnlock()

			if rawJWT == "" {
				continue
			}

			claims, err := p.validator.Validate(rawJWT)
			if err != nil {
				p.logger.Warn("license: background re-validation failed", "error", err)
				p.mu.Lock()
				p.info.Valid = false
				p.mu.Unlock()
				continue
			}

			checkinResult, checkinErr := p.activationClient.Checkin(currentLicenseID, p.instanceID)
			if checkinErr == nil {
				if checkinResult.Revoked {
					p.logger.Warn("license: server reports license revoked, reverting to CE",
						"license_id", currentLicenseID)
					p.deactivateLocally()
					continue
				}

				if checkinResult.DeactivationPending {
					p.logger.Info("license: remote deactivation requested, reverting to CE",
						"license_id", currentLicenseID)
					_ = p.activationClient.ConfirmDeactivation(currentLicenseID, p.instanceID)
					p.deactivateLocally()
					continue
				}

				if checkinResult.Receipt != "" {
					receiptClaims, receiptErr := p.validator.ValidateReceipt(checkinResult.Receipt, p.instanceID)
					if receiptErr != nil {
						p.logger.Warn("license: server returned invalid receipt on checkin", "error", receiptErr)
					} else {
						info := ClaimsToInfo(claims, p.instanceID)
						info.Limits = receiptClaims.Limits.ToLimits()
						info.Features = resolveFeatures(receiptClaims.Features, info.Features)
						now := time.Now()
						info.LastCheckinAt = &now

						p.mu.RLock()
						if p.info != nil {
							info.ActivatedAt = p.info.ActivatedAt
						}
						p.mu.RUnlock()

						_ = p.receiptStore.Save(checkinResult.Receipt)

						p.mu.Lock()
						p.info = info
						p.rawReceipt = checkinResult.Receipt
						p.mu.Unlock()

						p.logger.Info("license: checkin successful, receipt refreshed",
							"license_id", currentLicenseID)
					}
				}

			} else {
				p.logger.Warn("license: checkin failed (server unreachable)", "error", checkinErr)

				info := ClaimsToInfo(claims, p.instanceID)
				now := time.Now()

				if rawReceipt != "" {
					expiredClaims, parseErr := p.validator.ParseReceiptClaims(rawReceipt)
					if parseErr == nil && expiredClaims.ExpiresAt != nil {
						receiptExp := expiredClaims.ExpiresAt.Time
						degradeAt := receiptExp.Add(SyncGracePeriod)

						if now.After(degradeAt) {
							p.logger.Warn("license: sync grace period expired, reverting to CE",
								"license_id", currentLicenseID,
								"receipt_expired_at", receiptExp,
							)
							p.deactivateLocally()
							continue
						} else if now.After(receiptExp) {
							info.SyncWarning = true
							info.SyncDegradationAt = &degradeAt
						}
					}
				} else {
					degradeAt := now.Add(SyncGracePeriod)
					info.SyncWarning = true
					info.SyncDegradationAt = &degradeAt
				}

				p.mu.RLock()
				if p.info != nil {
					info.ActivatedAt = p.info.ActivatedAt
					info.LastCheckinAt = p.info.LastCheckinAt
				}
				p.mu.RUnlock()

				p.mu.Lock()
				p.info = info
				p.mu.Unlock()

				if !info.Valid {
					p.logger.Warn("license: license has expired",
						"license_id", info.LicenseID,
						"expired_at", info.ExpiresAt,
					)
				}
			}
		}
	}
}
