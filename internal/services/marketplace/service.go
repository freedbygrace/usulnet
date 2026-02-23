// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Fran Ruiz <fran@usulnet.com>

// Package marketplace provides a curated container app marketplace.
package marketplace

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// AppRepository defines persistence for marketplace apps.
type AppRepository interface {
	Create(ctx context.Context, app *models.MarketplaceApp) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.MarketplaceApp, error)
	GetBySlug(ctx context.Context, slug string) (*models.MarketplaceApp, error)
	Search(ctx context.Context, query string, category string, limit, offset int) ([]*models.MarketplaceApp, int, error)
	ListFeatured(ctx context.Context, limit int) ([]*models.MarketplaceApp, error)
	ListByCategory(ctx context.Context, category string, limit, offset int) ([]*models.MarketplaceApp, int, error)
	Update(ctx context.Context, app *models.MarketplaceApp) error
	Delete(ctx context.Context, id uuid.UUID) error
	IncrementInstallCount(ctx context.Context, id uuid.UUID) error
	UpdateRating(ctx context.Context, id uuid.UUID) error
}

// InstallationRepository defines persistence for marketplace installations.
type InstallationRepository interface {
	Create(ctx context.Context, inst *models.MarketplaceInstallation) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.MarketplaceInstallation, error)
	ListByHost(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]*models.MarketplaceInstallation, int, error)
	ListByApp(ctx context.Context, appID uuid.UUID) ([]*models.MarketplaceInstallation, error)
	Update(ctx context.Context, inst *models.MarketplaceInstallation) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// ReviewRepository defines persistence for marketplace reviews.
type ReviewRepository interface {
	Create(ctx context.Context, review *models.MarketplaceReview) error
	ListByApp(ctx context.Context, appID uuid.UUID) ([]*models.MarketplaceReview, error)
	GetByUserAndApp(ctx context.Context, userID, appID uuid.UUID) (*models.MarketplaceReview, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// Service implements marketplace business logic.
type Service struct {
	apps          AppRepository
	installations InstallationRepository
	reviews       ReviewRepository
	logger        *logger.Logger
}

// NewService creates a new marketplace service.
func NewService(apps AppRepository, installations InstallationRepository, reviews ReviewRepository, log *logger.Logger) *Service {
	return &Service{
		apps:          apps,
		installations: installations,
		reviews:       reviews,
		logger:        log.Named("marketplace"),
	}
}

// ============================================================================
// App browsing
// ============================================================================

// SearchApps searches marketplace apps by query and optional category filter.
func (s *Service) SearchApps(ctx context.Context, query, category string, limit, offset int) ([]*models.MarketplaceApp, int, error) {
	return s.apps.Search(ctx, query, category, limit, offset)
}

// GetApp returns a marketplace app by ID.
func (s *Service) GetApp(ctx context.Context, id uuid.UUID) (*models.MarketplaceApp, error) {
	return s.apps.GetByID(ctx, id)
}

// GetAppBySlug returns a marketplace app by slug.
func (s *Service) GetAppBySlug(ctx context.Context, slug string) (*models.MarketplaceApp, error) {
	return s.apps.GetBySlug(ctx, slug)
}

// ListFeatured returns featured apps.
func (s *Service) ListFeatured(ctx context.Context, limit int) ([]*models.MarketplaceApp, error) {
	return s.apps.ListFeatured(ctx, limit)
}

// ListByCategory returns apps filtered by category.
func (s *Service) ListByCategory(ctx context.Context, category string, limit, offset int) ([]*models.MarketplaceApp, int, error) {
	return s.apps.ListByCategory(ctx, category, limit, offset)
}

// ============================================================================
// App management
// ============================================================================

// CreateApp creates a new marketplace app.
func (s *Service) CreateApp(ctx context.Context, app *models.MarketplaceApp) error {
	if app.Slug == "" {
		app.Slug = generateSlug(app.Name)
	}
	if app.Icon == "" {
		app.Icon = "fa-cube"
	}
	if app.IconColor == "" {
		app.IconColor = "#6c757d"
	}

	if err := s.apps.Create(ctx, app); err != nil {
		return fmt.Errorf("create app: %w", err)
	}

	s.logger.Info("Marketplace app created",
		"app_id", app.ID,
		"slug", app.Slug,
		"name", app.Name)
	return nil
}

// UpdateApp updates a marketplace app.
func (s *Service) UpdateApp(ctx context.Context, app *models.MarketplaceApp) error {
	if err := s.apps.Update(ctx, app); err != nil {
		return fmt.Errorf("update app: %w", err)
	}
	s.logger.Info("Marketplace app updated", "app_id", app.ID)
	return nil
}

// DeleteApp deletes a marketplace app.
func (s *Service) DeleteApp(ctx context.Context, id uuid.UUID) error {
	if err := s.apps.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete app: %w", err)
	}
	s.logger.Info("Marketplace app deleted", "app_id", id)
	return nil
}

// ============================================================================
// Installation management
// ============================================================================

// InstallApp installs a marketplace app on a host.
func (s *Service) InstallApp(ctx context.Context, appID, hostID uuid.UUID, name string, configValues map[string]string, userID *uuid.UUID) (*models.MarketplaceInstallation, error) {
	app, err := s.apps.GetByID(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("get app: %w", err)
	}

	inst := &models.MarketplaceInstallation{
		AppID:       appID,
		HostID:      hostID,
		Name:        name,
		Status:      models.InstallationStatusInstalled,
		Version:     app.Version,
		InstalledBy: userID,
	}

	if err := s.installations.Create(ctx, inst); err != nil {
		return nil, fmt.Errorf("create installation: %w", err)
	}

	// Increment install counter
	_ = s.apps.IncrementInstallCount(ctx, appID)

	s.logger.Info("Marketplace app installed",
		"installation_id", inst.ID,
		"app_id", appID,
		"host_id", hostID,
		"name", name)
	return inst, nil
}

// ListInstallations returns installations for a host.
func (s *Service) ListInstallations(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]*models.MarketplaceInstallation, int, error) {
	return s.installations.ListByHost(ctx, hostID, limit, offset)
}

// GetInstallation returns an installation by ID.
func (s *Service) GetInstallation(ctx context.Context, id uuid.UUID) (*models.MarketplaceInstallation, error) {
	return s.installations.GetByID(ctx, id)
}

// UninstallApp removes a marketplace installation.
func (s *Service) UninstallApp(ctx context.Context, id uuid.UUID) error {
	inst, err := s.installations.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("get installation: %w", err)
	}

	inst.Status = models.InstallationStatusUninstalled
	if err := s.installations.Update(ctx, inst); err != nil {
		return fmt.Errorf("update installation status: %w", err)
	}

	s.logger.Info("Marketplace app uninstalled",
		"installation_id", id,
		"app_id", inst.AppID)
	return nil
}

// ============================================================================
// Reviews
// ============================================================================

// AddReview adds or updates a user review for an app.
func (s *Service) AddReview(ctx context.Context, review *models.MarketplaceReview) error {
	if err := s.reviews.Create(ctx, review); err != nil {
		return fmt.Errorf("create review: %w", err)
	}
	// Update app rating aggregate
	_ = s.apps.UpdateRating(ctx, review.AppID)

	s.logger.Info("Marketplace review added",
		"app_id", review.AppID,
		"user_id", review.UserID,
		"rating", review.Rating)
	return nil
}

// ListReviews returns all reviews for an app.
func (s *Service) ListReviews(ctx context.Context, appID uuid.UUID) ([]*models.MarketplaceReview, error) {
	return s.reviews.ListByApp(ctx, appID)
}

// DeleteReview deletes a review.
func (s *Service) DeleteReview(ctx context.Context, id uuid.UUID) error {
	if err := s.reviews.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete review: %w", err)
	}
	return nil
}

// ============================================================================
// Helpers
// ============================================================================

// generateSlug creates a URL-safe slug from a name.
func generateSlug(name string) string {
	slug := strings.ToLower(name)
	slug = strings.ReplaceAll(slug, " ", "-")
	slug = strings.ReplaceAll(slug, "_", "-")
	// Remove non-alphanumeric/dash characters
	var clean []byte
	for _, b := range []byte(slug) {
		if (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-' {
			clean = append(clean, b)
		}
	}
	return string(clean)
}
