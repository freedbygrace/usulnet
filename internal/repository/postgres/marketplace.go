// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// MarketplaceAppRepository
// ============================================================================

type MarketplaceAppRepository struct {
	db     *DB
	logger *logger.Logger
}

func NewMarketplaceAppRepository(db *DB, log *logger.Logger) *MarketplaceAppRepository {
	return &MarketplaceAppRepository{
		db:     db,
		logger: log.Named("repo.marketplace_apps"),
	}
}

func (r *MarketplaceAppRepository) Create(ctx context.Context, app *models.MarketplaceApp) error {
	if app.ID == uuid.Nil {
		app.ID = uuid.New()
	}
	now := time.Now()
	if app.CreatedAt.IsZero() {
		app.CreatedAt = now
	}
	app.UpdatedAt = now

	_, err := r.db.Pool().Exec(ctx, `
		INSERT INTO marketplace_apps (
			id, slug, name, description, long_description,
			icon, icon_color, category, version, website, source,
			author, license, compose_template, fields, tags,
			min_memory_mb, min_cpu_cores, is_official, is_verified, featured,
			install_count, avg_rating, rating_count,
			created_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27)`,
		app.ID, app.Slug, app.Name, app.Description, app.LongDescription,
		app.Icon, app.IconColor, app.Category, app.Version, app.Website, app.Source,
		app.Author, app.License, app.ComposeTemplate, app.Fields, app.Tags,
		app.MinMemoryMB, app.MinCPUCores, app.IsOfficial, app.IsVerified, app.Featured,
		app.InstallCount, app.AvgRating, app.RatingCount,
		app.CreatedBy, app.CreatedAt, app.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "create marketplace app")
	}
	return nil
}

func (r *MarketplaceAppRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.MarketplaceApp, error) {
	var app models.MarketplaceApp
	err := r.db.Pool().QueryRow(ctx, `
		SELECT id, slug, name, description, long_description,
			icon, icon_color, category, version, website, source,
			author, license, compose_template, fields, tags,
			min_memory_mb, min_cpu_cores, is_official, is_verified, featured,
			install_count, avg_rating, rating_count,
			created_by, created_at, updated_at
		FROM marketplace_apps WHERE id = $1`, id,
	).Scan(
		&app.ID, &app.Slug, &app.Name, &app.Description, &app.LongDescription,
		&app.Icon, &app.IconColor, &app.Category, &app.Version, &app.Website, &app.Source,
		&app.Author, &app.License, &app.ComposeTemplate, &app.Fields, &app.Tags,
		&app.MinMemoryMB, &app.MinCPUCores, &app.IsOfficial, &app.IsVerified, &app.Featured,
		&app.InstallCount, &app.AvgRating, &app.RatingCount,
		&app.CreatedBy, &app.CreatedAt, &app.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("marketplace_app")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "get marketplace app")
	}
	return &app, nil
}

func (r *MarketplaceAppRepository) GetBySlug(ctx context.Context, slug string) (*models.MarketplaceApp, error) {
	var app models.MarketplaceApp
	err := r.db.Pool().QueryRow(ctx, `
		SELECT id, slug, name, description, long_description,
			icon, icon_color, category, version, website, source,
			author, license, compose_template, fields, tags,
			min_memory_mb, min_cpu_cores, is_official, is_verified, featured,
			install_count, avg_rating, rating_count,
			created_by, created_at, updated_at
		FROM marketplace_apps WHERE slug = $1`, slug,
	).Scan(
		&app.ID, &app.Slug, &app.Name, &app.Description, &app.LongDescription,
		&app.Icon, &app.IconColor, &app.Category, &app.Version, &app.Website, &app.Source,
		&app.Author, &app.License, &app.ComposeTemplate, &app.Fields, &app.Tags,
		&app.MinMemoryMB, &app.MinCPUCores, &app.IsOfficial, &app.IsVerified, &app.Featured,
		&app.InstallCount, &app.AvgRating, &app.RatingCount,
		&app.CreatedBy, &app.CreatedAt, &app.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("marketplace_app")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "get marketplace app by slug")
	}
	return &app, nil
}

func (r *MarketplaceAppRepository) Search(ctx context.Context, query string, category string, limit, offset int) ([]*models.MarketplaceApp, int, error) {
	var total int
	args := []interface{}{}
	countSQL := `SELECT COUNT(*) FROM marketplace_apps WHERE 1=1`
	listSQL := `
		SELECT id, slug, name, description, long_description,
			icon, icon_color, category, version, website, source,
			author, license, compose_template, fields, tags,
			min_memory_mb, min_cpu_cores, is_official, is_verified, featured,
			install_count, avg_rating, rating_count,
			created_by, created_at, updated_at
		FROM marketplace_apps WHERE 1=1`

	paramIdx := 1

	if query != "" {
		filter := ` AND (name ILIKE $` + strconv.Itoa(paramIdx) + ` OR description ILIKE $` + strconv.Itoa(paramIdx) + `)`
		countSQL += filter
		listSQL += filter
		args = append(args, "%"+query+"%")
		paramIdx++
	}

	if category != "" {
		filter := ` AND category = $` + strconv.Itoa(paramIdx)
		countSQL += filter
		listSQL += filter
		args = append(args, category)
		paramIdx++
	}

	err := r.db.Pool().QueryRow(ctx, countSQL, args...).Scan(&total)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "count marketplace apps search")
	}

	listSQL += ` ORDER BY install_count DESC LIMIT $` + strconv.Itoa(paramIdx) + ` OFFSET $` + strconv.Itoa(paramIdx+1)
	args = append(args, limit, offset)

	rows, err := r.db.Pool().Query(ctx, listSQL, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "search marketplace apps")
	}
	defer rows.Close()

	var results []*models.MarketplaceApp
	for rows.Next() {
		var app models.MarketplaceApp
		if err := rows.Scan(
			&app.ID, &app.Slug, &app.Name, &app.Description, &app.LongDescription,
			&app.Icon, &app.IconColor, &app.Category, &app.Version, &app.Website, &app.Source,
			&app.Author, &app.License, &app.ComposeTemplate, &app.Fields, &app.Tags,
			&app.MinMemoryMB, &app.MinCPUCores, &app.IsOfficial, &app.IsVerified, &app.Featured,
			&app.InstallCount, &app.AvgRating, &app.RatingCount,
			&app.CreatedBy, &app.CreatedAt, &app.UpdatedAt,
		); err != nil {
			return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "scan marketplace app")
		}
		results = append(results, &app)
	}
	return results, total, nil
}

func (r *MarketplaceAppRepository) ListFeatured(ctx context.Context, limit int) ([]*models.MarketplaceApp, error) {
	rows, err := r.db.Pool().Query(ctx, `
		SELECT id, slug, name, description, long_description,
			icon, icon_color, category, version, website, source,
			author, license, compose_template, fields, tags,
			min_memory_mb, min_cpu_cores, is_official, is_verified, featured,
			install_count, avg_rating, rating_count,
			created_by, created_at, updated_at
		FROM marketplace_apps WHERE featured = true
		ORDER BY install_count DESC LIMIT $1`, limit,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "list featured marketplace apps")
	}
	defer rows.Close()

	var results []*models.MarketplaceApp
	for rows.Next() {
		var app models.MarketplaceApp
		if err := rows.Scan(
			&app.ID, &app.Slug, &app.Name, &app.Description, &app.LongDescription,
			&app.Icon, &app.IconColor, &app.Category, &app.Version, &app.Website, &app.Source,
			&app.Author, &app.License, &app.ComposeTemplate, &app.Fields, &app.Tags,
			&app.MinMemoryMB, &app.MinCPUCores, &app.IsOfficial, &app.IsVerified, &app.Featured,
			&app.InstallCount, &app.AvgRating, &app.RatingCount,
			&app.CreatedBy, &app.CreatedAt, &app.UpdatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "scan featured marketplace app")
		}
		results = append(results, &app)
	}
	return results, nil
}

func (r *MarketplaceAppRepository) ListByCategory(ctx context.Context, category string, limit, offset int) ([]*models.MarketplaceApp, int, error) {
	var total int
	err := r.db.Pool().QueryRow(ctx,
		`SELECT COUNT(*) FROM marketplace_apps WHERE category = $1`, category,
	).Scan(&total)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "count marketplace apps by category")
	}

	rows, err := r.db.Pool().Query(ctx, `
		SELECT id, slug, name, description, long_description,
			icon, icon_color, category, version, website, source,
			author, license, compose_template, fields, tags,
			min_memory_mb, min_cpu_cores, is_official, is_verified, featured,
			install_count, avg_rating, rating_count,
			created_by, created_at, updated_at
		FROM marketplace_apps WHERE category = $1
		ORDER BY install_count DESC LIMIT $2 OFFSET $3`, category, limit, offset,
	)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "list marketplace apps by category")
	}
	defer rows.Close()

	var results []*models.MarketplaceApp
	for rows.Next() {
		var app models.MarketplaceApp
		if err := rows.Scan(
			&app.ID, &app.Slug, &app.Name, &app.Description, &app.LongDescription,
			&app.Icon, &app.IconColor, &app.Category, &app.Version, &app.Website, &app.Source,
			&app.Author, &app.License, &app.ComposeTemplate, &app.Fields, &app.Tags,
			&app.MinMemoryMB, &app.MinCPUCores, &app.IsOfficial, &app.IsVerified, &app.Featured,
			&app.InstallCount, &app.AvgRating, &app.RatingCount,
			&app.CreatedBy, &app.CreatedAt, &app.UpdatedAt,
		); err != nil {
			return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "scan marketplace app by category")
		}
		results = append(results, &app)
	}
	return results, total, nil
}

func (r *MarketplaceAppRepository) Update(ctx context.Context, app *models.MarketplaceApp) error {
	app.UpdatedAt = time.Now()
	_, err := r.db.Pool().Exec(ctx, `
		UPDATE marketplace_apps SET
			slug = $2, name = $3, description = $4, long_description = $5,
			icon = $6, icon_color = $7, category = $8, version = $9,
			website = $10, source = $11, author = $12, license = $13,
			compose_template = $14, fields = $15, tags = $16,
			min_memory_mb = $17, min_cpu_cores = $18,
			is_official = $19, is_verified = $20, featured = $21,
			updated_at = $22
		WHERE id = $1`,
		app.ID, app.Slug, app.Name, app.Description, app.LongDescription,
		app.Icon, app.IconColor, app.Category, app.Version,
		app.Website, app.Source, app.Author, app.License,
		app.ComposeTemplate, app.Fields, app.Tags,
		app.MinMemoryMB, app.MinCPUCores,
		app.IsOfficial, app.IsVerified, app.Featured,
		app.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "update marketplace app")
	}
	return nil
}

func (r *MarketplaceAppRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Pool().Exec(ctx, `DELETE FROM marketplace_apps WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "delete marketplace app")
	}
	return nil
}

func (r *MarketplaceAppRepository) IncrementInstallCount(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Pool().Exec(ctx,
		`UPDATE marketplace_apps SET install_count = install_count + 1 WHERE id = $1`, id,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "increment marketplace app install count")
	}
	return nil
}

func (r *MarketplaceAppRepository) UpdateRating(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Pool().Exec(ctx, `
		UPDATE marketplace_apps SET
			avg_rating = COALESCE((SELECT AVG(rating)::FLOAT FROM marketplace_reviews WHERE app_id = $1), 0),
			rating_count = (SELECT COUNT(*) FROM marketplace_reviews WHERE app_id = $1)
		WHERE id = $1`, id,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "update marketplace app rating")
	}
	return nil
}

// ============================================================================
// MarketplaceInstallationRepository
// ============================================================================

type MarketplaceInstallationRepository struct {
	db     *DB
	logger *logger.Logger
}

func NewMarketplaceInstallationRepository(db *DB, log *logger.Logger) *MarketplaceInstallationRepository {
	return &MarketplaceInstallationRepository{
		db:     db,
		logger: log.Named("repo.marketplace_installations"),
	}
}

func (r *MarketplaceInstallationRepository) Create(ctx context.Context, inst *models.MarketplaceInstallation) error {
	if inst.ID == uuid.Nil {
		inst.ID = uuid.New()
	}
	now := time.Now()
	if inst.InstalledAt.IsZero() {
		inst.InstalledAt = now
	}
	inst.UpdatedAt = now

	_, err := r.db.Pool().Exec(ctx, `
		INSERT INTO marketplace_installations (
			id, app_id, host_id, stack_id, name,
			status, version, config_values, notes,
			installed_by, installed_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		inst.ID, inst.AppID, inst.HostID, inst.StackID, inst.Name,
		inst.Status, inst.Version, inst.ConfigValues, inst.Notes,
		inst.InstalledBy, inst.InstalledAt, inst.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "create marketplace installation")
	}
	return nil
}

func (r *MarketplaceInstallationRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.MarketplaceInstallation, error) {
	var inst models.MarketplaceInstallation
	err := r.db.Pool().QueryRow(ctx, `
		SELECT id, app_id, host_id, stack_id, name,
			status, version, config_values, notes,
			installed_by, installed_at, updated_at
		FROM marketplace_installations WHERE id = $1`, id,
	).Scan(
		&inst.ID, &inst.AppID, &inst.HostID, &inst.StackID, &inst.Name,
		&inst.Status, &inst.Version, &inst.ConfigValues, &inst.Notes,
		&inst.InstalledBy, &inst.InstalledAt, &inst.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("marketplace_installation")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "get marketplace installation")
	}
	return &inst, nil
}

func (r *MarketplaceInstallationRepository) ListByHost(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]*models.MarketplaceInstallation, int, error) {
	var total int
	err := r.db.Pool().QueryRow(ctx,
		`SELECT COUNT(*) FROM marketplace_installations WHERE host_id = $1`, hostID,
	).Scan(&total)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "count marketplace installations by host")
	}

	rows, err := r.db.Pool().Query(ctx, `
		SELECT mi.id, mi.app_id, mi.host_id, mi.stack_id, mi.name,
			mi.status, mi.version, mi.config_values, mi.notes,
			mi.installed_by, mi.installed_at, mi.updated_at
		FROM marketplace_installations mi
		JOIN marketplace_apps ma ON ma.id = mi.app_id
		WHERE mi.host_id = $1
		ORDER BY mi.installed_at DESC LIMIT $2 OFFSET $3`, hostID, limit, offset,
	)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "list marketplace installations by host")
	}
	defer rows.Close()

	var results []*models.MarketplaceInstallation
	for rows.Next() {
		var inst models.MarketplaceInstallation
		if err := rows.Scan(
			&inst.ID, &inst.AppID, &inst.HostID, &inst.StackID, &inst.Name,
			&inst.Status, &inst.Version, &inst.ConfigValues, &inst.Notes,
			&inst.InstalledBy, &inst.InstalledAt, &inst.UpdatedAt,
		); err != nil {
			return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "scan marketplace installation")
		}
		results = append(results, &inst)
	}
	return results, total, nil
}

func (r *MarketplaceInstallationRepository) ListByApp(ctx context.Context, appID uuid.UUID) ([]*models.MarketplaceInstallation, error) {
	rows, err := r.db.Pool().Query(ctx, `
		SELECT id, app_id, host_id, stack_id, name,
			status, version, config_values, notes,
			installed_by, installed_at, updated_at
		FROM marketplace_installations WHERE app_id = $1
		ORDER BY installed_at DESC`, appID,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "list marketplace installations by app")
	}
	defer rows.Close()

	var results []*models.MarketplaceInstallation
	for rows.Next() {
		var inst models.MarketplaceInstallation
		if err := rows.Scan(
			&inst.ID, &inst.AppID, &inst.HostID, &inst.StackID, &inst.Name,
			&inst.Status, &inst.Version, &inst.ConfigValues, &inst.Notes,
			&inst.InstalledBy, &inst.InstalledAt, &inst.UpdatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "scan marketplace installation by app")
		}
		results = append(results, &inst)
	}
	return results, nil
}

func (r *MarketplaceInstallationRepository) Update(ctx context.Context, inst *models.MarketplaceInstallation) error {
	inst.UpdatedAt = time.Now()
	_, err := r.db.Pool().Exec(ctx, `
		UPDATE marketplace_installations SET
			stack_id = $2, name = $3, status = $4, version = $5,
			config_values = $6, notes = $7, updated_at = $8
		WHERE id = $1`,
		inst.ID, inst.StackID, inst.Name, inst.Status, inst.Version,
		inst.ConfigValues, inst.Notes, inst.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "update marketplace installation")
	}
	return nil
}

func (r *MarketplaceInstallationRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Pool().Exec(ctx, `DELETE FROM marketplace_installations WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "delete marketplace installation")
	}
	return nil
}

// ============================================================================
// MarketplaceReviewRepository
// ============================================================================

type MarketplaceReviewRepository struct {
	db     *DB
	logger *logger.Logger
}

func NewMarketplaceReviewRepository(db *DB, log *logger.Logger) *MarketplaceReviewRepository {
	return &MarketplaceReviewRepository{
		db:     db,
		logger: log.Named("repo.marketplace_reviews"),
	}
}

func (r *MarketplaceReviewRepository) Create(ctx context.Context, review *models.MarketplaceReview) error {
	if review.ID == uuid.Nil {
		review.ID = uuid.New()
	}
	now := time.Now()
	if review.CreatedAt.IsZero() {
		review.CreatedAt = now
	}
	review.UpdatedAt = now

	_, err := r.db.Pool().Exec(ctx, `
		INSERT INTO marketplace_reviews (
			id, app_id, user_id, rating, title, comment,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		review.ID, review.AppID, review.UserID, review.Rating, review.Title, review.Comment,
		review.CreatedAt, review.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "create marketplace review")
	}
	return nil
}

func (r *MarketplaceReviewRepository) ListByApp(ctx context.Context, appID uuid.UUID) ([]*models.MarketplaceReview, error) {
	rows, err := r.db.Pool().Query(ctx, `
		SELECT id, app_id, user_id, rating, title, comment,
			created_at, updated_at
		FROM marketplace_reviews WHERE app_id = $1
		ORDER BY created_at DESC`, appID,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "list marketplace reviews by app")
	}
	defer rows.Close()

	var results []*models.MarketplaceReview
	for rows.Next() {
		var review models.MarketplaceReview
		if err := rows.Scan(
			&review.ID, &review.AppID, &review.UserID, &review.Rating, &review.Title, &review.Comment,
			&review.CreatedAt, &review.UpdatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "scan marketplace review")
		}
		results = append(results, &review)
	}
	return results, nil
}

func (r *MarketplaceReviewRepository) GetByUserAndApp(ctx context.Context, userID, appID uuid.UUID) (*models.MarketplaceReview, error) {
	var review models.MarketplaceReview
	err := r.db.Pool().QueryRow(ctx, `
		SELECT id, app_id, user_id, rating, title, comment,
			created_at, updated_at
		FROM marketplace_reviews WHERE user_id = $1 AND app_id = $2`, userID, appID,
	).Scan(
		&review.ID, &review.AppID, &review.UserID, &review.Rating, &review.Title, &review.Comment,
		&review.CreatedAt, &review.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("marketplace_review")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "get marketplace review by user and app")
	}
	return &review, nil
}

func (r *MarketplaceReviewRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Pool().Exec(ctx, `DELETE FROM marketplace_reviews WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "delete marketplace review")
	}
	return nil
}
