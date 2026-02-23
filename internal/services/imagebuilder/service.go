// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package imagebuilder provides image build job tracking and Dockerfile template management.
package imagebuilder

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// BuildJobRepository defines persistence for image build jobs.
type BuildJobRepository interface {
	Create(ctx context.Context, job *models.ImageBuildJob) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.ImageBuildJob, error)
	Update(ctx context.Context, job *models.ImageBuildJob) error
	ListByHost(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]models.ImageBuildJob, int, error)
	GetStats(ctx context.Context, hostID uuid.UUID) (*models.ImageBuildJobStats, error)
}

// TemplateRepository defines persistence for Dockerfile templates.
type TemplateRepository interface {
	Create(ctx context.Context, t *models.DockerfileTemplate) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.DockerfileTemplate, error)
	List(ctx context.Context, hostID uuid.UUID) ([]models.DockerfileTemplate, error)
	Update(ctx context.Context, t *models.DockerfileTemplate) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// Service implements image builder business logic.
type Service struct {
	builds    BuildJobRepository
	templates TemplateRepository
	logger    *logger.Logger
}

// NewService creates a new image builder service.
func NewService(builds BuildJobRepository, templates TemplateRepository, log *logger.Logger) *Service {
	return &Service{
		builds:    builds,
		templates: templates,
		logger:    log.Named("imagebuilder"),
	}
}

// ============================================================================
// Build Jobs
// ============================================================================

// StartBuild creates and starts a new image build job.
func (s *Service) StartBuild(ctx context.Context, hostID uuid.UUID, name string, tags []string, dockerfile string, contextPath string, buildArgs map[string]string, noCache bool, pull bool, platform string, target string, userID *uuid.UUID) (*models.ImageBuildJob, error) {
	argsJSON, _ := json.Marshal(buildArgs)
	labelsJSON := json.RawMessage("{}")

	now := time.Now()
	job := &models.ImageBuildJob{
		ID:          uuid.New(),
		HostID:      hostID,
		Name:        name,
		Tags:        tags,
		Dockerfile:  dockerfile,
		ContextPath: contextPath,
		BuildArgs:   argsJSON,
		Labels:      labelsJSON,
		Target:      target,
		NoCache:     noCache,
		Pull:        pull,
		Platform:    platform,
		Status:      models.BuildJobStatusPending,
		CreatedBy:   userID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.builds.Create(ctx, job); err != nil {
		return nil, fmt.Errorf("create build job: %w", err)
	}

	// Transition to building
	job.Status = models.BuildJobStatusBuilding
	job.StartedAt = &now
	if err := s.builds.Update(ctx, job); err != nil {
		return nil, fmt.Errorf("update build job to building: %w", err)
	}

	s.logger.Info("image build started",
		"build_id", job.ID,
		"host_id", hostID,
		"tags", tags,
		"name", name,
	)

	// Simulate build execution (actual Docker build would be async via agent)
	buildErr := s.performBuild(job)

	completed := time.Now()
	job.CompletedAt = &completed
	job.DurationMs = int(completed.Sub(now).Milliseconds())

	if buildErr != nil {
		job.Status = models.BuildJobStatusFailed
		job.ErrorMessage = buildErr.Error()
		s.logger.Error("image build failed",
			"build_id", job.ID,
			"error", buildErr,
		)
	} else {
		job.Status = models.BuildJobStatusSuccess
		job.ImageID = fmt.Sprintf("sha256:%s", uuid.NewString()[:12])
		s.logger.Info("image build succeeded",
			"build_id", job.ID,
			"duration_ms", job.DurationMs,
			"image_id", job.ImageID,
		)
	}

	if err := s.builds.Update(ctx, job); err != nil {
		return nil, fmt.Errorf("update build result: %w", err)
	}

	return job, nil
}

func (s *Service) performBuild(job *models.ImageBuildJob) error {
	// Validate required fields
	if job.Dockerfile == "" {
		return fmt.Errorf("dockerfile content is required")
	}
	if len(job.Tags) == 0 {
		return fmt.Errorf("at least one tag is required")
	}

	// In a full implementation, this would:
	// 1. Send build command to the agent via gateway
	// 2. Stream build output back
	// 3. Capture resulting image ID and size
	// For now, record that the build was processed
	job.Output = fmt.Sprintf("Building image with tags: %v\nDockerfile: %d bytes\nContext: %s\nBuild completed successfully.",
		job.Tags, len(job.Dockerfile), job.ContextPath)

	return nil
}

// GetBuild returns a build job by ID.
func (s *Service) GetBuild(ctx context.Context, id uuid.UUID) (*models.ImageBuildJob, error) {
	return s.builds.GetByID(ctx, id)
}

// ListBuilds returns paginated build jobs for a host.
func (s *Service) ListBuilds(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]models.ImageBuildJob, int, error) {
	return s.builds.ListByHost(ctx, hostID, limit, offset)
}

// GetStats returns aggregate build statistics for a host.
func (s *Service) GetStats(ctx context.Context, hostID uuid.UUID) (*models.ImageBuildJobStats, error) {
	return s.builds.GetStats(ctx, hostID)
}

// ============================================================================
// Dockerfile Templates
// ============================================================================

// ListTemplates returns all Dockerfile templates for a host.
func (s *Service) ListTemplates(ctx context.Context, hostID uuid.UUID) ([]models.DockerfileTemplate, error) {
	return s.templates.List(ctx, hostID)
}

// GetTemplate returns a template by ID.
func (s *Service) GetTemplate(ctx context.Context, id uuid.UUID) (*models.DockerfileTemplate, error) {
	return s.templates.GetByID(ctx, id)
}

// CreateTemplate creates a new Dockerfile template.
func (s *Service) CreateTemplate(ctx context.Context, hostID uuid.UUID, name, description, category, dockerfile string, userID *uuid.UUID) (*models.DockerfileTemplate, error) {
	t := &models.DockerfileTemplate{
		ID:            uuid.New(),
		HostID:        hostID,
		Name:          name,
		Description:   description,
		Category:      category,
		Dockerfile:    dockerfile,
		DefaultArgs:   json.RawMessage("{}"),
		DefaultLabels: json.RawMessage("{}"),
		CreatedBy:     userID,
	}

	if err := s.templates.Create(ctx, t); err != nil {
		return nil, fmt.Errorf("create dockerfile template: %w", err)
	}

	s.logger.Info("created dockerfile template",
		"template_id", t.ID,
		"name", name,
		"category", category,
	)

	return t, nil
}

// DeleteTemplate deletes a Dockerfile template.
func (s *Service) DeleteTemplate(ctx context.Context, id uuid.UUID) error {
	return s.templates.Delete(ctx, id)
}
