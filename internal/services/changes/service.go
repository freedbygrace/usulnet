// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package changes

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Repository defines the persistence interface for change events.
type Repository interface {
	Create(ctx context.Context, e *models.ChangeEvent) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.ChangeEvent, error)
	List(ctx context.Context, opts models.ChangeEventListOptions) ([]*models.ChangeEvent, int, error)
	GetByResource(ctx context.Context, resourceType, resourceID string, limit int) ([]*models.ChangeEvent, error)
	GetByUser(ctx context.Context, userID uuid.UUID, limit int) ([]*models.ChangeEvent, error)
	GetStats(ctx context.Context, since time.Time) (*models.ChangeEventStats, error)
	DeleteOlderThan(ctx context.Context, before time.Time) (int64, error)
	ExportCSV(ctx context.Context, opts models.ChangeEventListOptions) ([][]string, error)
}

// Service handles change event recording and retrieval.
type Service struct {
	repo   Repository
	logger *logger.Logger
}

// NewService creates a new change tracking service.
func NewService(repo Repository, log *logger.Logger) *Service {
	if log == nil {
		log = logger.Nop()
	}
	return &Service{
		repo:   repo,
		logger: log.Named("changes"),
	}
}

// RecordInput is the input for recording a new change event.
type RecordInput struct {
	UserID        *uuid.UUID
	UserName      string
	ClientIP      string
	ResourceType  string
	ResourceID    string
	ResourceName  string
	Action        string
	OldState      any // will be JSON-marshalled
	NewState      any // will be JSON-marshalled
	DiffSummary   string
	RelatedTicket string
	Metadata      map[string]any
}

// Record creates an immutable change event from the given input.
func (s *Service) Record(ctx context.Context, input RecordInput) error {
	e := &models.ChangeEvent{
		UserID:        input.UserID,
		UserName:      input.UserName,
		ClientIP:      input.ClientIP,
		ResourceType:  input.ResourceType,
		ResourceID:    input.ResourceID,
		ResourceName:  input.ResourceName,
		Action:        input.Action,
		DiffSummary:   input.DiffSummary,
		RelatedTicket: input.RelatedTicket,
	}

	if input.OldState != nil {
		raw, err := json.Marshal(input.OldState)
		if err == nil {
			msg := json.RawMessage(raw)
			e.OldState = &msg
		}
	}
	if input.NewState != nil {
		raw, err := json.Marshal(input.NewState)
		if err == nil {
			msg := json.RawMessage(raw)
			e.NewState = &msg
		}
	}
	if len(input.Metadata) > 0 {
		raw, err := json.Marshal(input.Metadata)
		if err == nil {
			msg := json.RawMessage(raw)
			e.Metadata = &msg
		}
	}

	// Auto-generate diff summary if not provided
	if e.DiffSummary == "" && e.OldState != nil && e.NewState != nil {
		e.DiffSummary = generateDiffSummary(e.OldState, e.NewState)
	}

	if err := s.repo.Create(ctx, e); err != nil {
		s.logger.Error("failed to record change event",
			"resource_type", input.ResourceType,
			"resource_id", input.ResourceID,
			"action", input.Action,
			"error", err,
		)
		return fmt.Errorf("recording change event: %w", err)
	}

	s.logger.Debug("change event recorded",
		"id", e.ID,
		"resource_type", input.ResourceType,
		"resource_id", input.ResourceID,
		"action", input.Action,
		"user", input.UserName,
	)
	return nil
}

// RecordAsync records a change event asynchronously (fire-and-forget).
func (s *Service) RecordAsync(ctx context.Context, input RecordInput) {
	go func() {
		bgCtx := context.WithoutCancel(ctx)
		if err := s.Record(bgCtx, input); err != nil {
			s.logger.Error("async change event recording failed", "error", err)
		}
	}()
}

// GetByID retrieves a single change event by its ID.
func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (*models.ChangeEvent, error) {
	return s.repo.GetByID(ctx, id)
}

// List retrieves change events with filtering and pagination.
func (s *Service) List(ctx context.Context, opts models.ChangeEventListOptions) ([]*models.ChangeEvent, int, error) {
	return s.repo.List(ctx, opts)
}

// GetByResource retrieves change events for a specific resource.
func (s *Service) GetByResource(ctx context.Context, resourceType, resourceID string, limit int) ([]*models.ChangeEvent, error) {
	return s.repo.GetByResource(ctx, resourceType, resourceID, limit)
}

// GetByUser retrieves change events for a specific user.
func (s *Service) GetByUser(ctx context.Context, userID uuid.UUID, limit int) ([]*models.ChangeEvent, error) {
	return s.repo.GetByUser(ctx, userID, limit)
}

// GetStats returns aggregated statistics for change events.
func (s *Service) GetStats(ctx context.Context, since time.Time) (*models.ChangeEventStats, error) {
	return s.repo.GetStats(ctx, since)
}

// ExportCSV returns change events as CSV rows.
func (s *Service) ExportCSV(ctx context.Context, opts models.ChangeEventListOptions) ([][]string, error) {
	return s.repo.ExportCSV(ctx, opts)
}

// generateDiffSummary creates a human-readable summary comparing two JSON states.
func generateDiffSummary(oldRaw, newRaw *json.RawMessage) string {
	if oldRaw == nil || newRaw == nil {
		return ""
	}

	var oldMap, newMap map[string]any
	if err := json.Unmarshal(*oldRaw, &oldMap); err != nil {
		return ""
	}
	if err := json.Unmarshal(*newRaw, &newMap); err != nil {
		return ""
	}

	var changes []string

	// Find modified and deleted keys
	for k, oldVal := range oldMap {
		newVal, exists := newMap[k]
		if !exists {
			changes = append(changes, fmt.Sprintf("-%s", k))
			continue
		}
		oldStr := fmt.Sprintf("%v", oldVal)
		newStr := fmt.Sprintf("%v", newVal)
		if oldStr != newStr {
			changes = append(changes, fmt.Sprintf("~%s", k))
		}
	}

	// Find added keys
	for k := range newMap {
		if _, exists := oldMap[k]; !exists {
			changes = append(changes, fmt.Sprintf("+%s", k))
		}
	}

	if len(changes) == 0 {
		return "no changes detected"
	}

	summary := strings.Join(changes, ", ")
	if len(summary) > 500 {
		summary = summary[:497] + "..."
	}
	return summary
}
