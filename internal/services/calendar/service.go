// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package calendar

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// Service manages calendar events, tasks, notes, and checklists.
type Service struct {
	repo   *postgres.CalendarRepository
	logger *logger.Logger
}

// NewService creates a new calendar service.
func NewService(repo *postgres.CalendarRepository, log *logger.Logger) *Service {
	return &Service{
		repo:   repo,
		logger: log.Named("calendar"),
	}
}

// ============================================================================
// Events
// ============================================================================

// CreateEvent creates a new calendar event after validation.
func (s *Service) CreateEvent(ctx context.Context, ev *models.CalendarEvent) error {
	if err := s.validateEvent(ev); err != nil {
		return fmt.Errorf("create calendar event: validate: %w", err)
	}

	if err := s.repo.CreateEvent(ctx, ev); err != nil {
		return fmt.Errorf("create calendar event: %w", err)
	}

	s.logger.Info("created calendar event",
		"id", ev.ID,
		"title", ev.Title,
		"user_id", ev.UserID,
		"date", ev.EventDate,
	)
	return nil
}

// GetEvent retrieves a calendar event by ID.
func (s *Service) GetEvent(ctx context.Context, id, userID uuid.UUID) (*models.CalendarEvent, error) {
	ev, err := s.repo.GetEvent(ctx, id, userID)
	if err != nil {
		return nil, fmt.Errorf("get calendar event %s: %w", id, err)
	}
	return ev, nil
}

// ListEventsByMonth returns events for a given year/month.
func (s *Service) ListEventsByMonth(ctx context.Context, userID uuid.UUID, year, month int) ([]*models.CalendarEvent, error) {
	if month < 1 || month > 12 {
		return nil, errors.NewValidationError("month must be between 1 and 12")
	}
	if year < 2000 || year > 2100 {
		return nil, errors.NewValidationError("year must be between 2000 and 2100")
	}

	events, err := s.repo.ListEventsByMonth(ctx, userID, year, month)
	if err != nil {
		return nil, fmt.Errorf("list calendar events for %d-%02d: %w", year, month, err)
	}
	return events, nil
}

// UpdateEvent updates a calendar event.
func (s *Service) UpdateEvent(ctx context.Context, ev *models.CalendarEvent) error {
	if err := s.validateEvent(ev); err != nil {
		return fmt.Errorf("update calendar event %s: validate: %w", ev.ID, err)
	}

	if err := s.repo.UpdateEvent(ctx, ev); err != nil {
		return fmt.Errorf("update calendar event %s: %w", ev.ID, err)
	}

	s.logger.Info("updated calendar event",
		"id", ev.ID,
		"title", ev.Title,
		"user_id", ev.UserID,
	)
	return nil
}

// DeleteEvent deletes a calendar event.
func (s *Service) DeleteEvent(ctx context.Context, id, userID uuid.UUID) error {
	if err := s.repo.DeleteEvent(ctx, id, userID); err != nil {
		return fmt.Errorf("delete calendar event %s: %w", id, err)
	}

	s.logger.Info("deleted calendar event", "id", id, "user_id", userID)
	return nil
}

func (s *Service) validateEvent(ev *models.CalendarEvent) error {
	if ev.Title == "" {
		return errors.NewValidationError("title is required")
	}
	if ev.EventDate == "" {
		return errors.NewValidationError("event_date is required")
	}
	if ev.Color == "" {
		ev.Color = models.CalendarColorBlue
	}
	if !models.ValidCalendarColors[ev.Color] {
		return errors.NewValidationError("invalid color: " + ev.Color)
	}
	return nil
}

// ============================================================================
// Tasks
// ============================================================================

// CreateTask creates a new calendar task after validation.
func (s *Service) CreateTask(ctx context.Context, t *models.CalendarTask) error {
	if err := s.validateTask(t); err != nil {
		return fmt.Errorf("create calendar task: validate: %w", err)
	}

	if err := s.repo.CreateTask(ctx, t); err != nil {
		return fmt.Errorf("create calendar task: %w", err)
	}

	s.logger.Info("created calendar task",
		"id", t.ID,
		"text", t.Text,
		"user_id", t.UserID,
		"priority", t.Priority,
	)
	return nil
}

// ListTasks returns tasks with optional filter.
func (s *Service) ListTasks(ctx context.Context, userID uuid.UUID, filter string) ([]*models.CalendarTask, error) {
	if filter == "" {
		filter = "all"
	}
	if filter != "all" && filter != "active" && filter != "done" {
		return nil, errors.NewValidationError("filter must be one of: all, active, done")
	}

	tasks, err := s.repo.ListTasks(ctx, userID, filter)
	if err != nil {
		return nil, fmt.Errorf("list calendar tasks: %w", err)
	}
	return tasks, nil
}

// UpdateTask updates a calendar task.
func (s *Service) UpdateTask(ctx context.Context, t *models.CalendarTask) error {
	if err := s.validateTask(t); err != nil {
		return fmt.Errorf("update calendar task %s: validate: %w", t.ID, err)
	}

	if err := s.repo.UpdateTask(ctx, t); err != nil {
		return fmt.Errorf("update calendar task %s: %w", t.ID, err)
	}

	s.logger.Info("updated calendar task", "id", t.ID, "user_id", t.UserID)
	return nil
}

// ToggleTask toggles the done status of a task.
func (s *Service) ToggleTask(ctx context.Context, id, userID uuid.UUID) error {
	if err := s.repo.ToggleTask(ctx, id, userID); err != nil {
		return fmt.Errorf("toggle calendar task %s: %w", id, err)
	}

	s.logger.Info("toggled calendar task", "id", id, "user_id", userID)
	return nil
}

// DeleteTask deletes a calendar task.
func (s *Service) DeleteTask(ctx context.Context, id, userID uuid.UUID) error {
	if err := s.repo.DeleteTask(ctx, id, userID); err != nil {
		return fmt.Errorf("delete calendar task %s: %w", id, err)
	}

	s.logger.Info("deleted calendar task", "id", id, "user_id", userID)
	return nil
}

func (s *Service) validateTask(t *models.CalendarTask) error {
	if t.Text == "" {
		return errors.NewValidationError("text is required")
	}
	if t.Priority == "" {
		t.Priority = models.CalendarPriorityNormal
	}
	if !models.ValidCalendarPriorities[t.Priority] {
		return errors.NewValidationError("invalid priority: " + t.Priority)
	}
	return nil
}

// ============================================================================
// Notes
// ============================================================================

// CreateNote creates a new calendar note after validation.
func (s *Service) CreateNote(ctx context.Context, n *models.CalendarNote) error {
	if n.Title == "" {
		return errors.NewValidationError("title is required")
	}

	if err := s.repo.CreateNote(ctx, n); err != nil {
		return fmt.Errorf("create calendar note: %w", err)
	}

	s.logger.Info("created calendar note",
		"id", n.ID,
		"title", n.Title,
		"user_id", n.UserID,
	)
	return nil
}

// ListNotes returns notes visible to the user.
func (s *Service) ListNotes(ctx context.Context, userID uuid.UUID) ([]*models.CalendarNote, error) {
	notes, err := s.repo.ListNotes(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list calendar notes: %w", err)
	}
	return notes, nil
}

// UpdateNote updates a calendar note.
func (s *Service) UpdateNote(ctx context.Context, n *models.CalendarNote) error {
	if n.Title == "" {
		return errors.NewValidationError("title is required")
	}

	if err := s.repo.UpdateNote(ctx, n); err != nil {
		return fmt.Errorf("update calendar note %s: %w", n.ID, err)
	}

	s.logger.Info("updated calendar note", "id", n.ID, "user_id", n.UserID)
	return nil
}

// DeleteNote deletes a calendar note.
func (s *Service) DeleteNote(ctx context.Context, id, userID uuid.UUID) error {
	if err := s.repo.DeleteNote(ctx, id, userID); err != nil {
		return fmt.Errorf("delete calendar note %s: %w", id, err)
	}

	s.logger.Info("deleted calendar note", "id", id, "user_id", userID)
	return nil
}

// ============================================================================
// Checklists
// ============================================================================

// CreateChecklist creates a new calendar checklist after validation.
func (s *Service) CreateChecklist(ctx context.Context, cl *models.CalendarChecklist) error {
	if cl.Title == "" {
		return errors.NewValidationError("title is required")
	}
	if cl.Items == nil {
		cl.Items = json.RawMessage("[]")
	}

	if err := s.repo.CreateChecklist(ctx, cl); err != nil {
		return fmt.Errorf("create calendar checklist: %w", err)
	}

	s.logger.Info("created calendar checklist",
		"id", cl.ID,
		"title", cl.Title,
		"user_id", cl.UserID,
	)
	return nil
}

// ListChecklists returns checklists visible to the user.
func (s *Service) ListChecklists(ctx context.Context, userID uuid.UUID) ([]*models.CalendarChecklist, error) {
	checklists, err := s.repo.ListChecklists(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list calendar checklists: %w", err)
	}
	return checklists, nil
}

// UpdateChecklist updates a calendar checklist.
func (s *Service) UpdateChecklist(ctx context.Context, cl *models.CalendarChecklist) error {
	if cl.Title == "" {
		return errors.NewValidationError("title is required")
	}

	if err := s.repo.UpdateChecklist(ctx, cl); err != nil {
		return fmt.Errorf("update calendar checklist %s: %w", cl.ID, err)
	}

	s.logger.Info("updated calendar checklist", "id", cl.ID, "user_id", cl.UserID)
	return nil
}

// DeleteChecklist deletes a calendar checklist.
func (s *Service) DeleteChecklist(ctx context.Context, id, userID uuid.UUID) error {
	if err := s.repo.DeleteChecklist(ctx, id, userID); err != nil {
		return fmt.Errorf("delete calendar checklist %s: %w", id, err)
	}

	s.logger.Info("deleted calendar checklist", "id", id, "user_id", userID)
	return nil
}
