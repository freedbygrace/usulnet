// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package crontab provides a managed cron job service.
// Users create cron entries via the web UI; the service schedules and
// executes them using robfig/cron, recording execution history.
package crontab

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/robfig/cron/v3"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// EntryRepository defines persistence operations for crontab entries.
type EntryRepository interface {
	Create(ctx context.Context, entry *models.CrontabEntry) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.CrontabEntry, error)
	List(ctx context.Context, hostID uuid.UUID) ([]*models.CrontabEntry, error)
	Update(ctx context.Context, entry *models.CrontabEntry) error
	Delete(ctx context.Context, id uuid.UUID) error
	UpdateLastRun(ctx context.Context, id uuid.UUID, status string, output string, runAt time.Time) error
	UpdateNextRun(ctx context.Context, id uuid.UUID, nextRun *time.Time) error
	GetStats(ctx context.Context, hostID uuid.UUID) (*models.CrontabStats, error)
}

// ExecutionRepository defines persistence for crontab execution history.
type ExecutionRepository interface {
	Create(ctx context.Context, exec *models.CrontabExecution) error
	ListByEntry(ctx context.Context, entryID uuid.UUID, limit int) ([]*models.CrontabExecution, error)
	DeleteOlderThan(ctx context.Context, olderThan time.Duration) (int64, error)
}

// Service manages cron job entries and their scheduled execution.
type Service struct {
	entries    EntryRepository
	executions ExecutionRepository
	logger     *logger.Logger

	hostID uuid.UUID // default host for execution context

	scheduler *cron.Cron
	cronMu    sync.Mutex
	cronIDs   map[uuid.UUID]cron.EntryID // entry UUID → cron library entry ID

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewService creates a new crontab service.
func NewService(entries EntryRepository, executions ExecutionRepository, log *logger.Logger) *Service {
	return &Service{
		entries:    entries,
		executions: executions,
		logger:     log.Named("crontab"),
		cronIDs:    make(map[uuid.UUID]cron.EntryID),
		stopCh:     make(chan struct{}),
	}
}

// ============================================================================
// Lifecycle
// ============================================================================

// Start initializes the cron scheduler and loads enabled entries.
func (s *Service) Start(ctx context.Context, hostID uuid.UUID) error {
	s.hostID = hostID

	s.scheduler = cron.New(cron.WithParser(cron.NewParser(
		cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor,
	)))

	// Load enabled entries from DB
	entries, err := s.entries.List(ctx, hostID)
	if err != nil {
		return fmt.Errorf("load crontab entries: %w", err)
	}

	registered := 0
	for _, e := range entries {
		if !e.Enabled {
			continue
		}
		if err := s.registerEntry(e); err != nil {
			s.logger.Warn("failed to register crontab entry",
				"id", e.ID, "name", e.Name, "schedule", e.Schedule, "error", err)
			continue
		}
		registered++
	}

	s.scheduler.Start()

	// Update next run times
	s.updateAllNextRun(ctx)

	s.logger.Info("crontab service started",
		"host_id", hostID,
		"entries_loaded", len(entries),
		"entries_registered", registered,
	)

	// Start cleanup worker (prune old executions daily)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.cleanupWorker(ctx)
	}()

	return nil
}

// Stop stops the cron scheduler and waits for running jobs.
func (s *Service) Stop() error {
	close(s.stopCh)
	if s.scheduler != nil {
		ctx := s.scheduler.Stop()
		<-ctx.Done()
	}
	s.wg.Wait()
	s.logger.Info("crontab service stopped")
	return nil
}

// ============================================================================
// CRUD Operations
// ============================================================================

// List returns all crontab entries for a host.
func (s *Service) List(ctx context.Context, hostID uuid.UUID) ([]*models.CrontabEntry, error) {
	return s.entries.List(ctx, hostID)
}

// Get retrieves a crontab entry by ID.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (*models.CrontabEntry, error) {
	return s.entries.GetByID(ctx, id)
}

// Create creates a new crontab entry and registers it in the scheduler if enabled.
func (s *Service) Create(ctx context.Context, hostID uuid.UUID, input models.CreateCrontabInput, userID *uuid.UUID) (*models.CrontabEntry, error) {
	// Validate cron expression
	if _, err := cron.ParseStandard(input.Schedule); err != nil {
		return nil, fmt.Errorf("invalid cron expression %q: %w", input.Schedule, err)
	}

	entry := &models.CrontabEntry{
		ID:          uuid.New(),
		HostID:      hostID,
		Name:        input.Name,
		Description: input.Description,
		Schedule:    input.Schedule,
		CommandType: input.CommandType,
		Command:     input.Command,
		ContainerID: input.ContainerID,
		WorkingDir:  input.WorkingDir,
		HTTPMethod:  input.HTTPMethod,
		HTTPURL:     input.HTTPURL,
		Enabled:     input.Enabled,
		CreatedBy:   userID,
	}

	if entry.CommandType == "" {
		entry.CommandType = models.CrontabCommandShell
	}

	if err := s.entries.Create(ctx, entry); err != nil {
		return nil, err
	}

	// Register in cron scheduler if enabled
	if entry.Enabled {
		if err := s.registerEntry(entry); err != nil {
			s.logger.Warn("failed to register new entry", "id", entry.ID, "error", err)
		} else {
			s.updateNextRunForEntry(ctx, entry.ID)
		}
	}

	s.logger.Info("crontab entry created", "id", entry.ID, "name", entry.Name, "schedule", entry.Schedule)
	return entry, nil
}

// Update modifies a crontab entry and re-registers it in the scheduler.
func (s *Service) Update(ctx context.Context, id uuid.UUID, input models.UpdateCrontabInput) (*models.CrontabEntry, error) {
	entry, err := s.entries.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Apply updates
	if input.Name != nil {
		entry.Name = *input.Name
	}
	if input.Description != nil {
		entry.Description = *input.Description
	}
	if input.Schedule != nil {
		if _, err := cron.ParseStandard(*input.Schedule); err != nil {
			return nil, fmt.Errorf("invalid cron expression %q: %w", *input.Schedule, err)
		}
		entry.Schedule = *input.Schedule
	}
	if input.CommandType != nil {
		entry.CommandType = *input.CommandType
	}
	if input.Command != nil {
		entry.Command = *input.Command
	}
	if input.ContainerID != nil {
		entry.ContainerID = input.ContainerID
	}
	if input.WorkingDir != nil {
		entry.WorkingDir = input.WorkingDir
	}
	if input.HTTPMethod != nil {
		entry.HTTPMethod = input.HTTPMethod
	}
	if input.HTTPURL != nil {
		entry.HTTPURL = input.HTTPURL
	}
	if input.Enabled != nil {
		entry.Enabled = *input.Enabled
	}

	if err := s.entries.Update(ctx, entry); err != nil {
		return nil, err
	}

	// Re-register in cron
	s.unregisterEntry(id)
	if entry.Enabled {
		if err := s.registerEntry(entry); err != nil {
			s.logger.Warn("failed to re-register entry", "id", id, "error", err)
		}
	}
	s.updateNextRunForEntry(ctx, entry.ID)

	s.logger.Info("crontab entry updated", "id", id, "name", entry.Name)
	return entry, nil
}

// Delete removes a crontab entry.
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	s.unregisterEntry(id)
	if err := s.entries.Delete(ctx, id); err != nil {
		return err
	}
	s.logger.Info("crontab entry deleted", "id", id)
	return nil
}

// ToggleEnabled enables or disables a crontab entry.
func (s *Service) ToggleEnabled(ctx context.Context, id uuid.UUID, enabled bool) error {
	entry, err := s.entries.GetByID(ctx, id)
	if err != nil {
		return err
	}
	entry.Enabled = enabled
	if err := s.entries.Update(ctx, entry); err != nil {
		return err
	}

	if enabled {
		if err := s.registerEntry(entry); err != nil {
			s.logger.Warn("failed to register entry", "id", id, "error", err)
		}
		s.updateNextRunForEntry(ctx, id)
	} else {
		s.unregisterEntry(id)
		_ = s.entries.UpdateNextRun(ctx, id, nil)
	}
	return nil
}

// RunNow executes a crontab entry immediately (in a background goroutine).
func (s *Service) RunNow(ctx context.Context, id uuid.UUID) error {
	entry, err := s.entries.GetByID(ctx, id)
	if err != nil {
		return err
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.executeEntry(context.Background(), entry)
	}()
	return nil
}

// ListExecutions returns execution history for an entry.
func (s *Service) ListExecutions(ctx context.Context, entryID uuid.UUID, limit int) ([]*models.CrontabExecution, error) {
	if limit <= 0 {
		limit = 50
	}
	return s.executions.ListByEntry(ctx, entryID, limit)
}

// GetStats returns aggregate statistics.
func (s *Service) GetStats(ctx context.Context, hostID uuid.UUID) (*models.CrontabStats, error) {
	return s.entries.GetStats(ctx, hostID)
}

// ============================================================================
// Internal: cron registration
// ============================================================================

// registerEntry adds an entry to the cron scheduler.
func (s *Service) registerEntry(entry *models.CrontabEntry) error {
	s.cronMu.Lock()
	defer s.cronMu.Unlock()

	// Remove existing registration
	if existingID, ok := s.cronIDs[entry.ID]; ok {
		s.scheduler.Remove(existingID)
		delete(s.cronIDs, entry.ID)
	}

	entryID := entry.ID
	cronID, err := s.scheduler.AddFunc(entry.Schedule, func() {
		// Fetch fresh entry from DB for each execution
		e, err := s.entries.GetByID(context.Background(), entryID)
		if err != nil {
			s.logger.Error("failed to fetch entry for execution", "id", entryID, "error", err)
			return
		}
		s.executeEntry(context.Background(), e)
	})
	if err != nil {
		return fmt.Errorf("add cron schedule %q: %w", entry.Schedule, err)
	}

	s.cronIDs[entry.ID] = cronID
	return nil
}

// unregisterEntry removes an entry from the cron scheduler.
func (s *Service) unregisterEntry(entryID uuid.UUID) {
	s.cronMu.Lock()
	defer s.cronMu.Unlock()

	if cronID, ok := s.cronIDs[entryID]; ok {
		s.scheduler.Remove(cronID)
		delete(s.cronIDs, entryID)
	}
}

// ============================================================================
// Internal: command execution
// ============================================================================

// executeEntry runs the command for a crontab entry and records the result.
func (s *Service) executeEntry(ctx context.Context, entry *models.CrontabEntry) {
	startedAt := time.Now()

	s.logger.Debug("executing crontab entry", "id", entry.ID, "name", entry.Name, "type", entry.CommandType)

	var output string
	var exitCode int
	var execErr error

	switch entry.CommandType {
	case models.CrontabCommandShell:
		output, exitCode, execErr = s.executeShell(ctx, entry.Command, entry.WorkingDir)
	case models.CrontabCommandHTTP:
		method := "GET"
		if entry.HTTPMethod != nil {
			method = *entry.HTTPMethod
		}
		url := entry.Command
		if entry.HTTPURL != nil {
			url = *entry.HTTPURL
		}
		output, exitCode, execErr = s.executeHTTP(ctx, method, url)
	case models.CrontabCommandDocker:
		output = "docker exec not yet supported"
		exitCode = 1
		execErr = fmt.Errorf("docker command type requires HostService integration")
	default:
		output = "unknown command type: " + string(entry.CommandType)
		exitCode = 1
		execErr = fmt.Errorf("unknown command type: %s", entry.CommandType)
	}

	finishedAt := time.Now()
	durationMs := finishedAt.Sub(startedAt).Milliseconds()

	status := "success"
	errMsg := ""
	if execErr != nil {
		status = "failed"
		errMsg = execErr.Error()
	}

	// Truncate output if too large
	if len(output) > 10000 {
		output = output[:10000] + "\n...(truncated)"
	}

	// Record execution
	execution := &models.CrontabExecution{
		ID:         uuid.New(),
		EntryID:    entry.ID,
		HostID:     entry.HostID,
		Status:     status,
		Output:     output,
		Error:      errMsg,
		ExitCode:   &exitCode,
		DurationMs: durationMs,
		StartedAt:  startedAt,
		FinishedAt: finishedAt,
	}

	if err := s.executions.Create(ctx, execution); err != nil {
		s.logger.Error("failed to record crontab execution", "id", entry.ID, "error", err)
	}

	// Update entry last run info
	if err := s.entries.UpdateLastRun(ctx, entry.ID, status, output, startedAt); err != nil {
		s.logger.Error("failed to update crontab last run", "id", entry.ID, "error", err)
	}

	// Update next run time
	s.updateNextRunForEntry(ctx, entry.ID)

	s.logger.Info("crontab entry executed",
		"id", entry.ID, "name", entry.Name,
		"status", status, "duration_ms", durationMs,
	)
}

// executeShell runs a shell command.
func (s *Service) executeShell(ctx context.Context, command string, workingDir *string) (string, int, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	if workingDir != nil && *workingDir != "" {
		cmd.Dir = *workingDir
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	output := stdout.String()
	if stderr.Len() > 0 {
		output += "\n--- STDERR ---\n" + stderr.String()
	}

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
		return output, exitCode, err
	}

	return output, 0, nil
}

// executeHTTP makes an HTTP request.
func (s *Service) executeHTTP(ctx context.Context, method, url string) (string, int, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return "", 1, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "usulnet-crontab/1.0")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", 1, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	var body bytes.Buffer
	body.ReadFrom(resp.Body)

	output := fmt.Sprintf("HTTP %d %s\n%s", resp.StatusCode, resp.Status, body.String())

	if resp.StatusCode >= 400 {
		return output, resp.StatusCode, fmt.Errorf("http %d: %s", resp.StatusCode, resp.Status)
	}
	return output, 0, nil
}

// ============================================================================
// Internal: helpers
// ============================================================================

// updateAllNextRun updates next_run_at for all registered entries.
func (s *Service) updateAllNextRun(ctx context.Context) {
	s.cronMu.Lock()
	defer s.cronMu.Unlock()

	for entryUUID, cronID := range s.cronIDs {
		cronEntry := s.scheduler.Entry(cronID)
		if !cronEntry.Next.IsZero() {
			next := cronEntry.Next
			_ = s.entries.UpdateNextRun(ctx, entryUUID, &next)
		}
	}
}

// updateNextRunForEntry updates next_run_at for a single entry.
func (s *Service) updateNextRunForEntry(ctx context.Context, entryID uuid.UUID) {
	s.cronMu.Lock()
	cronID, ok := s.cronIDs[entryID]
	s.cronMu.Unlock()

	if !ok {
		_ = s.entries.UpdateNextRun(ctx, entryID, nil)
		return
	}

	cronEntry := s.scheduler.Entry(cronID)
	if !cronEntry.Next.IsZero() {
		next := cronEntry.Next
		_ = s.entries.UpdateNextRun(ctx, entryID, &next)
	}
}

// cleanupWorker periodically prunes old execution records.
func (s *Service) cleanupWorker(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			deleted, err := s.executions.DeleteOlderThan(ctx, 30*24*time.Hour)
			if err != nil {
				s.logger.Warn("failed to cleanup old executions", "error", err)
			} else if deleted > 0 {
				s.logger.Info("cleaned up old crontab executions", "deleted", deleted)
			}
		}
	}
}
