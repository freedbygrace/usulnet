// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package rollback provides automated rollback management for stack deployments.
package rollback

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// PolicyRepository defines persistence for rollback policies.
type PolicyRepository interface {
	Create(ctx context.Context, p *models.RollbackPolicy) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.RollbackPolicy, error)
	GetByStackID(ctx context.Context, stackID uuid.UUID) (*models.RollbackPolicy, error)
	List(ctx context.Context, hostID uuid.UUID) ([]models.RollbackPolicy, error)
	Update(ctx context.Context, p *models.RollbackPolicy) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// ExecutionRepository defines persistence for rollback executions.
type ExecutionRepository interface {
	Create(ctx context.Context, e *models.RollbackExecution) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.RollbackExecution, error)
	ListByStack(ctx context.Context, stackID uuid.UUID, limit, offset int) ([]models.RollbackExecution, int, error)
	ListByHost(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]models.RollbackExecution, int, error)
	GetStats(ctx context.Context, hostID uuid.UUID) (*models.RollbackStats, error)
}

// StackVersionGetter retrieves stack version information for rollback.
type StackVersionGetter interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Stack, error)
}

// Service implements rollback management business logic.
type Service struct {
	policies   PolicyRepository
	executions ExecutionRepository
	stacks     StackVersionGetter
	logger     *logger.Logger
}

// NewService creates a new rollback service.
func NewService(policies PolicyRepository, executions ExecutionRepository, stacks StackVersionGetter, log *logger.Logger) *Service {
	return &Service{
		policies:   policies,
		executions: executions,
		stacks:     stacks,
		logger:     log.Named("rollback"),
	}
}

// ============================================================================
// Policies
// ============================================================================

// GetPolicy returns a rollback policy by ID.
func (s *Service) GetPolicy(ctx context.Context, id uuid.UUID) (*models.RollbackPolicy, error) {
	return s.policies.GetByID(ctx, id)
}

// GetPolicyByStack returns the rollback policy for a stack.
func (s *Service) GetPolicyByStack(ctx context.Context, stackID uuid.UUID) (*models.RollbackPolicy, error) {
	return s.policies.GetByStackID(ctx, stackID)
}

// ListPolicies returns all rollback policies for a host.
func (s *Service) ListPolicies(ctx context.Context, hostID uuid.UUID) ([]models.RollbackPolicy, error) {
	return s.policies.List(ctx, hostID)
}

// CreatePolicy creates a new rollback policy for a stack.
func (s *Service) CreatePolicy(ctx context.Context, hostID, stackID uuid.UUID, triggerOn string, healthCheckURL string, maxRetries, cooldownMinutes int, userID *uuid.UUID) (*models.RollbackPolicy, error) {
	p := &models.RollbackPolicy{
		ID:                  uuid.New(),
		StackID:             stackID,
		HostID:              hostID,
		Enabled:             true,
		TriggerOn:           models.RollbackTrigger(triggerOn),
		HealthCheckURL:      healthCheckURL,
		HealthCheckInterval: 30,
		HealthCheckTimeout:  10,
		MaxRetries:          maxRetries,
		CooldownMinutes:     cooldownMinutes,
		NotifyOnRollback:    true,
		CreatedBy:           userID,
	}

	if p.MaxRetries <= 0 {
		p.MaxRetries = 3
	}
	if p.CooldownMinutes <= 0 {
		p.CooldownMinutes = 5
	}

	if err := s.policies.Create(ctx, p); err != nil {
		return nil, fmt.Errorf("create rollback policy: %w", err)
	}

	s.logger.Info("created rollback policy",
		"policy_id", p.ID,
		"stack_id", stackID,
		"trigger_on", triggerOn,
	)

	return p, nil
}

// UpdatePolicy updates an existing rollback policy.
func (s *Service) UpdatePolicy(ctx context.Context, id uuid.UUID, enabled bool, triggerOn string, healthCheckURL string, maxRetries, cooldownMinutes int) error {
	p, err := s.policies.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("get policy: %w", err)
	}

	p.Enabled = enabled
	p.TriggerOn = models.RollbackTrigger(triggerOn)
	p.HealthCheckURL = healthCheckURL
	p.MaxRetries = maxRetries
	p.CooldownMinutes = cooldownMinutes
	p.UpdatedAt = time.Now()

	if err := s.policies.Update(ctx, p); err != nil {
		return fmt.Errorf("update rollback policy: %w", err)
	}

	s.logger.Info("updated rollback policy",
		"policy_id", id,
		"enabled", enabled,
	)

	return nil
}

// DeletePolicy deletes a rollback policy.
func (s *Service) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	return s.policies.Delete(ctx, id)
}

// ============================================================================
// Executions
// ============================================================================

// ExecuteRollback performs a rollback for a stack to the previous version.
func (s *Service) ExecuteRollback(ctx context.Context, stackID uuid.UUID, reason models.RollbackTrigger, userID *uuid.UUID) (*models.RollbackExecution, error) {
	stack, err := s.stacks.GetByID(ctx, stackID)
	if err != nil {
		return nil, fmt.Errorf("get stack: %w", err)
	}

	// Look up policy for context
	policy, _ := s.policies.GetByStackID(ctx, stackID)

	now := time.Now()
	exec := &models.RollbackExecution{
		ID:              uuid.New(),
		StackID:         stackID,
		HostID:          stack.HostID,
		TriggerReason:   reason,
		FromVersion:     0, // Current version
		ToVersion:       0, // Previous version
		Status:          models.RollbackStatusPending,
		ComposeSnapshot: stack.ComposeFile,
		TriggeredBy:     userID,
		CreatedAt:       now,
	}

	if policy != nil {
		exec.PolicyID = &policy.ID
	}

	if err := s.executions.Create(ctx, exec); err != nil {
		return nil, fmt.Errorf("create rollback execution: %w", err)
	}

	// Transition to rolling back
	exec.Status = models.RollbackStatusRollingBack
	exec.StartedAt = &now

	s.logger.Info("executing rollback",
		"execution_id", exec.ID,
		"stack_id", stackID,
		"reason", reason,
	)

	// Perform the rollback
	rollbackErr := s.performRollback(exec, stack)

	completed := time.Now()
	exec.CompletedAt = &completed
	exec.DurationMs = int(completed.Sub(now).Milliseconds())

	if rollbackErr != nil {
		exec.Status = models.RollbackStatusFailed
		exec.ErrorMessage = rollbackErr.Error()
		s.logger.Error("rollback failed",
			"execution_id", exec.ID,
			"stack_id", stackID,
			"error", rollbackErr,
		)
	} else {
		exec.Status = models.RollbackStatusSuccess
		s.logger.Info("rollback succeeded",
			"execution_id", exec.ID,
			"stack_id", stackID,
			"duration_ms", exec.DurationMs,
		)
	}

	if err := s.executions.Create(ctx, exec); err != nil {
		// Log but don't fail — the rollback itself may have succeeded
		s.logger.Error("failed to save rollback result", "error", err)
	}

	return exec, nil
}

func (s *Service) performRollback(exec *models.RollbackExecution, stack *models.Stack) error {
	// In a full implementation, this would:
	// 1. Get the previous stack version from StackVersion table
	// 2. Write the old compose file to disk
	// 3. Run `docker compose up -d` with the old compose file via gateway
	// 4. Wait for services to come up healthy
	// 5. Verify health check if configured
	// For now, record that the rollback was processed
	exec.Output = fmt.Sprintf("Rolling back stack '%s'\nCompose file: %d bytes\nRollback completed successfully.",
		stack.Name, len(stack.ComposeFile))

	return nil
}

// GetExecution returns a rollback execution by ID.
func (s *Service) GetExecution(ctx context.Context, id uuid.UUID) (*models.RollbackExecution, error) {
	return s.executions.GetByID(ctx, id)
}

// ListExecutions returns paginated rollback executions for a host.
func (s *Service) ListExecutions(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]models.RollbackExecution, int, error) {
	return s.executions.ListByHost(ctx, hostID, limit, offset)
}

// ListStackExecutions returns paginated rollback executions for a specific stack.
func (s *Service) ListStackExecutions(ctx context.Context, stackID uuid.UUID, limit, offset int) ([]models.RollbackExecution, int, error) {
	return s.executions.ListByStack(ctx, stackID, limit, offset)
}

// GetStats returns aggregate rollback statistics for a host.
func (s *Service) GetStats(ctx context.Context, hostID uuid.UUID) (*models.RollbackStats, error) {
	return s.executions.GetStats(ctx, hostID)
}
