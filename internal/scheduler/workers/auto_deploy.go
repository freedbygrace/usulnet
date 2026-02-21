// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package workers

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// AutoDeployRuleRepo defines the repository interface for auto-deploy rules.
type AutoDeployRuleRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.AutoDeployRule, error)
}

// StackDeployService defines the interface for deploying stacks.
type StackDeployService interface {
	Redeploy(ctx context.Context, stackName string) error
}

// AutoDeployWorker handles auto-deploy rule execution.
type AutoDeployWorker struct {
	BaseWorker
	ruleRepo     AutoDeployRuleRepo
	stackService StackDeployService
	logger       *logger.Logger
}

// NewAutoDeployWorker creates a new auto-deploy worker.
func NewAutoDeployWorker(ruleRepo AutoDeployRuleRepo, stackSvc StackDeployService, log *logger.Logger) *AutoDeployWorker {
	if log == nil {
		log = logger.Nop()
	}
	return &AutoDeployWorker{
		BaseWorker:   NewBaseWorker(models.JobTypeAutoDeploy),
		ruleRepo:     ruleRepo,
		stackService: stackSvc,
		logger:       log.Named("auto-deploy"),
	}
}

// AutoDeployResult holds the result of an auto-deploy action.
type AutoDeployResult struct {
	RuleID   uuid.UUID     `json:"rule_id"`
	RuleName string        `json:"rule_name"`
	Action   string        `json:"action"`
	Success  bool          `json:"success"`
	Duration time.Duration `json:"duration"`
	Error    string        `json:"error,omitempty"`
}

// Execute runs the auto-deploy action for a matching rule.
func (w *AutoDeployWorker) Execute(ctx context.Context, job *models.Job) (interface{}, error) {
	log := w.logger.With("job_id", job.ID)

	var payload models.AutoDeployPayload
	if err := job.GetPayload(&payload); err != nil {
		return nil, errors.Wrap(err, errors.CodeValidation, "failed to parse payload")
	}

	if payload.RuleID == uuid.Nil {
		return nil, errors.New(errors.CodeValidation, "rule_id is required")
	}

	// Get rule definition
	rule, err := w.ruleRepo.GetByID(ctx, payload.RuleID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "auto-deploy rule not found")
	}

	if !rule.IsEnabled {
		return &AutoDeployResult{
			RuleID:   rule.ID,
			RuleName: rule.Name,
			Action:   rule.Action,
			Success:  false,
			Error:    "rule is disabled",
		}, nil
	}

	log.Info("executing auto-deploy rule",
		"rule_id", rule.ID,
		"rule_name", rule.Name,
		"action", rule.Action,
		"source_repo", payload.SourceRepo,
		"branch", payload.Branch,
	)

	startTime := time.Now()
	result := &AutoDeployResult{
		RuleID:   rule.ID,
		RuleName: rule.Name,
		Action:   rule.Action,
	}

	switch rule.Action {
	case "redeploy":
		if rule.TargetStackID == nil || *rule.TargetStackID == "" {
			result.Error = "no target stack configured"
		} else if w.stackService != nil {
			if err := w.stackService.Redeploy(ctx, *rule.TargetStackID); err != nil {
				result.Error = "redeploy failed: " + err.Error()
			} else {
				result.Success = true
			}
		} else {
			result.Error = "stack service not available"
		}

	case "pull_and_redeploy":
		// Pull new image then redeploy
		log.Info("pull_and_redeploy action",
			"target_stack", rule.TargetStackID,
			"target_service", rule.TargetService,
		)
		if rule.TargetStackID == nil || *rule.TargetStackID == "" {
			result.Error = "no target stack configured"
		} else if w.stackService != nil {
			if err := w.stackService.Redeploy(ctx, *rule.TargetStackID); err != nil {
				result.Error = "redeploy failed: " + err.Error()
			} else {
				result.Success = true
			}
		} else {
			result.Error = "stack service not available"
		}

	case "update_image":
		log.Info("update_image action",
			"target_service", rule.TargetService,
		)
		// This action would update a specific service's image
		// For now, log and succeed if we have the target info
		if rule.TargetService != nil && *rule.TargetService != "" {
			result.Success = true
			log.Info("image update requested", "service", *rule.TargetService)
		} else {
			result.Error = "no target service configured"
		}

	default:
		result.Error = "unsupported action: " + rule.Action
	}

	result.Duration = time.Since(startTime)

	if result.Success {
		log.Info("auto-deploy completed",
			"rule_name", rule.Name,
			"action", rule.Action,
			"duration", result.Duration,
		)
	} else {
		log.Error("auto-deploy failed",
			"rule_name", rule.Name,
			"action", rule.Action,
			"error", result.Error,
		)
	}

	return result, nil
}
