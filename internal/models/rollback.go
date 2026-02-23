// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// RollbackTrigger represents what triggers a rollback.
type RollbackTrigger string

const (
	RollbackTriggerDeployFailure RollbackTrigger = "deploy_failure"
	RollbackTriggerHealthCheck   RollbackTrigger = "health_check"
	RollbackTriggerExitCode      RollbackTrigger = "exit_code"
	RollbackTriggerManual        RollbackTrigger = "manual"
)

// RollbackStatus represents the status of a rollback execution.
type RollbackStatus string

const (
	RollbackStatusPending     RollbackStatus = "pending"
	RollbackStatusRollingBack RollbackStatus = "rolling_back"
	RollbackStatusSuccess     RollbackStatus = "success"
	RollbackStatusFailed      RollbackStatus = "failed"
)

// RollbackPolicy defines automated rollback behavior for a stack.
type RollbackPolicy struct {
	ID                  uuid.UUID       `json:"id" db:"id"`
	StackID             uuid.UUID       `json:"stack_id" db:"stack_id"`
	HostID              uuid.UUID       `json:"host_id" db:"host_id"`
	Enabled             bool            `json:"enabled" db:"enabled"`
	TriggerOn           RollbackTrigger `json:"trigger_on" db:"trigger_on"`
	HealthCheckURL      string          `json:"health_check_url" db:"health_check_url"`
	HealthCheckInterval int             `json:"health_check_interval" db:"health_check_interval"`
	HealthCheckTimeout  int             `json:"health_check_timeout" db:"health_check_timeout"`
	MaxRetries          int             `json:"max_retries" db:"max_retries"`
	CooldownMinutes     int             `json:"cooldown_minutes" db:"cooldown_minutes"`
	NotifyOnRollback    bool            `json:"notify_on_rollback" db:"notify_on_rollback"`
	CreatedBy           *uuid.UUID      `json:"created_by,omitempty" db:"created_by"`
	CreatedAt           time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time       `json:"updated_at" db:"updated_at"`
}

// RollbackExecution represents a rollback operation execution.
type RollbackExecution struct {
	ID              uuid.UUID       `json:"id" db:"id"`
	PolicyID        *uuid.UUID      `json:"policy_id,omitempty" db:"policy_id"`
	StackID         uuid.UUID       `json:"stack_id" db:"stack_id"`
	HostID          uuid.UUID       `json:"host_id" db:"host_id"`
	TriggerReason   RollbackTrigger `json:"trigger_reason" db:"trigger_reason"`
	FromVersion     int             `json:"from_version" db:"from_version"`
	ToVersion       int             `json:"to_version" db:"to_version"`
	Status          RollbackStatus  `json:"status" db:"status"`
	Output          string          `json:"output" db:"output"`
	ErrorMessage    string          `json:"error_message" db:"error_message"`
	ComposeSnapshot string          `json:"compose_snapshot" db:"compose_snapshot"`
	DurationMs      int             `json:"duration_ms" db:"duration_ms"`
	TriggeredBy     *uuid.UUID      `json:"triggered_by,omitempty" db:"triggered_by"`
	StartedAt       *time.Time      `json:"started_at,omitempty" db:"started_at"`
	CompletedAt     *time.Time      `json:"completed_at,omitempty" db:"completed_at"`
	CreatedAt       time.Time       `json:"created_at" db:"created_at"`
}

// RollbackStats holds aggregate rollback statistics.
type RollbackStats struct {
	TotalRollbacks int        `json:"total_rollbacks"`
	Successful     int        `json:"successful"`
	Failed         int        `json:"failed"`
	AutoTriggered  int        `json:"auto_triggered"`
	ManualTriggers int        `json:"manual_triggers"`
	LastRollbackAt *time.Time `json:"last_rollback_at,omitempty"`
}
