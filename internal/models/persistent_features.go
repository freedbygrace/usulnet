// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// CompliancePolicyRecord represents a compliance policy.
type CompliancePolicyRecord struct {
	ID          uuid.UUID  `db:"id"`
	Name        string     `db:"name"`
	Description string     `db:"description"`
	Category    string     `db:"category"`
	Severity    string     `db:"severity"`
	Rule        string     `db:"rule"`
	IsEnabled   bool       `db:"is_enabled"`
	IsEnforced  bool       `db:"is_enforced"`
	LastCheckAt *time.Time `db:"last_check_at"`
	CreatedBy   *uuid.UUID `db:"created_by"`
	CreatedAt   time.Time  `db:"created_at"`
	UpdatedAt   time.Time  `db:"updated_at"`
}

// ComplianceViolationRecord represents a detected policy violation.
type ComplianceViolationRecord struct {
	ID            uuid.UUID  `db:"id"`
	PolicyID      uuid.UUID  `db:"policy_id"`
	PolicyName    string     `db:"policy_name"`
	ContainerID   string     `db:"container_id"`
	ContainerName string     `db:"container_name"`
	Severity      string     `db:"severity"`
	Message       string     `db:"message"`
	Details       string     `db:"details"`
	Status        string     `db:"status"`
	DetectedAt    time.Time  `db:"detected_at"`
	ResolvedAt    *time.Time `db:"resolved_at"`
	ResolvedBy    *uuid.UUID `db:"resolved_by"`
}

// ManagedSecretRecord represents a managed secret.
type ManagedSecretRecord struct {
	ID             uuid.UUID  `db:"id"`
	Name           string     `db:"name"`
	Description    string     `db:"description"`
	Type           string     `db:"type"`
	Scope          string     `db:"scope"`
	ScopeTarget    string     `db:"scope_target"`
	EncryptedValue string     `db:"encrypted_value"`
	RotationDays   int        `db:"rotation_days"`
	ExpiresAt      *time.Time `db:"expires_at"`
	LastRotatedAt  *time.Time `db:"last_rotated_at"`
	LinkedCount    int        `db:"linked_count"`
	CreatedBy      *uuid.UUID `db:"created_by"`
	CreatedAt      time.Time  `db:"created_at"`
	UpdatedAt      time.Time  `db:"updated_at"`
}

// LifecyclePolicyRecord represents a lifecycle policy.
type LifecyclePolicyRecord struct {
	ID             uuid.UUID  `db:"id"`
	Name           string     `db:"name"`
	Description    string     `db:"description"`
	ResourceType   string     `db:"resource_type"`
	Action         string     `db:"action"`
	Schedule       string     `db:"schedule"`
	IsEnabled      bool       `db:"is_enabled"`
	OnlyDangling   bool       `db:"only_dangling"`
	OnlyStopped    bool       `db:"only_stopped"`
	OnlyUnused     bool       `db:"only_unused"`
	MaxAgeDays     int        `db:"max_age_days"`
	KeepLatest     int        `db:"keep_latest"`
	ExcludeLabels  string     `db:"exclude_labels"`
	IncludeLabels  string     `db:"include_labels"`
	LastExecutedAt *time.Time `db:"last_executed_at"`
	LastResult     string     `db:"last_result"`
	CreatedBy      *uuid.UUID `db:"created_by"`
	CreatedAt      time.Time  `db:"created_at"`
	UpdatedAt      time.Time  `db:"updated_at"`
}

// LifecycleHistoryRecord represents a lifecycle execution history entry.
type LifecycleHistoryRecord struct {
	ID           uuid.UUID  `db:"id"`
	PolicyID     *uuid.UUID `db:"policy_id"`
	PolicyName   string     `db:"policy_name"`
	ResourceType string     `db:"resource_type"`
	Action       string     `db:"action"`
	ItemsRemoved int64      `db:"items_removed"`
	SpaceFreed   int64      `db:"space_freed"`
	Status       string     `db:"status"`
	DurationMs   int        `db:"duration_ms"`
	ErrorMessage string     `db:"error_message"`
	ExecutedAt   time.Time  `db:"executed_at"`
}

// MaintenanceWindowRecord represents a maintenance window.
type MaintenanceWindowRecord struct {
	ID              uuid.UUID       `db:"id"`
	Name            string          `db:"name"`
	Description     string          `db:"description"`
	HostID          string          `db:"host_id"`
	HostName        string          `db:"host_name"`
	Schedule        string          `db:"schedule"`
	DurationMinutes int             `db:"duration_minutes"`
	Actions         json.RawMessage `db:"actions"`
	IsEnabled       bool            `db:"is_enabled"`
	IsActive        bool            `db:"is_active"`
	LastRunAt       *time.Time      `db:"last_run_at"`
	LastStatus      string          `db:"last_status"`
	CreatedBy       *uuid.UUID      `db:"created_by"`
	CreatedAt       time.Time       `db:"created_at"`
	UpdatedAt       time.Time       `db:"updated_at"`
}

// GitOpsPipelineRecord represents a GitOps pipeline.
type GitOpsPipelineRecord struct {
	ID            uuid.UUID  `db:"id"`
	Name          string     `db:"name"`
	Repository    string     `db:"repository"`
	Branch        string     `db:"branch"`
	Provider      string     `db:"provider"`
	TargetStack   string     `db:"target_stack"`
	TargetService string     `db:"target_service"`
	Action        string     `db:"action"`
	TriggerType   string     `db:"trigger_type"`
	Schedule      string     `db:"schedule"`
	IsEnabled     bool       `db:"is_enabled"`
	AutoRollback  bool       `db:"auto_rollback"`
	DeployCount   int        `db:"deploy_count"`
	LastDeployAt  *time.Time `db:"last_deploy_at"`
	LastStatus    string     `db:"last_status"`
	CreatedBy     *uuid.UUID `db:"created_by"`
	CreatedAt     time.Time  `db:"created_at"`
	UpdatedAt     time.Time  `db:"updated_at"`
}

// GitOpsDeploymentRecord represents a deployment.
type GitOpsDeploymentRecord struct {
	ID           uuid.UUID  `db:"id"`
	PipelineID   *uuid.UUID `db:"pipeline_id"`
	PipelineName string     `db:"pipeline_name"`
	Repository   string     `db:"repository"`
	Branch       string     `db:"branch"`
	CommitSHA    string     `db:"commit_sha"`
	CommitMsg    string     `db:"commit_msg"`
	Action       string     `db:"action"`
	Status       string     `db:"status"`
	DurationMs   int        `db:"duration_ms"`
	StartedAt    time.Time  `db:"started_at"`
	FinishedAt   *time.Time `db:"finished_at"`
	ErrorMessage string     `db:"error_message"`
	TriggeredBy  string     `db:"triggered_by"`
}

// ResourceQuotaRecord represents a resource quota.
type ResourceQuotaRecord struct {
	ID           uuid.UUID  `db:"id"`
	Name         string     `db:"name"`
	Scope        string     `db:"scope"`
	ScopeName    string     `db:"scope_name"`
	ResourceType string     `db:"resource_type"`
	LimitValue   int64      `db:"limit_value"`
	AlertAt      int        `db:"alert_at"`
	IsEnabled    bool       `db:"is_enabled"`
	CreatedBy    *uuid.UUID `db:"created_by"`
	CreatedAt    time.Time  `db:"created_at"`
	UpdatedAt    time.Time  `db:"updated_at"`
}

// ContainerTemplateRecord represents a container template.
type ContainerTemplateRecord struct {
	ID            uuid.UUID       `db:"id"`
	Name          string          `db:"name"`
	Description   string          `db:"description"`
	Category      string          `db:"category"`
	Image         string          `db:"image"`
	Tag           string          `db:"tag"`
	Ports         []string        `db:"ports"`
	Volumes       []string        `db:"volumes"`
	EnvVars       json.RawMessage `db:"env_vars"`
	Network       string          `db:"network"`
	RestartPolicy string          `db:"restart_policy"`
	Command       string          `db:"command"`
	IsPublic      bool            `db:"is_public"`
	UsageCount    int             `db:"usage_count"`
	CreatedBy     *uuid.UUID      `db:"created_by"`
	CreatedAt     time.Time       `db:"created_at"`
	UpdatedAt     time.Time       `db:"updated_at"`
}

// TrackedVulnRecord represents a tracked vulnerability.
type TrackedVulnRecord struct {
	ID              uuid.UUID  `db:"id"`
	CVEID           string     `db:"cve_id"`
	Title           string     `db:"title"`
	Description     string     `db:"description"`
	Severity        string     `db:"severity"`
	CVSSScore       string     `db:"cvss_score"`
	Package         string     `db:"package"`
	InstalledVer    string     `db:"installed_ver"`
	FixedVer        string     `db:"fixed_ver"`
	AffectedImages  []string   `db:"affected_images"`
	ContainerCount  int        `db:"container_count"`
	Status          string     `db:"status"`
	Priority        string     `db:"priority"`
	SLADeadline     *time.Time `db:"sla_deadline"`
	Assignee        string     `db:"assignee"`
	AssigneeID      *uuid.UUID `db:"assignee_id"`
	Notes           string     `db:"notes"`
	ResolutionNotes string     `db:"resolution_notes"`
	ResolvedScanID  *uuid.UUID `db:"resolved_scan_id"`
	DetectedAt      time.Time  `db:"detected_at"`
	ResolvedAt      *time.Time `db:"resolved_at"`
	CreatedAt       time.Time  `db:"created_at"`
	UpdatedAt       time.Time  `db:"updated_at"`
}

// VulnWeeklyTrend represents a row from the vuln_weekly_trend view.
type VulnWeeklyTrend struct {
	Week             time.Time `db:"week" json:"week"`
	Opened           int       `db:"opened" json:"opened"`
	ResolvedSameWeek int       `db:"resolved_same_week" json:"resolved_same_week"`
}

// ImageVulnCount represents an image and its open vulnerability count.
type ImageVulnCount struct {
	Image string `json:"image"`
	Count int    `json:"count"`
}
