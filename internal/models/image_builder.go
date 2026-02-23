// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// BuildJobStatus represents the status of an image build job.
type BuildJobStatus string

const (
	BuildJobStatusPending   BuildJobStatus = "pending"
	BuildJobStatusBuilding  BuildJobStatus = "building"
	BuildJobStatusSuccess   BuildJobStatus = "success"
	BuildJobStatusFailed    BuildJobStatus = "failed"
	BuildJobStatusCancelled BuildJobStatus = "cancelled"
)

// ImageBuildJob represents a tracked image build operation.
type ImageBuildJob struct {
	ID           uuid.UUID       `json:"id" db:"id"`
	HostID       uuid.UUID       `json:"host_id" db:"host_id"`
	Name         string          `json:"name" db:"name"`
	Tags         []string        `json:"tags" db:"tags"`
	Dockerfile   string          `json:"dockerfile" db:"dockerfile"`
	ContextPath  string          `json:"context_path" db:"context_path"`
	BuildArgs    json.RawMessage `json:"build_args" db:"build_args"`
	Labels       json.RawMessage `json:"labels" db:"labels"`
	Target       string          `json:"target" db:"target"`
	NoCache      bool            `json:"no_cache" db:"no_cache"`
	Pull         bool            `json:"pull" db:"pull"`
	Platform     string          `json:"platform" db:"platform"`
	Status       BuildJobStatus  `json:"status" db:"status"`
	Output       string          `json:"output" db:"output"`
	ErrorMessage string          `json:"error_message" db:"error_message"`
	ImageID      string          `json:"image_id" db:"image_id"`
	ImageSize    int64           `json:"image_size" db:"image_size"`
	DurationMs   int             `json:"duration_ms" db:"duration_ms"`
	CreatedBy    *uuid.UUID      `json:"created_by,omitempty" db:"created_by"`
	StartedAt    *time.Time      `json:"started_at,omitempty" db:"started_at"`
	CompletedAt  *time.Time      `json:"completed_at,omitempty" db:"completed_at"`
	CreatedAt    time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at" db:"updated_at"`
}

// DockerfileTemplate represents a reusable Dockerfile template.
type DockerfileTemplate struct {
	ID            uuid.UUID       `json:"id" db:"id"`
	HostID        uuid.UUID       `json:"host_id" db:"host_id"`
	Name          string          `json:"name" db:"name"`
	Description   string          `json:"description" db:"description"`
	Category      string          `json:"category" db:"category"`
	Dockerfile    string          `json:"dockerfile" db:"dockerfile"`
	DefaultArgs   json.RawMessage `json:"default_args" db:"default_args"`
	DefaultLabels json.RawMessage `json:"default_labels" db:"default_labels"`
	IsBuiltin     bool            `json:"is_builtin" db:"is_builtin"`
	CreatedBy     *uuid.UUID      `json:"created_by,omitempty" db:"created_by"`
	CreatedAt     time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at" db:"updated_at"`
}

// ImageBuildJobStats holds aggregate stats for the image builder dashboard.
type ImageBuildJobStats struct {
	TotalBuilds   int        `json:"total_builds"`
	Successful    int        `json:"successful"`
	Failed        int        `json:"failed"`
	Building      int        `json:"building"`
	AvgDurationMs int        `json:"avg_duration_ms"`
	LastBuildAt   *time.Time `json:"last_build_at,omitempty"`
}
