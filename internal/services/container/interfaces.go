// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package container

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// ContainerRepository defines persistence operations for containers.
type ContainerRepository interface {
	Upsert(ctx context.Context, container *models.Container) error
	UpsertBatch(ctx context.Context, containers []*models.Container) error
	GetByHostAndID(ctx context.Context, hostID uuid.UUID, containerID string) (*models.Container, error)
	GetByName(ctx context.Context, hostID uuid.UUID, name string) (*models.Container, error)
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, opts postgres.ContainerListOptions) ([]*models.Container, int64, error)
	ListByHost(ctx context.Context, hostID uuid.UUID) ([]*models.Container, error)
	ListWithUpdatesAvailable(ctx context.Context, hostID *uuid.UUID) ([]*models.Container, error)
	ListBySecurityGrade(ctx context.Context, grade string, hostID *uuid.UUID) ([]*models.Container, error)
	UpdateState(ctx context.Context, id string, state models.ContainerState, status string) error
	UpdateSecurityInfo(ctx context.Context, id string, score int, grade string) error
	GetContainerIDs(ctx context.Context, hostID uuid.UUID) ([]string, error)
	GetStats(ctx context.Context, hostID *uuid.UUID) (*postgres.ContainerStats, error)
	GetStatsHistory(ctx context.Context, containerID string, since time.Time, limit int) ([]*models.ContainerStats, error)
	DeleteOldStats(ctx context.Context, olderThan time.Duration) (int64, error)
	DeleteOldLogs(ctx context.Context, olderThan time.Duration) (int64, error)
}

// HostService defines the host operations needed by the container service.
type HostService interface {
	GetClient(ctx context.Context, hostID uuid.UUID) (docker.ClientAPI, error)
	List(ctx context.Context, opts postgres.HostListOptions) ([]*models.Host, int64, error)
}
