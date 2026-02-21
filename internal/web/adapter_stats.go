// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	containersvc "github.com/fr4nsys/usulnet/internal/services/container"
	hostsvc "github.com/fr4nsys/usulnet/internal/services/host"
	imagesvc "github.com/fr4nsys/usulnet/internal/services/image"
	networksvc "github.com/fr4nsys/usulnet/internal/services/network"
	securitysvc "github.com/fr4nsys/usulnet/internal/services/security"
	stacksvc "github.com/fr4nsys/usulnet/internal/services/stack"
	volumesvc "github.com/fr4nsys/usulnet/internal/services/volume"
)

type statsAdapter struct {
	containerSvc *containersvc.Service
	imageSvc     *imagesvc.Service
	volumeSvc    *volumesvc.Service
	networkSvc   *networksvc.Service
	stackSvc     *stacksvc.Service
	securitySvc  *securitysvc.Service
	hostSvc      *hostsvc.Service
	hostID       uuid.UUID
}

func (a *statsAdapter) GetGlobalStats(ctx context.Context) (*GlobalStats, error) {
	stats := &GlobalStats{}

	// Resolve host for all stats queries
	statsHostID := resolveHostID(ctx, a.hostID)

	// Containers - use Docker Info for accurate counts if host service available
	if a.hostSvc != nil {
		info, err := a.hostSvc.GetDockerInfo(ctx, statsHostID)
		if err == nil && info != nil {
			stats.ContainersTotal = info.Containers
			stats.ContainersRunning = info.ContainersRunning
			stats.ContainersStopped = info.ContainersStopped
			stats.ContainersPaused = info.ContainersPaused
		}
	} else if a.containerSvc != nil {
		// Fallback: count from database
		runningState := models.ContainerStateRunning
		stoppedState := models.ContainerStateExited
		pausedState := models.ContainerStatePaused

		runningContainers, _, _ := a.containerSvc.List(ctx, postgres.ContainerListOptions{
			HostID:  &statsHostID,
			State:   &runningState,
			Page:    1,
			PerPage: 1000,
		})
		stoppedContainers, _, _ := a.containerSvc.List(ctx, postgres.ContainerListOptions{
			HostID:  &statsHostID,
			State:   &stoppedState,
			Page:    1,
			PerPage: 1000,
		})
		pausedContainers, _, _ := a.containerSvc.List(ctx, postgres.ContainerListOptions{
			HostID:  &statsHostID,
			State:   &pausedState,
			Page:    1,
			PerPage: 1000,
		})

		stats.ContainersRunning = len(runningContainers)
		stats.ContainersStopped = len(stoppedContainers)
		stats.ContainersPaused = len(pausedContainers)
		stats.ContainersTotal = stats.ContainersRunning + stats.ContainersStopped + stats.ContainersPaused
	}

	// Images
	if a.imageSvc != nil {
		images, _ := a.imageSvc.List(ctx, resolveHostID(ctx, a.hostID))
		stats.ImagesCount = len(images)
	}

	// Volumes
	if a.volumeSvc != nil {
		volumes, _ := a.volumeSvc.List(ctx, resolveHostID(ctx, a.hostID))
		stats.VolumesCount = len(volumes)
	}

	// Networks
	if a.networkSvc != nil {
		networks, _ := a.networkSvc.List(ctx, resolveHostID(ctx, a.hostID))
		stats.NetworksCount = len(networks)
	}

	// Stacks
	if a.stackSvc != nil {
		stacks, _, _ := a.stackSvc.List(ctx, postgres.StackListOptions{Page: 1, PerPage: 1000})
		stats.StacksCount = len(stacks)
	}

	// Hosts
	if a.hostSvc != nil {
		onlineHosts := a.hostSvc.GetOnlineHosts()
		stats.HostsOnline = len(onlineHosts)
		hostList, total, _ := a.hostSvc.List(ctx, postgres.HostListOptions{Limit: 1})
		if total > 0 {
			stats.HostsTotal = int(total)
		} else {
			stats.HostsTotal = len(hostList)
		}
	}

	// Security
	if a.securitySvc != nil {
		secHostID := resolveHostID(ctx, a.hostID)
		summary, _ := a.securitySvc.GetSecuritySummary(ctx, &secHostID)
		if summary != nil {
			if summary.SeverityCounts != nil {
				stats.SecurityIssues = summary.SeverityCounts[models.IssueSeverityCritical] +
					summary.SeverityCounts[models.IssueSeverityHigh]
			}
			stats.SecurityScore = int(summary.AverageScore)
			stats.SecurityGrade = securityScoreToGrade(int(summary.AverageScore))
		}
	}

	return stats, nil
}

// securityScoreToGrade converts a numeric security score to a letter grade.
func securityScoreToGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	case score > 0:
		return "F"
	default:
		return "-"
	}
}
