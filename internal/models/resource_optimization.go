// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// Recommendation type constants.
const (
	RecommendDownsizeMemory = "downsize_memory"
	RecommendDownsizeCPU    = "downsize_cpu"
	RecommendRemoveIdle     = "remove_idle"
	RecommendAddLimit       = "add_limit"
	RecommendRemoveStopped  = "remove_stopped"
)

// Recommendation status constants.
const (
	RecommendStatusOpen      = "open"
	RecommendStatusApplied   = "applied"
	RecommendStatusDismissed = "dismissed"
)

// ResourceUsageSample represents a single time-series sample of container resource usage.
type ResourceUsageSample struct {
	ID               uuid.UUID `json:"id" db:"id"`
	ContainerID      string    `json:"container_id" db:"container_id"`
	ContainerName    string    `json:"container_name" db:"container_name"`
	HostID           string    `json:"host_id" db:"host_id"`
	SampledAt        time.Time `json:"sampled_at" db:"sampled_at"`
	CPUUsagePercent  float64   `json:"cpu_usage_percent" db:"cpu_usage_percent"`
	CPUPeakPercent   float64   `json:"cpu_peak_percent" db:"cpu_peak_percent"`
	MemoryUsageBytes int64     `json:"memory_usage_bytes" db:"memory_usage_bytes"`
	MemoryLimitBytes int64     `json:"memory_limit_bytes" db:"memory_limit_bytes"`
	MemoryPeakBytes  int64     `json:"memory_peak_bytes" db:"memory_peak_bytes"`
	NetworkRxBytes   int64     `json:"network_rx_bytes" db:"network_rx_bytes"`
	NetworkTxBytes   int64     `json:"network_tx_bytes" db:"network_tx_bytes"`
	DiskReadBytes    int64     `json:"disk_read_bytes" db:"disk_read_bytes"`
	DiskWriteBytes   int64     `json:"disk_write_bytes" db:"disk_write_bytes"`
	PidsCurrent      int       `json:"pids_current" db:"pids_current"`
}

// ResourceUsageHourly represents hourly aggregated resource usage for a container.
type ResourceUsageHourly struct {
	ID               uuid.UUID `json:"id" db:"id"`
	ContainerID      string    `json:"container_id" db:"container_id"`
	ContainerName    string    `json:"container_name" db:"container_name"`
	Hour             time.Time `json:"hour" db:"hour"`
	CPUAvg           float64   `json:"cpu_avg" db:"cpu_avg"`
	CPUPeak          float64   `json:"cpu_peak" db:"cpu_peak"`
	MemoryAvgBytes   int64     `json:"memory_avg_bytes" db:"memory_avg_bytes"`
	MemoryPeakBytes  int64     `json:"memory_peak_bytes" db:"memory_peak_bytes"`
	MemoryLimitBytes int64     `json:"memory_limit_bytes" db:"memory_limit_bytes"`
	NetworkRxTotal   int64     `json:"network_rx_total" db:"network_rx_total"`
	NetworkTxTotal   int64     `json:"network_tx_total" db:"network_tx_total"`
	SampleCount      int       `json:"sample_count" db:"sample_count"`
}

// ResourceUsageDaily represents daily aggregated resource usage for a container.
type ResourceUsageDaily struct {
	ID               uuid.UUID `json:"id" db:"id"`
	ContainerID      string    `json:"container_id" db:"container_id"`
	ContainerName    string    `json:"container_name" db:"container_name"`
	Day              time.Time `json:"day" db:"day"`
	CPUAvg           float64   `json:"cpu_avg" db:"cpu_avg"`
	CPUPeak          float64   `json:"cpu_peak" db:"cpu_peak"`
	MemoryAvgBytes   int64     `json:"memory_avg_bytes" db:"memory_avg_bytes"`
	MemoryPeakBytes  int64     `json:"memory_peak_bytes" db:"memory_peak_bytes"`
	MemoryLimitBytes int64     `json:"memory_limit_bytes" db:"memory_limit_bytes"`
	NetworkRxTotal   int64     `json:"network_rx_total" db:"network_rx_total"`
	NetworkTxTotal   int64     `json:"network_tx_total" db:"network_tx_total"`
	SampleCount      int       `json:"sample_count" db:"sample_count"`
}

// ResourceRecommendation represents an optimization recommendation for a container.
type ResourceRecommendation struct {
	ID               uuid.UUID  `json:"id" db:"id"`
	ContainerID      string     `json:"container_id" db:"container_id"`
	ContainerName    string     `json:"container_name" db:"container_name"`
	Type             string     `json:"type" db:"type"`
	Severity         string     `json:"severity" db:"severity"`
	Status           string     `json:"status" db:"status"`
	CurrentValue     string     `json:"current_value" db:"current_value"`
	RecommendedValue string     `json:"recommended_value" db:"recommended_value"`
	EstimatedSavings string     `json:"estimated_savings" db:"estimated_savings"`
	Reason           string     `json:"reason" db:"reason"`
	CreatedAt        time.Time  `json:"created_at" db:"created_at"`
	ResolvedAt       *time.Time `json:"resolved_at,omitempty" db:"resolved_at"`
	ResolvedBy       *uuid.UUID `json:"resolved_by,omitempty" db:"resolved_by"`
}

// RecommendationListOptions holds filtering and pagination options for listing recommendations.
type RecommendationListOptions struct {
	Type     string
	Status   string
	Severity string
	Limit    int
	Offset   int
}

// ResourceOptStats holds aggregate statistics about resource optimization recommendations.
type ResourceOptStats struct {
	TotalRecommendations int                       `json:"total_recommendations"`
	OpenRecommendations  int                       `json:"open_recommendations"`
	ByType               map[string]int            `json:"by_type"`
	ByStatus             map[string]int            `json:"by_status"`
	TopContainers        []ContainerRecommendCount `json:"top_containers"`
}

// ContainerRecommendCount pairs a container name with its recommendation count.
type ContainerRecommendCount struct {
	ContainerName string `json:"container_name"`
	Count         int    `json:"count"`
}

// ContainerUsageSummary provides a high-level usage overview for a single container.
type ContainerUsageSummary struct {
	ContainerID   string    `json:"container_id"`
	ContainerName string    `json:"container_name"`
	CPUAvg        float64   `json:"cpu_avg"`
	CPUPeak       float64   `json:"cpu_peak"`
	MemoryAvg     int64     `json:"memory_avg"`
	MemoryPeak    int64     `json:"memory_peak"`
	MemoryLimit   int64     `json:"memory_limit"`
	LastSeen      time.Time `json:"last_seen"`
}
