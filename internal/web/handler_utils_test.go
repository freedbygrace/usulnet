// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"testing"

	quotastmpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/quotas"
)

// ============================================================================
// formatBytes tests
// ============================================================================

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		name  string
		bytes int64
		want  string
	}{
		{"zero bytes", 0, "0 B"},
		{"small bytes", 512, "512 B"},
		{"1023 bytes", 1023, "1023 B"},
		{"exactly 1 KB", 1024, "1.0 KB"},
		{"1.5 KB", 1536, "1.5 KB"},
		{"exactly 1 MB", 1024 * 1024, "1.0 MB"},
		{"500 MB", 500 * 1024 * 1024, "500.0 MB"},
		{"exactly 1 GB", 1024 * 1024 * 1024, "1.0 GB"},
		{"2.5 GB", int64(2.5 * 1024 * 1024 * 1024), "2.5 GB"},
		{"exactly 1 TB", int64(1024) * 1024 * 1024 * 1024, "1.0 TB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatBytes(tt.bytes)
			if got != tt.want {
				t.Errorf("formatBytes(%d) = %q, want %q", tt.bytes, got, tt.want)
			}
		})
	}
}

// ============================================================================
// truncateID tests
// ============================================================================

func TestTruncateID(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want string
	}{
		{"long docker ID", "abc123def456789", "abc123def456"},
		{"exactly 12 chars", "abc123def456", "abc123def456"},
		{"short ID", "abc123", "abc123"},
		{"empty ID", "", ""},
		{"single char", "a", "a"},
		{"full SHA256", "sha256:abc123def456789012345678901234567890", "sha256:abc12"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateID(tt.id)
			if got != tt.want {
				t.Errorf("truncateID(%q) = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}

// ============================================================================
// formatQuotaValue tests
// ============================================================================

func TestFormatQuotaValue(t *testing.T) {
	tests := []struct {
		name         string
		resourceType string
		value        int64
		want         string
	}{
		{"cpu cores", "cpu", 8, "8 cores"},
		{"cpu single core", "cpu", 1, "1 cores"},
		{"memory in bytes", "memory", 1024 * 1024 * 1024, "1.0 GB"},
		{"disk in bytes", "disk", 500 * 1024 * 1024, "500.0 MB"},
		{"containers count", "containers", 50, "50"},
		{"images count", "images", 100, "100"},
		{"volumes count", "volumes", 25, "25"},
		{"unknown type", "unknown", 42, "42"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatQuotaValue(tt.resourceType, tt.value)
			if got != tt.want {
				t.Errorf("formatQuotaValue(%q, %d) = %q, want %q", tt.resourceType, tt.value, got, tt.want)
			}
		})
	}
}

// ============================================================================
// getQuotaCurrentUsage tests
// ============================================================================

func TestGetQuotaCurrentUsage(t *testing.T) {
	usage := quotastmpl.ResourceUsageView{
		ContainersTotal:   25,
		ContainersRunning: 20,
		ContainersStopped: 5,
		ImagesTotal:       50,
		VolumesTotal:      10,
		VolumesInUse:      7,
		CPUCores:          8,
	}

	tests := []struct {
		name         string
		resourceType string
		limit        int64
		want         int64
	}{
		{"cpu usage", "cpu", 16, 8},
		{"containers usage", "containers", 100, 25},
		{"images usage", "images", 200, 50},
		{"volumes usage", "volumes", 50, 10},
		{"memory returns 0 (not available)", "memory", 1024, 0},
		{"disk returns 0 (not available)", "disk", 1024, 0},
		{"unknown type returns 0", "unknown", 100, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getQuotaCurrentUsage(tt.resourceType, tt.limit, usage)
			if got != tt.want {
				t.Errorf("getQuotaCurrentUsage(%q, %d, usage) = %d, want %d",
					tt.resourceType, tt.limit, got, tt.want)
			}
		})
	}
}
