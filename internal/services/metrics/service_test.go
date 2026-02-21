// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package metrics

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/scheduler/workers"
)

// ---------------------------------------------------------------------------
// FormatBytes tests
// ---------------------------------------------------------------------------

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1024 * 1024, "1.0 MB"},
		{1024 * 1024 * 512, "512.0 MB"},
		{1024 * 1024 * 1024, "1.0 GB"},
		{int64(1024*1024*1024) * 4, "4.0 GB"},
		{int64(1024*1024*1024) * 1024, "1.0 TB"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := FormatBytes(tt.input)
			if got != tt.want {
				t.Errorf("FormatBytes(%d) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// FormatUptime tests
// ---------------------------------------------------------------------------

func TestFormatUptime(t *testing.T) {
	tests := []struct {
		seconds int64
		want    string
	}{
		{0, "0m"},
		{59, "0m"},
		{60, "1m"},
		{3600, "1h 0m"},
		{3661, "1h 1m"},
		{86400, "1d 0h 0m"},
		{90061, "1d 1h 1m"},
		{172800, "2d 0h 0m"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := FormatUptime(tt.seconds)
			if got != tt.want {
				t.Errorf("FormatUptime(%d) = %q, want %q", tt.seconds, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// sanitizeLabel tests
// ---------------------------------------------------------------------------

func TestSanitizeLabel(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"simple", "simple"},
		{`has"quotes`, `has\"quotes`},
		{"has\nnewline", "hasnewline"},
		{"normal-label", "normal-label"},
		{"", ""},
	}
	for _, tt := range tests {
		got := sanitizeLabel(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeLabel(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// ptr helper tests
// ---------------------------------------------------------------------------

func TestPtrHelpers(t *testing.T) {
	f := ptr(3.14)
	if *f != 3.14 {
		t.Errorf("ptr(3.14) = %v", *f)
	}

	i := ptrI64(42)
	if *i != 42 {
		t.Errorf("ptrI64(42) = %v", *i)
	}

	n := ptrInt(7)
	if *n != 7 {
		t.Errorf("ptrInt(7) = %v", *n)
	}

	s := ptrStr("hello")
	if *s != "hello" {
		t.Errorf("ptrStr(\"hello\") = %v", *s)
	}

	// Empty string → nil
	if ptrStr("") != nil {
		t.Error("ptrStr(\"\") should return nil")
	}
}

// ---------------------------------------------------------------------------
// hostMetricsToModel tests
// ---------------------------------------------------------------------------

func TestHostMetricsToModel(t *testing.T) {
	hostID := uuid.New()
	now := time.Now()
	h := &workers.HostMetrics{
		HostID:            hostID,
		CPUUsagePercent:   45.5,
		MemoryUsed:        4 * 1024 * 1024 * 1024,
		MemoryTotal:       16 * 1024 * 1024 * 1024,
		MemoryPercent:     25.0,
		DiskUsed:          100 * 1024 * 1024 * 1024,
		DiskTotal:         500 * 1024 * 1024 * 1024,
		DiskPercent:       20.0,
		NetworkRxBytes:    1000000,
		NetworkTxBytes:    500000,
		ContainersTotal:   10,
		ContainersRunning: 7,
		ContainersStopped: 3,
		ImagesTotal:       25,
		VolumesTotal:      5,
		CollectedAt:       now,
	}

	m := hostMetricsToModel(hostID, h, now)

	if m.HostID != hostID {
		t.Errorf("HostID = %v, want %v", m.HostID, hostID)
	}
	if m.MetricType != models.MetricTypeHost {
		t.Errorf("MetricType = %q, want %q", m.MetricType, models.MetricTypeHost)
	}
	if *m.CPUPercent != 45.5 {
		t.Errorf("CPUPercent = %v, want 45.5", *m.CPUPercent)
	}
	if *m.MemoryUsed != 4*1024*1024*1024 {
		t.Errorf("MemoryUsed = %v", *m.MemoryUsed)
	}
	if *m.ContainersTotal != 10 {
		t.Errorf("ContainersTotal = %v, want 10", *m.ContainersTotal)
	}
	if *m.ContainersRunning != 7 {
		t.Errorf("ContainersRunning = %v, want 7", *m.ContainersRunning)
	}
	if m.CollectedAt != now {
		t.Errorf("CollectedAt = %v, want %v", m.CollectedAt, now)
	}
}

func TestHostMetricsToModel_ZeroCollectedAt(t *testing.T) {
	hostID := uuid.New()
	now := time.Now()
	h := &workers.HostMetrics{
		CollectedAt: now,
	}

	m := hostMetricsToModel(hostID, h, time.Time{})
	if m.CollectedAt != now {
		t.Error("should use host's CollectedAt when parameter is zero")
	}
}

// ---------------------------------------------------------------------------
// containerMetricsToModel tests
// ---------------------------------------------------------------------------

func TestContainerMetricsToModel(t *testing.T) {
	hostID := uuid.New()
	now := time.Now()
	cm := &workers.ContainerMetrics{
		ContainerID:     "abc123def456",
		ContainerName:   "web-server",
		CPUUsagePercent: 12.5,
		MemoryUsed:      256 * 1024 * 1024,
		MemoryLimit:     512 * 1024 * 1024,
		MemoryPercent:   50.0,
		NetworkRxBytes:  100000,
		NetworkTxBytes:  50000,
		BlockRead:       1024,
		BlockWrite:      2048,
		PIDs:            15,
		State:           "running",
		Health:          "healthy",
		Uptime:          3600,
		CollectedAt:     now,
	}

	m := containerMetricsToModel(hostID, cm, now)

	if m.MetricType != models.MetricTypeContainer {
		t.Errorf("MetricType = %q, want %q", m.MetricType, models.MetricTypeContainer)
	}
	if *m.ContainerID != "abc123def456" {
		t.Errorf("ContainerID = %q", *m.ContainerID)
	}
	if *m.ContainerName != "web-server" {
		t.Errorf("ContainerName = %q", *m.ContainerName)
	}
	if *m.CPUPercent != 12.5 {
		t.Errorf("CPUPercent = %v, want 12.5", *m.CPUPercent)
	}
	if *m.MemoryUsed != 256*1024*1024 {
		t.Errorf("MemoryUsed = %v", *m.MemoryUsed)
	}
	if *m.PIDs != 15 {
		t.Errorf("PIDs = %v, want 15", *m.PIDs)
	}
	if *m.State != "running" {
		t.Errorf("State = %q, want %q", *m.State, "running")
	}
	if *m.Health != "healthy" {
		t.Errorf("Health = %q, want %q", *m.Health, "healthy")
	}
	if *m.UptimeSeconds != 3600 {
		t.Errorf("UptimeSeconds = %v, want 3600", *m.UptimeSeconds)
	}
}

func TestContainerMetricsToModel_EmptyStringsNil(t *testing.T) {
	hostID := uuid.New()
	cm := &workers.ContainerMetrics{
		ContainerID:   "",
		ContainerName: "",
		State:         "",
		Health:        "",
	}

	m := containerMetricsToModel(hostID, cm, time.Now())
	if m.ContainerID != nil {
		t.Error("empty ContainerID should be nil")
	}
	if m.ContainerName != nil {
		t.Error("empty ContainerName should be nil")
	}
	if m.State != nil {
		t.Error("empty State should be nil")
	}
	if m.Health != nil {
		t.Error("empty Health should be nil")
	}
}

// ---------------------------------------------------------------------------
// FormatPrometheus tests (infrastructure metrics)
// ---------------------------------------------------------------------------

func TestFormatPrometheus_Empty(t *testing.T) {
	result := FormatPrometheus(nil, nil)
	if result != "" {
		t.Errorf("expected empty for nil inputs, got %q", result)
	}
}

func TestFormatPrometheus_HostMetrics(t *testing.T) {
	hostID := uuid.New()
	hosts := map[uuid.UUID]*workers.HostMetrics{
		hostID: {
			HostID:            hostID,
			CPUUsagePercent:   42.5,
			MemoryUsed:        8 * 1024 * 1024 * 1024,
			MemoryTotal:       16 * 1024 * 1024 * 1024,
			MemoryPercent:     50.0,
			ContainersTotal:   5,
			ContainersRunning: 3,
			ContainersStopped: 2,
		},
	}

	result := FormatPrometheus(hosts, nil)

	checks := []string{
		"usulnet_host_cpu_percent",
		"usulnet_host_memory_used_bytes",
		"usulnet_host_memory_total_bytes",
		"usulnet_host_memory_percent",
		"usulnet_host_containers_total",
		"usulnet_host_containers_running",
		"usulnet_host_containers_stopped",
		"# HELP",
		"# TYPE",
		"gauge",
	}
	for _, check := range checks {
		if !strings.Contains(result, check) {
			t.Errorf("result should contain %q", check)
		}
	}
}

func TestFormatPrometheus_ContainerMetrics(t *testing.T) {
	hostID := uuid.New()
	containers := map[uuid.UUID][]*workers.ContainerMetrics{
		hostID: {
			{
				ContainerID:     "abc123def456789",
				ContainerName:   "web-app",
				CPUUsagePercent: 25.0,
				MemoryUsed:      128 * 1024 * 1024,
				State:           "running",
			},
		},
	}

	result := FormatPrometheus(nil, containers)

	checks := []string{
		"usulnet_container_cpu_percent",
		"usulnet_container_memory_used_bytes",
		"usulnet_container_running",
		`name="web-app"`,
		`id="abc123def456"`, // truncated to 12 chars
	}
	for _, check := range checks {
		if !strings.Contains(result, check) {
			t.Errorf("result should contain %q", check)
		}
	}

	// Running container should have state=1
	if !strings.Contains(result, "1.0000") {
		t.Error("running container should have state gauge = 1")
	}
}

func TestFormatPrometheus_ShortContainerID(t *testing.T) {
	hostID := uuid.New()
	containers := map[uuid.UUID][]*workers.ContainerMetrics{
		hostID: {
			{
				ContainerID:   "short",
				ContainerName: "test",
			},
		},
	}

	result := FormatPrometheus(nil, containers)
	if !strings.Contains(result, `id="short"`) {
		t.Error("short container ID should not be truncated")
	}
}

// ---------------------------------------------------------------------------
// BusinessMetrics tests
// ---------------------------------------------------------------------------

func TestNewBusinessMetrics(t *testing.T) {
	bm := NewBusinessMetrics()
	if bm == nil {
		t.Fatal("NewBusinessMetrics() returned nil")
	}
	if bm.LicenseType != "community" {
		t.Errorf("LicenseType = %q, want %q", bm.LicenseType, "community")
	}
	if bm.LicenseDaysLeft != -1 {
		t.Errorf("LicenseDaysLeft = %d, want -1", bm.LicenseDaysLeft)
	}
	if bm.ContainersByState == nil {
		t.Error("ContainersByState should be initialized")
	}
}

func TestRecordAgentsConnected(t *testing.T) {
	bm := NewBusinessMetrics()
	bm.RecordAgentsConnected(5)
	if bm.AgentsConnected != 5 {
		t.Errorf("AgentsConnected = %d, want 5", bm.AgentsConnected)
	}
}

func TestRecordContainersByState(t *testing.T) {
	bm := NewBusinessMetrics()
	bm.RecordContainersByState("running", 10)
	bm.RecordContainersByState("stopped", 3)

	if bm.ContainersByState["running"] != 10 {
		t.Errorf("running = %d, want 10", bm.ContainersByState["running"])
	}
	if bm.ContainersByState["stopped"] != 3 {
		t.Errorf("stopped = %d, want 3", bm.ContainersByState["stopped"])
	}
}

func TestRecordContainersByHostState(t *testing.T) {
	bm := NewBusinessMetrics()
	bm.RecordContainersByHostState("host-1", "running", 5)
	bm.RecordContainersByHostState("host-1", "stopped", 2)
	bm.RecordContainersByHostState("host-2", "running", 3)

	if bm.ContainersByHost["host-1"]["running"] != 5 {
		t.Error("host-1 running != 5")
	}
	if bm.ContainersByHost["host-2"]["running"] != 3 {
		t.Error("host-2 running != 3")
	}
}

func TestRecordVulnerabilities(t *testing.T) {
	bm := NewBusinessMetrics()
	bm.RecordVulnerabilities("CRITICAL", 2)
	bm.RecordVulnerabilities("High", 5)

	if bm.ImagesWithVulns["critical"] != 2 {
		t.Errorf("critical = %d, want 2", bm.ImagesWithVulns["critical"])
	}
	if bm.ImagesWithVulns["high"] != 5 {
		t.Errorf("high = %d, want 5", bm.ImagesWithVulns["high"])
	}
}

func TestRecordBackup(t *testing.T) {
	bm := NewBusinessMetrics()
	bm.RecordBackup("success")
	bm.RecordBackup("success")
	bm.RecordBackup("failure")

	if bm.BackupsTotal["success"] != 2 {
		t.Errorf("success = %d, want 2", bm.BackupsTotal["success"])
	}
	if bm.BackupsTotal["failure"] != 1 {
		t.Errorf("failure = %d, want 1", bm.BackupsTotal["failure"])
	}
}

func TestRecordSecurityScan(t *testing.T) {
	bm := NewBusinessMetrics()
	bm.RecordSecurityScan("completed")
	bm.RecordSecurityScan("completed")
	bm.RecordSecurityScan("failed")

	if bm.SecurityScansTotal["completed"] != 2 {
		t.Errorf("completed = %d, want 2", bm.SecurityScansTotal["completed"])
	}
}

func TestRecordAPIRequest(t *testing.T) {
	bm := NewBusinessMetrics()
	bm.RecordAPIRequest("GET", 200)
	bm.RecordAPIRequest("POST", 201)
	bm.RecordAPIRequest("GET", 200)

	if bm.APIRequestsTotal["GET:200"] != 2 {
		t.Errorf("GET:200 = %d, want 2", bm.APIRequestsTotal["GET:200"])
	}
	if bm.APIRequestsTotal["POST:201"] != 1 {
		t.Errorf("POST:201 = %d, want 1", bm.APIRequestsTotal["POST:201"])
	}
}

func TestRecordAuthAttempt(t *testing.T) {
	bm := NewBusinessMetrics()
	bm.RecordAuthAttempt("success")
	bm.RecordAuthAttempt("failure")
	bm.RecordAuthAttempt("failure")

	if bm.AuthAttemptsTotal["failure"] != 2 {
		t.Errorf("failure = %d, want 2", bm.AuthAttemptsTotal["failure"])
	}
}

func TestRecordDockerOpDuration(t *testing.T) {
	bm := NewBusinessMetrics()
	bm.RecordDockerOpDuration("pull", 500*time.Millisecond)
	bm.RecordDockerOpDuration("pull", 300*time.Millisecond)

	tracker := bm.DockerOpDurations["pull"]
	if tracker == nil {
		t.Fatal("pull tracker is nil")
	}
	if tracker.count != 2 {
		t.Errorf("count = %d, want 2", tracker.count)
	}
	if tracker.sum < 0.7 || tracker.sum > 0.9 {
		t.Errorf("sum = %f, want ~0.8", tracker.sum)
	}
}

func TestRecordAPILatency(t *testing.T) {
	bm := NewBusinessMetrics()
	bm.RecordAPILatency("/api/containers", 100*time.Millisecond)
	bm.RecordAPILatency("/api/containers", 200*time.Millisecond)

	tracker := bm.APILatencies["/api/containers"]
	if tracker == nil {
		t.Fatal("tracker is nil")
	}
	if tracker.count != 2 {
		t.Errorf("count = %d, want 2", tracker.count)
	}
}

func TestRecordLicenseInfo(t *testing.T) {
	bm := NewBusinessMetrics()
	bm.RecordLicenseInfo("enterprise", 365)

	if bm.LicenseType != "enterprise" {
		t.Errorf("LicenseType = %q, want %q", bm.LicenseType, "enterprise")
	}
	if bm.LicenseDaysLeft != 365 {
		t.Errorf("LicenseDaysLeft = %d, want 365", bm.LicenseDaysLeft)
	}
}

// ---------------------------------------------------------------------------
// BusinessMetrics.FormatPrometheus tests
// ---------------------------------------------------------------------------

func TestBusinessMetrics_FormatPrometheus_Empty(t *testing.T) {
	bm := NewBusinessMetrics()
	result := bm.FormatPrometheus()

	// Should at minimum contain agent gauge and license info
	if !strings.Contains(result, "usulnet_agents_connected_total") {
		t.Error("should contain agents gauge")
	}
	if !strings.Contains(result, "usulnet_license_info") {
		t.Error("should contain license info")
	}
}

func TestBusinessMetrics_FormatPrometheus_WithData(t *testing.T) {
	bm := NewBusinessMetrics()
	bm.RecordAgentsConnected(3)
	bm.RecordContainersByState("running", 10)
	bm.RecordVulnerabilities("critical", 2)
	bm.RecordBackup("success")
	bm.RecordSecurityScan("completed")
	bm.RecordAPIRequest("GET", 200)
	bm.RecordAuthAttempt("success")
	bm.RecordDockerOpDuration("pull", time.Second)
	bm.RecordAPILatency("/api/v1/containers", 50*time.Millisecond)
	bm.RecordLicenseInfo("business", 180)

	result := bm.FormatPrometheus()

	checks := []string{
		"usulnet_agents_connected_total",
		"usulnet_containers_by_state",
		"usulnet_vulnerabilities_total",
		"usulnet_backups_total",
		"usulnet_security_scans_total",
		"usulnet_api_requests_total",
		"usulnet_auth_attempts_total",
		"usulnet_docker_operation_duration_seconds",
		"usulnet_api_request_duration_seconds",
		"usulnet_license_days_remaining",
		"usulnet_license_info",
		`type="business"`,
		`state="running"`,
		`severity="critical"`,
	}
	for _, check := range checks {
		if !strings.Contains(result, check) {
			t.Errorf("result should contain %q", check)
		}
	}
}

func TestBusinessMetrics_FormatPrometheus_ContainersByHost(t *testing.T) {
	bm := NewBusinessMetrics()
	bm.RecordContainersByHostState("host-1", "running", 5)

	result := bm.FormatPrometheus()
	if !strings.Contains(result, "usulnet_containers_by_host") {
		t.Error("should contain containers_by_host metric")
	}
	if !strings.Contains(result, `host="host-1"`) {
		t.Error("should contain host label")
	}
}

// ---------------------------------------------------------------------------
// Concurrency safety tests
// ---------------------------------------------------------------------------

func TestBusinessMetrics_ConcurrentAccess(t *testing.T) {
	bm := NewBusinessMetrics()
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(6)
		go func() {
			defer wg.Done()
			bm.RecordAgentsConnected(1)
		}()
		go func() {
			defer wg.Done()
			bm.RecordContainersByState("running", 5)
		}()
		go func() {
			defer wg.Done()
			bm.RecordBackup("success")
		}()
		go func() {
			defer wg.Done()
			bm.RecordAPIRequest("GET", 200)
		}()
		go func() {
			defer wg.Done()
			bm.RecordDockerOpDuration("pull", time.Millisecond)
		}()
		go func() {
			defer wg.Done()
			_ = bm.FormatPrometheus()
		}()
	}

	wg.Wait()
	// If we get here without panic/race, concurrency is safe
}

// ---------------------------------------------------------------------------
// writeGauge helpers tests
// ---------------------------------------------------------------------------

func TestWriteGauge(t *testing.T) {
	var b strings.Builder
	writeGauge(&b, "test_metric", "Test help", 42.5, "key", "val")

	result := b.String()
	if !strings.Contains(result, "# HELP test_metric Test help") {
		t.Error("missing HELP line")
	}
	if !strings.Contains(result, "# TYPE test_metric gauge") {
		t.Error("missing TYPE line")
	}
	if !strings.Contains(result, `test_metric{key="val"} 42.5`) {
		t.Errorf("unexpected metric line in: %q", result)
	}
}

func TestWriteGaugeI64(t *testing.T) {
	var b strings.Builder
	writeGaugeI64(&b, "test_bytes", "Test bytes", 1024, "host", "h1")

	result := b.String()
	if !strings.Contains(result, `test_bytes{host="h1"} 1024`) {
		t.Errorf("unexpected metric line in: %q", result)
	}
}

func TestWriteGaugeLabels(t *testing.T) {
	var b strings.Builder
	writeGaugeLabels(&b, "test_labeled", "Test labeled", 99.9, `name="web",id="abc"`)

	result := b.String()
	if !strings.Contains(result, `test_labeled{name="web",id="abc"} 99.9`) {
		t.Errorf("unexpected metric line in: %q", result)
	}
}
