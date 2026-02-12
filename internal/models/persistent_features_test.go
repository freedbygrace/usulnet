// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ============================================================================
// CompliancePolicyRecord tests
// ============================================================================

func TestCompliancePolicyRecord_Defaults(t *testing.T) {
	p := CompliancePolicyRecord{
		ID:   uuid.New(),
		Name: "test-policy",
	}

	if p.IsEnabled {
		t.Error("IsEnabled should default to false")
	}
	if p.IsEnforced {
		t.Error("IsEnforced should default to false")
	}
	if p.LastCheckAt != nil {
		t.Error("LastCheckAt should default to nil")
	}
}

func TestComplianceViolationRecord_Fields(t *testing.T) {
	policyID := uuid.New()
	now := time.Now()

	v := ComplianceViolationRecord{
		ID:            uuid.New(),
		PolicyID:      policyID,
		PolicyName:    "test-policy",
		ContainerID:   "abc123",
		ContainerName: "my-container",
		Severity:      "high",
		Message:       "Violation detected",
		Status:        "open",
		DetectedAt:    now,
	}

	if v.PolicyID != policyID {
		t.Errorf("PolicyID = %v, want %v", v.PolicyID, policyID)
	}
	if v.Status != "open" {
		t.Errorf("Status = %q, want %q", v.Status, "open")
	}
	if v.ResolvedAt != nil {
		t.Error("ResolvedAt should be nil for open violation")
	}
}

// ============================================================================
// ManagedSecretRecord tests
// ============================================================================

func TestManagedSecretRecord_ExpiryTracking(t *testing.T) {
	expires := time.Now().Add(30 * 24 * time.Hour) // 30 days
	s := ManagedSecretRecord{
		ID:           uuid.New(),
		Name:         "db-password",
		Type:         "password",
		Scope:        "global",
		RotationDays: 90,
		ExpiresAt:    &expires,
	}

	if s.ExpiresAt == nil {
		t.Fatal("ExpiresAt should not be nil")
	}
	if s.ExpiresAt.Before(time.Now()) {
		t.Error("ExpiresAt should be in the future")
	}
}

func TestManagedSecretRecord_NoExpiry(t *testing.T) {
	s := ManagedSecretRecord{
		ID:           uuid.New(),
		Name:         "api-key",
		Type:         "api_key",
		RotationDays: 0,
	}

	if s.ExpiresAt != nil {
		t.Error("ExpiresAt should be nil when no rotation")
	}
}

// ============================================================================
// LifecyclePolicyRecord tests
// ============================================================================

func TestLifecyclePolicyRecord_Fields(t *testing.T) {
	p := LifecyclePolicyRecord{
		ID:           uuid.New(),
		Name:         "cleanup-images",
		ResourceType: "images",
		Action:       "remove_dangling",
		Schedule:     "0 2 * * *",
		IsEnabled:    true,
		OnlyDangling: true,
		MaxAgeDays:   30,
		KeepLatest:   5,
	}

	if !p.IsEnabled {
		t.Error("IsEnabled should be true")
	}
	if !p.OnlyDangling {
		t.Error("OnlyDangling should be true")
	}
	if p.MaxAgeDays != 30 {
		t.Errorf("MaxAgeDays = %d, want 30", p.MaxAgeDays)
	}
}

func TestLifecycleHistoryRecord_Fields(t *testing.T) {
	policyID := uuid.New()
	h := LifecycleHistoryRecord{
		ID:           uuid.New(),
		PolicyID:     &policyID,
		PolicyName:   "cleanup-images",
		ResourceType: "images",
		Action:       "remove_dangling",
		ItemsRemoved: 15,
		SpaceFreed:   1024 * 1024 * 500, // 500 MB
		Status:       "success",
		DurationMs:   1234,
		ExecutedAt:   time.Now(),
	}

	if h.ItemsRemoved != 15 {
		t.Errorf("ItemsRemoved = %d, want 15", h.ItemsRemoved)
	}
	if h.SpaceFreed != 524288000 {
		t.Errorf("SpaceFreed = %d, want 524288000", h.SpaceFreed)
	}
}

// ============================================================================
// MaintenanceWindowRecord tests
// ============================================================================

func TestMaintenanceWindowRecord_JSONActions(t *testing.T) {
	actions := json.RawMessage(`{"stop_containers":true,"prune_images":false}`)
	mw := MaintenanceWindowRecord{
		ID:              uuid.New(),
		Name:            "weekly-cleanup",
		Schedule:        "0 3 * * 0",
		DurationMinutes: 60,
		Actions:         actions,
		IsEnabled:       true,
	}

	// Verify actions can be unmarshaled
	var parsed map[string]interface{}
	if err := json.Unmarshal(mw.Actions, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal actions: %v", err)
	}

	if stop, ok := parsed["stop_containers"].(bool); !ok || !stop {
		t.Error("stop_containers should be true")
	}
}

// ============================================================================
// GitOpsPipelineRecord tests
// ============================================================================

func TestGitOpsPipelineRecord_Fields(t *testing.T) {
	p := GitOpsPipelineRecord{
		ID:           uuid.New(),
		Name:         "deploy-prod",
		Repository:   "github.com/org/repo",
		Branch:       "main",
		Provider:     "github",
		Action:       "redeploy",
		TriggerType:  "webhook",
		IsEnabled:    true,
		AutoRollback: true,
	}

	if p.Provider != "github" {
		t.Errorf("Provider = %q, want %q", p.Provider, "github")
	}
	if !p.AutoRollback {
		t.Error("AutoRollback should be true")
	}
	if p.DeployCount != 0 {
		t.Errorf("DeployCount should default to 0, got %d", p.DeployCount)
	}
}

func TestGitOpsDeploymentRecord_Fields(t *testing.T) {
	pipelineID := uuid.New()
	now := time.Now()
	d := GitOpsDeploymentRecord{
		ID:           uuid.New(),
		PipelineID:   &pipelineID,
		PipelineName: "deploy-prod",
		CommitSHA:    "abc123def",
		Status:       "success",
		DurationMs:   5000,
		StartedAt:    now,
		TriggeredBy:  "manual",
	}

	if d.Status != "success" {
		t.Errorf("Status = %q, want %q", d.Status, "success")
	}
	if d.DurationMs != 5000 {
		t.Errorf("DurationMs = %d, want 5000", d.DurationMs)
	}
}

// ============================================================================
// ResourceQuotaRecord tests
// ============================================================================

func TestResourceQuotaRecord_Fields(t *testing.T) {
	q := ResourceQuotaRecord{
		ID:           uuid.New(),
		Name:         "max-containers",
		Scope:        "global",
		ScopeName:    "Global",
		ResourceType: "containers",
		LimitValue:   100,
		AlertAt:      80,
		IsEnabled:    true,
	}

	if q.LimitValue != 100 {
		t.Errorf("LimitValue = %d, want 100", q.LimitValue)
	}
	if q.AlertAt != 80 {
		t.Errorf("AlertAt = %d, want 80", q.AlertAt)
	}
}

// ============================================================================
// ContainerTemplateRecord tests
// ============================================================================

func TestContainerTemplateRecord_PortsAndVolumes(t *testing.T) {
	tpl := ContainerTemplateRecord{
		ID:      uuid.New(),
		Name:    "nginx-template",
		Image:   "nginx",
		Tag:     "alpine",
		Ports:   []string{"80:80", "443:443"},
		Volumes: []string{"/data:/usr/share/nginx/html"},
		EnvVars: json.RawMessage(`[{"key":"NGINX_HOST","value":"localhost"}]`),
	}

	if len(tpl.Ports) != 2 {
		t.Errorf("Ports count = %d, want 2", len(tpl.Ports))
	}
	if len(tpl.Volumes) != 1 {
		t.Errorf("Volumes count = %d, want 1", len(tpl.Volumes))
	}

	// Verify env vars can be parsed
	var envVars []map[string]interface{}
	if err := json.Unmarshal(tpl.EnvVars, &envVars); err != nil {
		t.Fatalf("Failed to unmarshal env vars: %v", err)
	}
	if len(envVars) != 1 {
		t.Errorf("EnvVars count = %d, want 1", len(envVars))
	}
}

// ============================================================================
// TrackedVulnRecord tests
// ============================================================================

func TestTrackedVulnRecord_Fields(t *testing.T) {
	deadline := time.Now().Add(7 * 24 * time.Hour)
	v := TrackedVulnRecord{
		ID:             uuid.New(),
		CVEID:          "CVE-2024-1234",
		Title:          "Critical vulnerability",
		Severity:       "critical",
		CVSSScore:      "9.8",
		Package:        "openssl",
		InstalledVer:   "1.1.1k",
		FixedVer:       "1.1.1l",
		AffectedImages: []string{"nginx:latest", "app:v1"},
		ContainerCount: 5,
		Status:         "open",
		Priority:       "high",
		SLADeadline:    &deadline,
		DetectedAt:     time.Now(),
	}

	if v.CVEID != "CVE-2024-1234" {
		t.Errorf("CVEID = %q, want %q", v.CVEID, "CVE-2024-1234")
	}
	if len(v.AffectedImages) != 2 {
		t.Errorf("AffectedImages count = %d, want 2", len(v.AffectedImages))
	}
	if v.ContainerCount != 5 {
		t.Errorf("ContainerCount = %d, want 5", v.ContainerCount)
	}
	if v.ResolvedAt != nil {
		t.Error("ResolvedAt should be nil for open vulnerability")
	}
}

func TestTrackedVulnRecord_Resolved(t *testing.T) {
	resolved := time.Now()
	v := TrackedVulnRecord{
		ID:         uuid.New(),
		CVEID:      "CVE-2024-5678",
		Status:     "resolved",
		ResolvedAt: &resolved,
		DetectedAt: time.Now().Add(-7 * 24 * time.Hour),
	}

	if v.ResolvedAt == nil {
		t.Error("ResolvedAt should not be nil for resolved vulnerability")
	}
	if v.ResolvedAt.Before(v.DetectedAt) {
		t.Error("ResolvedAt should be after DetectedAt")
	}
}
