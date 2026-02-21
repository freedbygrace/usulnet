// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package drift

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"testing"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ---------------------------------------------------------------------------
// Mock repository
// ---------------------------------------------------------------------------

type mockRepo struct {
	snapshots map[uuid.UUID]*models.ConfigSnapshot
	drifts    map[uuid.UUID]*models.DriftDetection
	baselines map[string]*models.ConfigSnapshot // key: resourceType+":"+resourceID

	createSnapshotErr error
	createDriftErr    error
}

func newMockRepo() *mockRepo {
	return &mockRepo{
		snapshots: make(map[uuid.UUID]*models.ConfigSnapshot),
		drifts:    make(map[uuid.UUID]*models.DriftDetection),
		baselines: make(map[string]*models.ConfigSnapshot),
	}
}

func baselineKey(rt, rid string) string { return rt + ":" + rid }

func (m *mockRepo) CreateSnapshot(_ context.Context, s *models.ConfigSnapshot) error {
	if m.createSnapshotErr != nil {
		return m.createSnapshotErr
	}
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	m.snapshots[s.ID] = s
	return nil
}

func (m *mockRepo) GetSnapshotByID(_ context.Context, id uuid.UUID) (*models.ConfigSnapshot, error) {
	s, ok := m.snapshots[id]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return s, nil
}

func (m *mockRepo) GetBaseline(_ context.Context, resourceType, resourceID string) (*models.ConfigSnapshot, error) {
	s := m.baselines[baselineKey(resourceType, resourceID)]
	return s, nil
}

func (m *mockRepo) GetLatestSnapshot(_ context.Context, _, _ string) (*models.ConfigSnapshot, error) {
	return nil, nil
}

func (m *mockRepo) SetBaseline(_ context.Context, snapshotID uuid.UUID) error {
	s, ok := m.snapshots[snapshotID]
	if !ok {
		return fmt.Errorf("not found")
	}
	s.Status = models.SnapshotStatusBaseline
	m.baselines[baselineKey(s.ResourceType, s.ResourceID)] = s
	return nil
}

func (m *mockRepo) ListSnapshots(_ context.Context, _, _ string, _ int) ([]*models.ConfigSnapshot, error) {
	var result []*models.ConfigSnapshot
	for _, s := range m.snapshots {
		result = append(result, s)
	}
	return result, nil
}

func (m *mockRepo) CreateDrift(_ context.Context, d *models.DriftDetection) error {
	if m.createDriftErr != nil {
		return m.createDriftErr
	}
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	m.drifts[d.ID] = d
	return nil
}

func (m *mockRepo) GetDriftByID(_ context.Context, id uuid.UUID) (*models.DriftDetection, error) {
	d, ok := m.drifts[id]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return d, nil
}

func (m *mockRepo) ListDrifts(_ context.Context, _ models.DriftListOptions) ([]*models.DriftDetection, int, error) {
	var result []*models.DriftDetection
	for _, d := range m.drifts {
		result = append(result, d)
	}
	return result, len(result), nil
}

func (m *mockRepo) GetOpenDrifts(_ context.Context) ([]*models.DriftDetection, error) {
	var result []*models.DriftDetection
	for _, d := range m.drifts {
		if d.Status == models.DriftStatusOpen {
			result = append(result, d)
		}
	}
	return result, nil
}

func (m *mockRepo) ResolveDrift(_ context.Context, id uuid.UUID, status string, resolvedBy *uuid.UUID, note string) error {
	d, ok := m.drifts[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	d.Status = status
	d.ResolvedBy = resolvedBy
	d.ResolutionNote = note
	return nil
}

func (m *mockRepo) GetDriftStats(_ context.Context) (*models.DriftStats, error) {
	return &models.DriftStats{TotalOpen: len(m.drifts)}, nil
}

func (m *mockRepo) CloseExistingDrifts(_ context.Context, _, _ string) error {
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func testService(repo *mockRepo) *Service {
	log, _ := logger.NewWithOutput("error", "console", io.Discard)
	return NewService(repo, log)
}

func jsonRaw(v any) *json.RawMessage {
	raw, _ := json.Marshal(v)
	msg := json.RawMessage(raw)
	return &msg
}

// ---------------------------------------------------------------------------
// compareMaps tests (pure function)
// ---------------------------------------------------------------------------

func TestCompareMaps_NoDiff(t *testing.T) {
	base := map[string]any{"image": "nginx:1.25", "ports": "80"}
	curr := map[string]any{"image": "nginx:1.25", "ports": "80"}

	diffs := compareMaps(base, curr)
	if len(diffs) != 0 {
		t.Errorf("expected no diffs, got %d", len(diffs))
	}
}

func TestCompareMaps_Modified(t *testing.T) {
	base := map[string]any{"image": "nginx:1.25"}
	curr := map[string]any{"image": "nginx:1.26"}

	diffs := compareMaps(base, curr)
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d", len(diffs))
	}
	if diffs[0].Field != "image" {
		t.Errorf("Field = %q, want %q", diffs[0].Field, "image")
	}
	if diffs[0].OldValue != "nginx:1.25" {
		t.Errorf("OldValue = %q, want %q", diffs[0].OldValue, "nginx:1.25")
	}
	if diffs[0].NewValue != "nginx:1.26" {
		t.Errorf("NewValue = %q, want %q", diffs[0].NewValue, "nginx:1.26")
	}
}

func TestCompareMaps_Removed(t *testing.T) {
	base := map[string]any{"image": "nginx:1.25", "ports": "80"}
	curr := map[string]any{"image": "nginx:1.25"}

	diffs := compareMaps(base, curr)
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d", len(diffs))
	}
	if diffs[0].Field != "ports" {
		t.Errorf("Field = %q, want %q", diffs[0].Field, "ports")
	}
	if diffs[0].NewValue != "" {
		t.Errorf("NewValue should be empty for removed key, got %q", diffs[0].NewValue)
	}
}

func TestCompareMaps_Added(t *testing.T) {
	base := map[string]any{"image": "nginx:1.25"}
	curr := map[string]any{"image": "nginx:1.25", "labels": "app=web"}

	diffs := compareMaps(base, curr)
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d", len(diffs))
	}
	if diffs[0].Field != "labels" {
		t.Errorf("Field = %q, want %q", diffs[0].Field, "labels")
	}
	if diffs[0].OldValue != "" {
		t.Errorf("OldValue should be empty for added key, got %q", diffs[0].OldValue)
	}
}

func TestCompareMaps_MultipleChanges(t *testing.T) {
	base := map[string]any{"image": "nginx:1.25", "ports": "80", "labels": "old"}
	curr := map[string]any{"image": "nginx:1.26", "volumes": "/data", "labels": "old"}

	diffs := compareMaps(base, curr)
	// image modified, ports removed, volumes added = 3 diffs
	if len(diffs) != 3 {
		t.Errorf("expected 3 diffs, got %d: %+v", len(diffs), diffs)
	}
}

// ---------------------------------------------------------------------------
// classifyDrift tests
// ---------------------------------------------------------------------------

func TestClassifyDrift(t *testing.T) {
	tests := []struct {
		key          string
		wantType     string
		wantSeverity string
	}{
		{"image", models.DriftTypeImage, "critical"},
		{"privileged", models.DriftTypePrivileged, "critical"},
		{"env", models.DriftTypeEnvVar, "warning"},
		{"env_APP_PORT", models.DriftTypeEnvVar, "warning"},
		{"ports", models.DriftTypePort, "warning"},
		{"volumes", models.DriftTypeVolume, "warning"},
		{"memory_limit", models.DriftTypeLimit, "warning"},
		{"cpu_limit", models.DriftTypeLimit, "warning"},
		{"memory_reservation", models.DriftTypeLimit, "warning"},
		{"labels", models.DriftTypeLabel, "info"},
		{"networks", models.DriftTypeNetwork, "info"},
		{"restart_policy", models.DriftTypeRestartPolicy, "warning"},
		{"healthcheck", models.DriftTypeHealthcheck, "warning"},
		{"unknown_key", "unknown_key_changed", "warning"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			gotType, gotSev := classifyDrift(tt.key)
			if gotType != tt.wantType {
				t.Errorf("type = %q, want %q", gotType, tt.wantType)
			}
			if gotSev != tt.wantSeverity {
				t.Errorf("severity = %q, want %q", gotSev, tt.wantSeverity)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// highestSeverity tests
// ---------------------------------------------------------------------------

func TestHighestSeverity(t *testing.T) {
	tests := []struct {
		name string
		in   []models.DriftDiff
		want string
	}{
		{
			"critical wins",
			[]models.DriftDiff{
				{Severity: "info"},
				{Severity: "critical"},
				{Severity: "warning"},
			},
			"critical",
		},
		{
			"warning wins over info",
			[]models.DriftDiff{
				{Severity: "info"},
				{Severity: "warning"},
			},
			"warning",
		},
		{
			"info only",
			[]models.DriftDiff{
				{Severity: "info"},
			},
			"info",
		},
		{
			"empty",
			nil,
			"info",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := highestSeverity(tt.in)
			if got != tt.want {
				t.Errorf("highestSeverity() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Service tests
// ---------------------------------------------------------------------------

func TestNewService_NilLogger(t *testing.T) {
	svc := NewService(newMockRepo(), nil)
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestTakeSnapshot_Success(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	config := map[string]string{"image": "nginx:1.25", "ports": "80:80"}
	snap, err := svc.TakeSnapshot(context.Background(), "container", "cid-1", "my-container", config, nil, "initial")
	if err != nil {
		t.Fatalf("TakeSnapshot() error = %v", err)
	}
	if snap.ResourceType != "container" {
		t.Errorf("ResourceType = %q, want %q", snap.ResourceType, "container")
	}
	if snap.ResourceID != "cid-1" {
		t.Errorf("ResourceID = %q, want %q", snap.ResourceID, "cid-1")
	}
	if snap.Status != models.SnapshotStatusCurrent {
		t.Errorf("Status = %q, want %q", snap.Status, models.SnapshotStatusCurrent)
	}
	if snap.Note != "initial" {
		t.Errorf("Note = %q, want %q", snap.Note, "initial")
	}
}

func TestTakeSnapshot_RepoError(t *testing.T) {
	repo := newMockRepo()
	repo.createSnapshotErr = fmt.Errorf("db error")
	svc := testService(repo)

	_, err := svc.TakeSnapshot(context.Background(), "container", "cid-1", "test", map[string]string{}, nil, "")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDetectDrift_NoBaseline(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	got, err := svc.DetectDrift(context.Background(), "container", "cid-1", "test", map[string]string{"image": "nginx:1.25"})
	if err != nil {
		t.Fatalf("DetectDrift() error = %v", err)
	}
	if got != nil {
		t.Error("expected nil when no baseline exists")
	}
}

func TestDetectDrift_NoDrift(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	// Create and set baseline
	config := map[string]string{"image": "nginx:1.25"}
	snap, _ := svc.TakeSnapshot(context.Background(), "container", "cid-1", "test", config, nil, "")
	_ = svc.SetBaseline(context.Background(), snap.ID)

	// Detect drift with identical config
	got, err := svc.DetectDrift(context.Background(), "container", "cid-1", "test", map[string]string{"image": "nginx:1.25"})
	if err != nil {
		t.Fatalf("DetectDrift() error = %v", err)
	}
	if got != nil {
		t.Error("expected nil when config matches baseline")
	}
}

func TestDetectDrift_DriftDetected(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	// Create and set baseline
	config := map[string]string{"image": "nginx:1.25", "ports": "80"}
	snap, _ := svc.TakeSnapshot(context.Background(), "container", "cid-1", "test", config, nil, "")
	_ = svc.SetBaseline(context.Background(), snap.ID)

	// Detect drift with changed image
	got, err := svc.DetectDrift(context.Background(), "container", "cid-1", "test", map[string]string{"image": "nginx:1.26", "ports": "80"})
	if err != nil {
		t.Fatalf("DetectDrift() error = %v", err)
	}
	if got == nil {
		t.Fatal("expected drift detection, got nil")
	}
	if got.Status != models.DriftStatusOpen {
		t.Errorf("Status = %q, want %q", got.Status, models.DriftStatusOpen)
	}
	if got.Severity != "critical" {
		t.Errorf("Severity = %q, want %q (image change is critical)", got.Severity, "critical")
	}
	if got.DiffCount != 1 {
		t.Errorf("DiffCount = %d, want 1", got.DiffCount)
	}
}

func TestDetectDrift_MultipleDiffs(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	config := map[string]string{"image": "nginx:1.25", "labels": "old", "ports": "80"}
	snap, _ := svc.TakeSnapshot(context.Background(), "container", "cid-1", "test", config, nil, "")
	_ = svc.SetBaseline(context.Background(), snap.ID)

	got, err := svc.DetectDrift(context.Background(), "container", "cid-1", "test", map[string]string{
		"image":  "nginx:1.26",
		"labels": "new",
		"ports":  "80",
	})
	if err != nil {
		t.Fatalf("DetectDrift() error = %v", err)
	}
	if got.DiffCount != 2 {
		t.Errorf("DiffCount = %d, want 2", got.DiffCount)
	}
}

func TestAcceptDrift(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	// Create a drift manually
	driftID := uuid.New()
	repo.drifts[driftID] = &models.DriftDetection{
		ID:     driftID,
		Status: models.DriftStatusOpen,
	}

	userID := uuid.New()
	err := svc.AcceptDrift(context.Background(), driftID, &userID, "acceptable change")
	if err != nil {
		t.Fatalf("AcceptDrift() error = %v", err)
	}
	if repo.drifts[driftID].Status != models.DriftStatusAccepted {
		t.Errorf("Status = %q, want %q", repo.drifts[driftID].Status, models.DriftStatusAccepted)
	}
}

func TestRemediateDrift(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	driftID := uuid.New()
	repo.drifts[driftID] = &models.DriftDetection{
		ID:     driftID,
		Status: models.DriftStatusOpen,
	}

	err := svc.RemediateDrift(context.Background(), driftID, nil, "reverted config")
	if err != nil {
		t.Fatalf("RemediateDrift() error = %v", err)
	}
	if repo.drifts[driftID].Status != models.DriftStatusRemediated {
		t.Errorf("Status = %q, want %q", repo.drifts[driftID].Status, models.DriftStatusRemediated)
	}
}
