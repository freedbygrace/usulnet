// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package changes

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ---------------------------------------------------------------------------
// Mock repository
// ---------------------------------------------------------------------------

type mockRepo struct {
	events    map[uuid.UUID]*models.ChangeEvent
	createErr error
}

func newMockRepo() *mockRepo {
	return &mockRepo{
		events: make(map[uuid.UUID]*models.ChangeEvent),
	}
}

func (m *mockRepo) Create(_ context.Context, e *models.ChangeEvent) error {
	if m.createErr != nil {
		return m.createErr
	}
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	m.events[e.ID] = e
	return nil
}

func (m *mockRepo) GetByID(_ context.Context, id uuid.UUID) (*models.ChangeEvent, error) {
	e, ok := m.events[id]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return e, nil
}

func (m *mockRepo) List(_ context.Context, _ models.ChangeEventListOptions) ([]*models.ChangeEvent, int, error) {
	var result []*models.ChangeEvent
	for _, e := range m.events {
		result = append(result, e)
	}
	return result, len(result), nil
}

func (m *mockRepo) GetByResource(_ context.Context, _, _ string, _ int) ([]*models.ChangeEvent, error) {
	return nil, nil
}

func (m *mockRepo) GetByUser(_ context.Context, _ uuid.UUID, _ int) ([]*models.ChangeEvent, error) {
	return nil, nil
}

func (m *mockRepo) GetStats(_ context.Context, _ time.Time) (*models.ChangeEventStats, error) {
	return &models.ChangeEventStats{}, nil
}

func (m *mockRepo) DeleteOlderThan(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func (m *mockRepo) ExportCSV(_ context.Context, _ models.ChangeEventListOptions) ([][]string, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func testService(repo *mockRepo) *Service {
	log, _ := logger.NewWithOutput("error", "console", io.Discard)
	return NewService(repo, log)
}

// ---------------------------------------------------------------------------
// generateDiffSummary tests (pure function)
// ---------------------------------------------------------------------------

func TestGenerateDiffSummary_NilInputs(t *testing.T) {
	got := generateDiffSummary(nil, nil)
	if got != "" {
		t.Errorf("expected empty for nil inputs, got %q", got)
	}
}

func TestGenerateDiffSummary_NoChanges(t *testing.T) {
	old := rawJSON(map[string]string{"key": "value"})
	new := rawJSON(map[string]string{"key": "value"})

	got := generateDiffSummary(old, new)
	if got != "no changes detected" {
		t.Errorf("got %q, want %q", got, "no changes detected")
	}
}

func TestGenerateDiffSummary_Modified(t *testing.T) {
	old := rawJSON(map[string]string{"image": "nginx:1.25"})
	new := rawJSON(map[string]string{"image": "nginx:1.26"})

	got := generateDiffSummary(old, new)
	if !strings.Contains(got, "~image") {
		t.Errorf("expected ~image in summary, got %q", got)
	}
}

func TestGenerateDiffSummary_Added(t *testing.T) {
	old := rawJSON(map[string]string{"image": "nginx"})
	new := rawJSON(map[string]string{"image": "nginx", "ports": "80"})

	got := generateDiffSummary(old, new)
	if !strings.Contains(got, "+ports") {
		t.Errorf("expected +ports in summary, got %q", got)
	}
}

func TestGenerateDiffSummary_Removed(t *testing.T) {
	old := rawJSON(map[string]string{"image": "nginx", "labels": "app"})
	new := rawJSON(map[string]string{"image": "nginx"})

	got := generateDiffSummary(old, new)
	if !strings.Contains(got, "-labels") {
		t.Errorf("expected -labels in summary, got %q", got)
	}
}

func TestGenerateDiffSummary_InvalidJSON(t *testing.T) {
	bad := rawJSONStr(`not json`)
	good := rawJSON(map[string]string{"key": "value"})

	got := generateDiffSummary(bad, good)
	if got != "" {
		t.Errorf("expected empty for invalid JSON, got %q", got)
	}
}

func TestGenerateDiffSummary_Truncation(t *testing.T) {
	// Build maps with many keys to exceed 500 chars
	old := make(map[string]string)
	new := make(map[string]string)
	for i := 0; i < 200; i++ {
		key := fmt.Sprintf("very_long_key_name_%03d", i)
		old[key] = "old"
		new[key] = "new"
	}

	got := generateDiffSummary(rawJSON(old), rawJSON(new))
	if len(got) > 500 {
		t.Errorf("summary should be truncated to 500 chars, got %d", len(got))
	}
	if len(got) > 3 && !strings.HasSuffix(got, "...") {
		t.Errorf("truncated summary should end with ..., got suffix %q", got[len(got)-3:])
	}
}

func rawJSON(v any) *json.RawMessage {
	raw, _ := json.Marshal(v)
	msg := json.RawMessage(raw)
	return &msg
}

func rawJSONStr(s string) *json.RawMessage {
	msg := json.RawMessage(s)
	return &msg
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

func TestRecord_Success(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)
	userID := uuid.New()

	err := svc.Record(context.Background(), RecordInput{
		UserID:       &userID,
		UserName:     "admin",
		ResourceType: "container",
		ResourceID:   "cid-1",
		ResourceName: "my-container",
		Action:       "restart",
	})
	if err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if len(repo.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(repo.events))
	}
	for _, e := range repo.events {
		if e.Action != "restart" {
			t.Errorf("Action = %q, want %q", e.Action, "restart")
		}
		if e.ResourceType != "container" {
			t.Errorf("ResourceType = %q, want %q", e.ResourceType, "container")
		}
	}
}

func TestRecord_WithStates(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	err := svc.Record(context.Background(), RecordInput{
		ResourceType: "container",
		ResourceID:   "cid-1",
		Action:       "update",
		OldState:     map[string]string{"image": "nginx:1.25"},
		NewState:     map[string]string{"image": "nginx:1.26"},
	})
	if err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	for _, e := range repo.events {
		if e.OldState == nil {
			t.Error("OldState should be set")
		}
		if e.NewState == nil {
			t.Error("NewState should be set")
		}
		// DiffSummary should be auto-generated
		if e.DiffSummary == "" {
			t.Error("DiffSummary should be auto-generated from states")
		}
		if !strings.Contains(e.DiffSummary, "~image") {
			t.Errorf("DiffSummary = %q, expected to contain ~image", e.DiffSummary)
		}
	}
}

func TestRecord_WithMetadata(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	err := svc.Record(context.Background(), RecordInput{
		ResourceType: "container",
		ResourceID:   "cid-1",
		Action:       "stop",
		Metadata:     map[string]any{"reason": "maintenance"},
	})
	if err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	for _, e := range repo.events {
		if e.Metadata == nil {
			t.Error("Metadata should be set")
		}
	}
}

func TestRecord_ManualDiffSummary(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	err := svc.Record(context.Background(), RecordInput{
		ResourceType: "container",
		ResourceID:   "cid-1",
		Action:       "update",
		DiffSummary:  "manual summary",
		OldState:     map[string]string{"a": "1"},
		NewState:     map[string]string{"a": "2"},
	})
	if err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	for _, e := range repo.events {
		if e.DiffSummary != "manual summary" {
			t.Errorf("DiffSummary = %q, want %q (manual should not be overwritten)", e.DiffSummary, "manual summary")
		}
	}
}

func TestRecord_RepoError(t *testing.T) {
	repo := newMockRepo()
	repo.createErr = fmt.Errorf("db error")
	svc := testService(repo)

	err := svc.Record(context.Background(), RecordInput{
		ResourceType: "container",
		ResourceID:   "cid-1",
		Action:       "start",
	})
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

func TestGetByID(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	_ = svc.Record(context.Background(), RecordInput{
		ResourceType: "container",
		ResourceID:   "cid-1",
		Action:       "start",
	})

	var id uuid.UUID
	for k := range repo.events {
		id = k
	}

	got, err := svc.GetByID(context.Background(), id)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if got.Action != "start" {
		t.Errorf("Action = %q, want %q", got.Action, "start")
	}
}
