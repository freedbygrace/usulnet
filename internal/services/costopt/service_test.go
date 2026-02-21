// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package costopt

import (
	"context"
	"io"
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
	samples         []*models.ResourceUsageSample
	recommendations []*models.ResourceRecommendation
	clearCalled     bool
}

func newMockRepo() *mockRepo {
	return &mockRepo{}
}

func (m *mockRepo) CreateSample(_ context.Context, s *models.ResourceUsageSample) error {
	m.samples = append(m.samples, s)
	return nil
}

func (m *mockRepo) CreateSamples(_ context.Context, ss []*models.ResourceUsageSample) error {
	m.samples = append(m.samples, ss...)
	return nil
}

func (m *mockRepo) GetContainerUsageSummary(_ context.Context, _ string, _ time.Time) (*models.ContainerUsageSummary, error) {
	return &models.ContainerUsageSummary{ContainerID: "cid-1"}, nil
}

func (m *mockRepo) ListContainerSummaries(_ context.Context, _ time.Time, _ int) ([]*models.ContainerUsageSummary, error) {
	return nil, nil
}

func (m *mockRepo) UpsertHourly(_ context.Context, _ *models.ResourceUsageHourly) error {
	return nil
}

func (m *mockRepo) UpsertDaily(_ context.Context, _ *models.ResourceUsageDaily) error {
	return nil
}

func (m *mockRepo) GetHourlyUsage(_ context.Context, _ string, _ time.Time) ([]*models.ResourceUsageHourly, error) {
	return nil, nil
}

func (m *mockRepo) GetDailyUsage(_ context.Context, _ string, _ time.Time) ([]*models.ResourceUsageDaily, error) {
	return nil, nil
}

func (m *mockRepo) CreateRecommendation(_ context.Context, r *models.ResourceRecommendation) error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	m.recommendations = append(m.recommendations, r)
	return nil
}

func (m *mockRepo) ListRecommendations(_ context.Context, _ models.RecommendationListOptions) ([]*models.ResourceRecommendation, int, error) {
	return m.recommendations, len(m.recommendations), nil
}

func (m *mockRepo) ResolveRecommendation(_ context.Context, _ uuid.UUID, _ string, _ *uuid.UUID) error {
	return nil
}

func (m *mockRepo) GetOptStats(_ context.Context) (*models.ResourceOptStats, error) {
	return &models.ResourceOptStats{TotalRecommendations: len(m.recommendations)}, nil
}

func (m *mockRepo) DeleteOldSamples(_ context.Context, _ time.Time) (int64, error) {
	return 42, nil
}

func (m *mockRepo) ClearOpenRecommendations(_ context.Context) error {
	m.clearCalled = true
	m.recommendations = nil
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func testService(repo *mockRepo) *Service {
	log, _ := logger.NewWithOutput("error", "console", io.Discard)
	return NewService(repo, log)
}

// ---------------------------------------------------------------------------
// formatBytes tests (pure function)
// ---------------------------------------------------------------------------

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1024 * 1024, "1.0 MB"},
		{1024 * 1024 * 512, "512.0 MB"},
		{1024 * 1024 * 1024, "1.0 GB"},
		{int64(1024*1024*1024) * 4, "4.0 GB"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatBytes(tt.input)
			if got != tt.want {
				t.Errorf("formatBytes(%d) = %q, want %q", tt.input, got, tt.want)
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

func TestRecordSample(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	err := svc.RecordSample(context.Background(), &models.ResourceUsageSample{
		ContainerID: "cid-1",
		CPUUsagePercent:  50.0,
	})
	if err != nil {
		t.Fatalf("RecordSample() error = %v", err)
	}
	if len(repo.samples) != 1 {
		t.Errorf("expected 1 sample, got %d", len(repo.samples))
	}
}

func TestRecordSamples(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	samples := []*models.ResourceUsageSample{
		{ContainerID: "cid-1", CPUUsagePercent: 10},
		{ContainerID: "cid-2", CPUUsagePercent: 20},
	}
	err := svc.RecordSamples(context.Background(), samples)
	if err != nil {
		t.Fatalf("RecordSamples() error = %v", err)
	}
	if len(repo.samples) != 2 {
		t.Errorf("expected 2 samples, got %d", len(repo.samples))
	}
}

func TestGenerateRecommendations_OversizedMemory(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	summaries := []*models.ContainerUsageSummary{
		{
			ContainerID:   "cid-1",
			ContainerName: "web",
			MemoryLimit:   1024 * 1024 * 1024, // 1 GB
			MemoryAvg:     100 * 1024 * 1024,   // 100 MB (< 30% of limit)
			CPUAvg:        50,
			CPUPeak:       80,
			LastSeen:      time.Now(),
		},
	}

	count, err := svc.GenerateRecommendations(context.Background(), summaries)
	if err != nil {
		t.Fatalf("GenerateRecommendations() error = %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
	if !repo.clearCalled {
		t.Error("expected ClearOpenRecommendations to be called")
	}
	if repo.recommendations[0].Type != models.RecommendDownsizeMemory {
		t.Errorf("type = %q, want %q", repo.recommendations[0].Type, models.RecommendDownsizeMemory)
	}
}

func TestGenerateRecommendations_LowCPU(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	summaries := []*models.ContainerUsageSummary{
		{
			ContainerID:   "cid-1",
			ContainerName: "worker",
			CPUAvg:        5,
			CPUPeak:       20,
			MemoryLimit:   512 * 1024 * 1024,
			MemoryAvg:     400 * 1024 * 1024, // > 30% so no memory recommendation
			LastSeen:      time.Now(),
		},
	}

	count, err := svc.GenerateRecommendations(context.Background(), summaries)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
	if repo.recommendations[0].Type != models.RecommendDownsizeCPU {
		t.Errorf("type = %q, want %q", repo.recommendations[0].Type, models.RecommendDownsizeCPU)
	}
}

func TestGenerateRecommendations_IdleContainer(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	summaries := []*models.ContainerUsageSummary{
		{
			ContainerID:   "cid-1",
			ContainerName: "dead-worker",
			CPUAvg:        0.5,
			CPUPeak:       2,
			MemoryLimit:   256 * 1024 * 1024,
			MemoryAvg:     200 * 1024 * 1024,
			LastSeen:      time.Now().Add(-10 * 24 * time.Hour), // 10 days ago
		},
	}

	count, err := svc.GenerateRecommendations(context.Background(), summaries)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	// Low CPU + idle = 2 recommendations
	found := false
	for _, r := range repo.recommendations {
		if r.Type == models.RecommendRemoveIdle {
			found = true
		}
	}
	if !found {
		t.Errorf("expected idle recommendation, got %d recs: %+v", count, repo.recommendations)
	}
}

func TestGenerateRecommendations_NoMemoryLimit(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	summaries := []*models.ContainerUsageSummary{
		{
			ContainerID:   "cid-1",
			ContainerName: "unlimited",
			CPUAvg:        50,
			CPUPeak:       90,
			MemoryLimit:   0, // No limit
			MemoryAvg:     0,
			LastSeen:      time.Now(),
		},
	}

	count, err := svc.GenerateRecommendations(context.Background(), summaries)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
	if repo.recommendations[0].Type != models.RecommendAddLimit {
		t.Errorf("type = %q, want %q", repo.recommendations[0].Type, models.RecommendAddLimit)
	}
}

func TestGenerateRecommendations_HealthyContainer(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	summaries := []*models.ContainerUsageSummary{
		{
			ContainerID:   "cid-1",
			ContainerName: "healthy",
			CPUAvg:        40,
			CPUPeak:       70,
			MemoryLimit:   1024 * 1024 * 1024,
			MemoryAvg:     600 * 1024 * 1024, // 60% of limit
			LastSeen:      time.Now(),
		},
	}

	count, err := svc.GenerateRecommendations(context.Background(), summaries)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 recommendations for healthy container, got %d", count)
	}
}

func TestGenerateRecommendations_Empty(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	count, err := svc.GenerateRecommendations(context.Background(), nil)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 for empty summaries, got %d", count)
	}
}

func TestCleanupOldSamples(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	deleted, err := svc.CleanupOldSamples(context.Background(), 30)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if deleted != 42 {
		t.Errorf("deleted = %d, want 42", deleted)
	}
}

func TestApplyRecommendation(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	err := svc.ApplyRecommendation(context.Background(), uuid.New(), nil)
	if err != nil {
		t.Fatalf("ApplyRecommendation() error = %v", err)
	}
}

func TestDismissRecommendation(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	err := svc.DismissRecommendation(context.Background(), uuid.New(), nil)
	if err != nil {
		t.Fatalf("DismissRecommendation() error = %v", err)
	}
}
