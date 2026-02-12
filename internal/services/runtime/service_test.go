// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package runtime

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// ---------------------------------------------------------------------------
// Mock repository
// ---------------------------------------------------------------------------

type mockRepo struct {
	events    []*models.RuntimeSecurityEvent
	rules     []*models.RuntimeSecurityRule
	baselines []*models.RuntimeBaseline
}

func newMockRepo() *mockRepo {
	return &mockRepo{}
}

func (m *mockRepo) CreateEvent(_ context.Context, event *models.RuntimeSecurityEvent) error {
	m.events = append(m.events, event)
	return nil
}

func (m *mockRepo) CreateEventBatch(_ context.Context, events []*models.RuntimeSecurityEvent) error {
	m.events = append(m.events, events...)
	return nil
}

func (m *mockRepo) ListEvents(_ context.Context, opts postgres.RuntimeEventListOptions) ([]*models.RuntimeSecurityEvent, int64, error) {
	limit := opts.Limit
	if limit <= 0 || limit > len(m.events) {
		limit = len(m.events)
	}
	result := m.events
	if limit < len(m.events) {
		result = m.events[:limit]
	}
	return result, int64(len(m.events)), nil
}

func (m *mockRepo) AcknowledgeEvent(_ context.Context, _ int64, _ uuid.UUID) error {
	return nil
}

func (m *mockRepo) GetEventStats(_ context.Context, _ time.Time) (*postgres.RuntimeEventStats, error) {
	return &postgres.RuntimeEventStats{
		TotalEvents:    int64(len(m.events)),
		SeverityCounts: map[string]int{},
		TypeCounts:     map[string]int{},
		TopContainers:  nil,
	}, nil
}

func (m *mockRepo) DeleteOldEvents(_ context.Context, _ time.Duration) (int64, error) {
	return 0, nil
}

func (m *mockRepo) CreateRule(_ context.Context, rule *models.RuntimeSecurityRule) error {
	m.rules = append(m.rules, rule)
	return nil
}

func (m *mockRepo) GetRule(_ context.Context, id uuid.UUID) (*models.RuntimeSecurityRule, error) {
	for _, r := range m.rules {
		if r.ID == id {
			return r, nil
		}
	}
	return nil, nil
}

func (m *mockRepo) ListRules(_ context.Context) ([]*models.RuntimeSecurityRule, error) {
	return m.rules, nil
}

func (m *mockRepo) UpdateRule(_ context.Context, _ *models.RuntimeSecurityRule) error {
	return nil
}

func (m *mockRepo) DeleteRule(_ context.Context, _ uuid.UUID) error {
	return nil
}

func (m *mockRepo) ToggleRule(_ context.Context, _ uuid.UUID, _ bool) error {
	return nil
}

func (m *mockRepo) IncrementRuleEventCount(_ context.Context, _ uuid.UUID) error {
	return nil
}

func (m *mockRepo) CreateBaseline(_ context.Context, baseline *models.RuntimeBaseline) error {
	m.baselines = append(m.baselines, baseline)
	return nil
}

func (m *mockRepo) GetActiveBaseline(_ context.Context, _ string, _ string) (*models.RuntimeBaseline, error) {
	return nil, nil
}

func (m *mockRepo) UpdateBaseline(_ context.Context, _ *models.RuntimeBaseline) error {
	return nil
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestNewService(t *testing.T) {
	repo := newMockRepo()
	cfg := DefaultConfig()

	svc := NewService(repo, nil, cfg, nil) // nil hostService and nil logger
	if svc == nil {
		t.Fatal("NewService returned nil")
	}
	if svc.repo != repo {
		t.Fatal("expected repo to be set")
	}
	if !svc.config.Enabled {
		t.Fatal("expected config.Enabled to be true by default")
	}
}

func TestListEvents_Delegates(t *testing.T) {
	repo := newMockRepo()
	// Pre-populate some events.
	repo.events = []*models.RuntimeSecurityEvent{
		{ID: 1, ContainerID: "c1", EventType: "process", Severity: "high", DetectedAt: time.Now()},
		{ID: 2, ContainerID: "c2", EventType: "network", Severity: "medium", DetectedAt: time.Now()},
	}

	svc := NewService(repo, nil, DefaultConfig(), logger.Nop())

	events, total, err := svc.ListEvents(context.Background(), postgres.RuntimeEventListOptions{})
	if err != nil {
		t.Fatalf("ListEvents returned unexpected error: %v", err)
	}
	if total != 2 {
		t.Fatalf("expected total=2, got %d", total)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
}

func TestListRules_Delegates(t *testing.T) {
	repo := newMockRepo()
	svc := NewService(repo, nil, DefaultConfig(), logger.Nop())

	rules, err := svc.ListRules(context.Background())
	if err != nil {
		t.Fatalf("ListRules returned unexpected error: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected 0 rules from empty repo, got %d", len(rules))
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if !cfg.Enabled {
		t.Error("expected Enabled to be true")
	}
	if cfg.Retention != 30*24*time.Hour {
		t.Errorf("expected Retention=30d, got %v", cfg.Retention)
	}
	if cfg.MonitorInterval != 1*time.Minute {
		t.Errorf("expected MonitorInterval=1m, got %v", cfg.MonitorInterval)
	}
	if cfg.BaselineLearningPeriod != 24*time.Hour {
		t.Errorf("expected BaselineLearningPeriod=24h, got %v", cfg.BaselineLearningPeriod)
	}
	if cfg.BaselineMinSamples != 100 {
		t.Errorf("expected BaselineMinSamples=100, got %d", cfg.BaselineMinSamples)
	}
}
