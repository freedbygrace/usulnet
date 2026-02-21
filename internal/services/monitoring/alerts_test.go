// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package monitoring

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/testutil"
)

// ---------------------------------------------------------------------------
// Mock: AlertRepository
// ---------------------------------------------------------------------------

type mockAlertRepo struct {
	mu     sync.Mutex
	rules  map[uuid.UUID]*models.AlertRule
	events map[uuid.UUID]*models.AlertEvent
	silences []*models.AlertSilence
	stats  *models.AlertStats

	createRuleErr error
	getRuleErr    error
	listRulesErr  error
}

func newMockAlertRepo() *mockAlertRepo {
	return &mockAlertRepo{
		rules:  make(map[uuid.UUID]*models.AlertRule),
		events: make(map[uuid.UUID]*models.AlertEvent),
	}
}

func (r *mockAlertRepo) CreateRule(_ context.Context, rule *models.AlertRule) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.createRuleErr != nil {
		return r.createRuleErr
	}
	r.rules[rule.ID] = rule
	return nil
}

func (r *mockAlertRepo) GetRule(_ context.Context, id uuid.UUID) (*models.AlertRule, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.getRuleErr != nil {
		return nil, r.getRuleErr
	}
	rule, ok := r.rules[id]
	if !ok {
		return nil, errors.New("rule not found")
	}
	return rule, nil
}

func (r *mockAlertRepo) UpdateRule(_ context.Context, rule *models.AlertRule) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules[rule.ID] = rule
	return nil
}

func (r *mockAlertRepo) DeleteRule(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.rules, id)
	return nil
}

func (r *mockAlertRepo) ListRules(_ context.Context, _ models.AlertListOptions) ([]*models.AlertRule, int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.listRulesErr != nil {
		return nil, 0, r.listRulesErr
	}
	var rules []*models.AlertRule
	for _, rule := range r.rules {
		rules = append(rules, rule)
	}
	return rules, int64(len(rules)), nil
}

func (r *mockAlertRepo) ListEnabledRules(_ context.Context) ([]*models.AlertRule, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var rules []*models.AlertRule
	for _, rule := range r.rules {
		if rule.IsEnabled {
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

func (r *mockAlertRepo) CreateEvent(_ context.Context, event *models.AlertEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events[event.ID] = event
	return nil
}

func (r *mockAlertRepo) GetEvent(_ context.Context, id uuid.UUID) (*models.AlertEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	event, ok := r.events[id]
	if !ok {
		return nil, errors.New("event not found")
	}
	return event, nil
}

func (r *mockAlertRepo) UpdateEvent(_ context.Context, event *models.AlertEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events[event.ID] = event
	return nil
}

func (r *mockAlertRepo) ListEvents(_ context.Context, opts models.AlertEventListOptions) ([]*models.AlertEvent, int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var events []*models.AlertEvent
	for _, event := range r.events {
		if opts.AlertID != nil && event.AlertID != *opts.AlertID {
			continue
		}
		if opts.State != nil && event.State != *opts.State {
			continue
		}
		events = append(events, event)
	}
	return events, int64(len(events)), nil
}

func (r *mockAlertRepo) GetActiveEvents(_ context.Context) ([]*models.AlertEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var events []*models.AlertEvent
	for _, event := range r.events {
		if event.State == models.AlertStateFiring {
			events = append(events, event)
		}
	}
	return events, nil
}

func (r *mockAlertRepo) CreateSilence(_ context.Context, silence *models.AlertSilence) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.silences = append(r.silences, silence)
	return nil
}

func (r *mockAlertRepo) GetSilence(_ context.Context, id uuid.UUID) (*models.AlertSilence, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.silences {
		if s.ID == id {
			return s, nil
		}
	}
	return nil, errors.New("silence not found")
}

func (r *mockAlertRepo) DeleteSilence(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, s := range r.silences {
		if s.ID == id {
			r.silences = append(r.silences[:i], r.silences[i+1:]...)
			return nil
		}
	}
	return errors.New("silence not found")
}

func (r *mockAlertRepo) ListSilences(_ context.Context) ([]*models.AlertSilence, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.silences, nil
}

func (r *mockAlertRepo) GetActiveSilences(_ context.Context) ([]*models.AlertSilence, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var active []*models.AlertSilence
	for _, s := range r.silences {
		if s.IsActive() {
			active = append(active, s)
		}
	}
	return active, nil
}

func (r *mockAlertRepo) GetStats(_ context.Context) (*models.AlertStats, error) {
	if r.stats != nil {
		return r.stats, nil
	}
	return &models.AlertStats{}, nil
}

// ---------------------------------------------------------------------------
// Mock: MetricsProvider
// ---------------------------------------------------------------------------

type mockMetricsProvider struct {
	mu        sync.Mutex
	hostVals  map[string]float64 // "hostID:metric" -> value
	contVals  map[string]float64 // "hostID:containerID:metric" -> value
	hostIDs   []uuid.UUID
	contIDs   map[uuid.UUID][]string
	returnErr error
}

func newMockMetricsProvider() *mockMetricsProvider {
	return &mockMetricsProvider{
		hostVals: make(map[string]float64),
		contVals: make(map[string]float64),
		contIDs:  make(map[uuid.UUID][]string),
	}
}

func (m *mockMetricsProvider) setHostMetric(hostID uuid.UUID, metric models.AlertMetric, value float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hostVals[hostID.String()+":"+string(metric)] = value
}

func (m *mockMetricsProvider) GetHostMetric(_ context.Context, hostID uuid.UUID, metric models.AlertMetric) (float64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.returnErr != nil {
		return 0, m.returnErr
	}
	key := hostID.String() + ":" + string(metric)
	v, ok := m.hostVals[key]
	if !ok {
		return 0, errors.New("metric not found")
	}
	return v, nil
}

func (m *mockMetricsProvider) GetContainerMetric(_ context.Context, hostID uuid.UUID, containerID string, metric models.AlertMetric) (float64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.returnErr != nil {
		return 0, m.returnErr
	}
	key := hostID.String() + ":" + containerID + ":" + string(metric)
	v, ok := m.contVals[key]
	if !ok {
		return 0, errors.New("metric not found")
	}
	return v, nil
}

func (m *mockMetricsProvider) ListHosts(_ context.Context) ([]uuid.UUID, error) {
	return m.hostIDs, nil
}

func (m *mockMetricsProvider) ListContainers(_ context.Context, hostID uuid.UUID) ([]string, error) {
	return m.contIDs[hostID], nil
}

// ---------------------------------------------------------------------------
// Mock: NotificationSender
// ---------------------------------------------------------------------------

type mockNotifier struct {
	mu    sync.Mutex
	sent  []sentAlert
	err   error
}

type sentAlert struct {
	Rule  *models.AlertRule
	Event *models.AlertEvent
}

func newMockNotifier() *mockNotifier {
	return &mockNotifier{}
}

func (n *mockNotifier) SendAlert(_ context.Context, rule *models.AlertRule, event *models.AlertEvent) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.err != nil {
		return n.err
	}
	n.sent = append(n.sent, sentAlert{Rule: rule, Event: event})
	return nil
}

func (n *mockNotifier) sentCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.sent)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func newTestAlertService(repo *mockAlertRepo, metrics *mockMetricsProvider, notifier *mockNotifier) *AlertService {
	log := testutil.NewTestLogger(&testing.T{})
	return NewAlertService(repo, metrics, notifier, DefaultAlertConfig(), log)
}

func TestNewAlertService_NilLogger(t *testing.T) {
	svc := NewAlertService(newMockAlertRepo(), nil, nil, DefaultAlertConfig(), nil)
	if svc == nil {
		t.Fatal("expected non-nil service with nil logger")
	}
}

func TestCreateRule_Success(t *testing.T) {
	repo := newMockAlertRepo()
	svc := newTestAlertService(repo, nil, nil)

	hostID := testutil.TestHostID
	input := models.CreateAlertRuleInput{
		HostID:          &hostID,
		Name:            "High CPU",
		Description:     "CPU > 90%",
		Metric:          models.AlertMetricHostCPU,
		Operator:        models.AlertOperatorGreater,
		Threshold:       90.0,
		Severity:        models.AlertSeverityCritical,
		DurationSeconds: 60,
		IsEnabled:       true,
	}

	rule, err := svc.CreateRule(context.Background(), input, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rule.Name != "High CPU" {
		t.Errorf("expected name 'High CPU', got %q", rule.Name)
	}
	if rule.State != models.AlertStateOK {
		t.Errorf("expected initial state OK, got %q", rule.State)
	}
	if rule.Cooldown == 0 {
		t.Error("expected default cooldown to be set")
	}
	if rule.EvalInterval == 0 {
		t.Error("expected default eval interval to be set")
	}

	// Verify stored
	stored, err := repo.GetRule(context.Background(), rule.ID)
	if err != nil {
		t.Fatalf("rule not found in repo: %v", err)
	}
	if stored.ID != rule.ID {
		t.Error("stored rule ID mismatch")
	}
}

func TestCreateRule_RepoError(t *testing.T) {
	repo := newMockAlertRepo()
	repo.createRuleErr = errors.New("db connection failed")
	svc := newTestAlertService(repo, nil, nil)

	_, err := svc.CreateRule(context.Background(), models.CreateAlertRuleInput{
		Name:      "test",
		Metric:    models.AlertMetricHostCPU,
		Operator:  models.AlertOperatorGreater,
		Threshold: 50,
		Severity:  models.AlertSeverityWarning,
		IsEnabled: true,
	}, nil)
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

func TestGetRule(t *testing.T) {
	repo := newMockAlertRepo()
	svc := newTestAlertService(repo, nil, nil)

	rule, _ := svc.CreateRule(context.Background(), models.CreateAlertRuleInput{
		Name:      "test",
		Metric:    models.AlertMetricHostCPU,
		Operator:  models.AlertOperatorGreater,
		Threshold: 50,
		Severity:  models.AlertSeverityWarning,
		IsEnabled: true,
	}, nil)

	got, err := svc.GetRule(context.Background(), rule.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != rule.ID {
		t.Error("rule ID mismatch")
	}
}

func TestDeleteRule_CleansState(t *testing.T) {
	repo := newMockAlertRepo()
	svc := newTestAlertService(repo, nil, nil)

	rule, _ := svc.CreateRule(context.Background(), models.CreateAlertRuleInput{
		Name:      "test",
		Metric:    models.AlertMetricHostCPU,
		Operator:  models.AlertOperatorGreater,
		Threshold: 50,
		Severity:  models.AlertSeverityWarning,
		IsEnabled: true,
	}, nil)

	// Simulate some state
	svc.ruleStatesMu.Lock()
	svc.ruleStates[rule.ID] = &ruleState{lastValue: 99.0}
	svc.ruleStatesMu.Unlock()

	if err := svc.DeleteRule(context.Background(), rule.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify state cleaned
	svc.ruleStatesMu.RLock()
	_, exists := svc.ruleStates[rule.ID]
	svc.ruleStatesMu.RUnlock()
	if exists {
		t.Error("expected rule state to be cleaned up after delete")
	}

	// Verify removed from repo
	_, err := repo.GetRule(context.Background(), rule.ID)
	if err == nil {
		t.Error("expected rule to be removed from repo")
	}
}

func TestUpdateRule(t *testing.T) {
	repo := newMockAlertRepo()
	svc := newTestAlertService(repo, nil, nil)

	rule, _ := svc.CreateRule(context.Background(), models.CreateAlertRuleInput{
		Name:      "test",
		Metric:    models.AlertMetricHostCPU,
		Operator:  models.AlertOperatorGreater,
		Threshold: 50,
		Severity:  models.AlertSeverityWarning,
		IsEnabled: true,
	}, nil)

	newName := "Updated Name"
	newThreshold := 75.0
	updated, err := svc.UpdateRule(context.Background(), rule.ID, models.UpdateAlertRuleInput{
		Name:      &newName,
		Threshold: &newThreshold,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated.Name != "Updated Name" {
		t.Errorf("expected name 'Updated Name', got %q", updated.Name)
	}
	if updated.Threshold != 75.0 {
		t.Errorf("expected threshold 75.0, got %f", updated.Threshold)
	}
	// Ensure unchanged fields preserved
	if updated.Metric != models.AlertMetricHostCPU {
		t.Errorf("expected metric preserved, got %q", updated.Metric)
	}
}

func TestEvaluateRule_ConditionMet_Fires(t *testing.T) {
	repo := newMockAlertRepo()
	metrics := newMockMetricsProvider()
	notifier := newMockNotifier()
	log := testutil.NewTestLogger(t)
	svc := NewAlertService(repo, metrics, notifier, AlertServiceConfig{
		DefaultEvalInterval:      1 * time.Second,
		MaxConcurrentEvaluations: 5,
		EnableAutoResolve:        true,
	}, log)

	hostID := testutil.TestHostID
	metrics.setHostMetric(hostID, models.AlertMetricHostCPU, 95.0)

	rule := &models.AlertRule{
		ID:        uuid.New(),
		HostID:    &hostID,
		Name:      "CPU Alert",
		Metric:    models.AlertMetricHostCPU,
		Operator:  models.AlertOperatorGreater,
		Threshold: 90.0,
		Severity:  models.AlertSeverityCritical,
		Duration:  0, // Fire immediately
		Cooldown:  0,
		State:     models.AlertStateOK,
		IsEnabled: true,
	}
	repo.rules[rule.ID] = rule

	// Evaluate the rule directly
	svc.evaluateRule(context.Background(), rule)

	// Rule should be firing
	if rule.State != models.AlertStateFiring {
		t.Errorf("expected state Firing, got %q", rule.State)
	}

	// Event should have been created
	if len(repo.events) != 1 {
		t.Errorf("expected 1 event, got %d", len(repo.events))
	}

	// Notification should have been sent
	if notifier.sentCount() != 1 {
		t.Errorf("expected 1 notification, got %d", notifier.sentCount())
	}
}

func TestEvaluateRule_ConditionNotMet_StaysOK(t *testing.T) {
	repo := newMockAlertRepo()
	metrics := newMockMetricsProvider()
	log := testutil.NewTestLogger(t)
	svc := NewAlertService(repo, metrics, nil, DefaultAlertConfig(), log)

	hostID := testutil.TestHostID
	metrics.setHostMetric(hostID, models.AlertMetricHostCPU, 50.0)

	rule := &models.AlertRule{
		ID:        uuid.New(),
		HostID:    &hostID,
		Name:      "CPU Alert",
		Metric:    models.AlertMetricHostCPU,
		Operator:  models.AlertOperatorGreater,
		Threshold: 90.0,
		Severity:  models.AlertSeverityWarning,
		State:     models.AlertStateOK,
		IsEnabled: true,
	}
	repo.rules[rule.ID] = rule

	svc.evaluateRule(context.Background(), rule)

	if rule.State != models.AlertStateOK {
		t.Errorf("expected state OK, got %q", rule.State)
	}
	if len(repo.events) != 0 {
		t.Errorf("expected no events, got %d", len(repo.events))
	}
}

func TestEvaluateRule_Duration_PendingBeforeFiring(t *testing.T) {
	repo := newMockAlertRepo()
	metrics := newMockMetricsProvider()
	log := testutil.NewTestLogger(t)
	svc := NewAlertService(repo, metrics, nil, DefaultAlertConfig(), log)

	hostID := testutil.TestHostID
	metrics.setHostMetric(hostID, models.AlertMetricHostCPU, 95.0)

	rule := &models.AlertRule{
		ID:        uuid.New(),
		HostID:    &hostID,
		Name:      "CPU Alert",
		Metric:    models.AlertMetricHostCPU,
		Operator:  models.AlertOperatorGreater,
		Threshold: 90.0,
		Severity:  models.AlertSeverityCritical,
		Duration:  60, // Must be true for 60 seconds
		State:     models.AlertStateOK,
		IsEnabled: true,
	}
	repo.rules[rule.ID] = rule

	// First evaluation: should go to pending
	svc.evaluateRule(context.Background(), rule)
	if rule.State != models.AlertStatePending {
		t.Errorf("expected state Pending, got %q", rule.State)
	}
	if len(repo.events) != 0 {
		t.Errorf("expected no events yet, got %d", len(repo.events))
	}
}

func TestEvaluateRule_AutoResolve(t *testing.T) {
	repo := newMockAlertRepo()
	metrics := newMockMetricsProvider()
	log := testutil.NewTestLogger(t)
	svc := NewAlertService(repo, metrics, nil, AlertServiceConfig{
		DefaultEvalInterval:      1 * time.Second,
		MaxConcurrentEvaluations: 5,
		EnableAutoResolve:        true,
	}, log)

	hostID := testutil.TestHostID
	metrics.setHostMetric(hostID, models.AlertMetricHostCPU, 95.0)

	rule := &models.AlertRule{
		ID:        uuid.New(),
		HostID:    &hostID,
		Name:      "CPU Alert",
		Metric:    models.AlertMetricHostCPU,
		Operator:  models.AlertOperatorGreater,
		Threshold: 90.0,
		Severity:  models.AlertSeverityCritical,
		Duration:  0,
		Cooldown:  0,
		State:     models.AlertStateOK,
		IsEnabled: true,
	}
	repo.rules[rule.ID] = rule

	// Fire the alert
	svc.evaluateRule(context.Background(), rule)
	if rule.State != models.AlertStateFiring {
		t.Fatalf("expected Firing, got %q", rule.State)
	}

	// Now value drops below threshold
	metrics.setHostMetric(hostID, models.AlertMetricHostCPU, 50.0)
	svc.evaluateRule(context.Background(), rule)

	if rule.State != models.AlertStateResolved {
		t.Errorf("expected state Resolved after condition cleared, got %q", rule.State)
	}
}

func TestIsSilenced(t *testing.T) {
	log := testutil.NewTestLogger(t)
	svc := NewAlertService(newMockAlertRepo(), nil, nil, DefaultAlertConfig(), log)

	ruleID := uuid.New()
	hostID := uuid.New()
	now := time.Now()
	later := now.Add(1 * time.Hour)

	rule := &models.AlertRule{
		ID:     ruleID,
		HostID: &hostID,
	}

	tests := []struct {
		name      string
		silences  []*models.AlertSilence
		want      bool
	}{
		{
			name:     "no silences",
			silences: nil,
			want:     false,
		},
		{
			name: "rule-specific silence",
			silences: []*models.AlertSilence{
				{ID: uuid.New(), AlertID: &ruleID, StartsAt: now, EndsAt: later},
			},
			want: true,
		},
		{
			name: "host-specific silence",
			silences: []*models.AlertSilence{
				{ID: uuid.New(), HostID: &hostID, StartsAt: now, EndsAt: later},
			},
			want: true,
		},
		{
			name: "global silence",
			silences: []*models.AlertSilence{
				{ID: uuid.New(), StartsAt: now, EndsAt: later},
			},
			want: true,
		},
		{
			name: "expired silence",
			silences: []*models.AlertSilence{
				{ID: uuid.New(), AlertID: &ruleID, StartsAt: now.Add(-2 * time.Hour), EndsAt: now.Add(-1 * time.Hour)},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := svc.isSilenced(rule, tt.silences)
			if got != tt.want {
				t.Errorf("isSilenced() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatAlertMessage(t *testing.T) {
	log := testutil.NewTestLogger(t)
	svc := NewAlertService(newMockAlertRepo(), nil, nil, DefaultAlertConfig(), log)

	rule := &models.AlertRule{
		Name:      "CPU Alert",
		Metric:    models.AlertMetricHostCPU,
		Operator:  models.AlertOperatorGreater,
		Threshold: 90.0,
	}

	msg := svc.formatAlertMessage(rule, 95.5)
	if msg == "" {
		t.Error("expected non-empty message")
	}
	// Should contain rule name, metric, value, and threshold
	for _, want := range []string{"CPU Alert", "host_cpu", "95.50", "90.00"} {
		if !containsStr(msg, want) {
			t.Errorf("expected message to contain %q, got %q", want, msg)
		}
	}
}

func TestStartStop(t *testing.T) {
	repo := newMockAlertRepo()
	log := testutil.NewTestLogger(t)
	svc := NewAlertService(repo, nil, nil, AlertServiceConfig{
		DefaultEvalInterval:      100 * time.Millisecond,
		MaxConcurrentEvaluations: 2,
	}, log)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Let it tick once
	time.Sleep(200 * time.Millisecond)

	if err := svc.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	// Double stop should be safe
	if err := svc.Stop(); err != nil {
		t.Fatalf("double Stop failed: %v", err)
	}
}

func TestGetMetricValue_NilProvider(t *testing.T) {
	log := testutil.NewTestLogger(t)
	svc := NewAlertService(newMockAlertRepo(), nil, nil, DefaultAlertConfig(), log)

	rule := &models.AlertRule{
		Metric: models.AlertMetricHostCPU,
	}

	_, err := svc.getMetricValue(context.Background(), rule)
	if err == nil {
		t.Error("expected error for nil metrics provider")
	}
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
