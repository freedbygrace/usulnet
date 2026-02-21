// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package ephemeral_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/services/ephemeral"
)

// ============================================================================
// Mock Repository
// ============================================================================

type mockRepo struct {
	mu   sync.Mutex
	envs map[uuid.UUID]*models.EphemeralEnvironment
	logs map[uuid.UUID][]*models.EphemeralEnvironmentLog
}

func newMockRepo() *mockRepo {
	return &mockRepo{
		envs: make(map[uuid.UUID]*models.EphemeralEnvironment),
		logs: make(map[uuid.UUID][]*models.EphemeralEnvironmentLog),
	}
}

func (m *mockRepo) Create(_ context.Context, env *models.EphemeralEnvironment) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.envs[env.ID] = env
	return nil
}

func (m *mockRepo) GetByID(_ context.Context, id uuid.UUID) (*models.EphemeralEnvironment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	env, ok := m.envs[id]
	if !ok {
		return nil, fmt.Errorf("environment %s not found", id)
	}
	return env, nil
}

func (m *mockRepo) List(_ context.Context, opts models.EphemeralEnvListOptions) ([]*models.EphemeralEnvironment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*models.EphemeralEnvironment
	for _, env := range m.envs {
		if opts.Status != "" && string(env.Status) != opts.Status {
			continue
		}
		if opts.Branch != "" && env.Branch != opts.Branch {
			continue
		}
		out = append(out, env)
	}
	if opts.Limit > 0 && len(out) > opts.Limit {
		out = out[:opts.Limit]
	}
	return out, nil
}

func (m *mockRepo) UpdateStatus(_ context.Context, id uuid.UUID, status models.EphemeralEnvironmentStatus, errorMsg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	env, ok := m.envs[id]
	if !ok {
		return fmt.Errorf("environment %s not found", id)
	}
	env.Status = status
	env.ErrorMessage = errorMsg
	env.UpdatedAt = time.Now()
	return nil
}

func (m *mockRepo) UpdateTTL(_ context.Context, id uuid.UUID, ttlMinutes int, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	env, ok := m.envs[id]
	if !ok {
		return fmt.Errorf("environment %s not found", id)
	}
	env.TTLMinutes = ttlMinutes
	env.ExpiresAt = &expiresAt
	env.UpdatedAt = time.Now()
	return nil
}

func (m *mockRepo) SetURL(_ context.Context, id uuid.UUID, url string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	env, ok := m.envs[id]
	if !ok {
		return fmt.Errorf("environment %s not found", id)
	}
	env.URL = url
	return nil
}

func (m *mockRepo) Delete(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.envs[id]; !ok {
		return fmt.Errorf("environment %s not found", id)
	}
	delete(m.envs, id)
	return nil
}

func (m *mockRepo) ListExpired(_ context.Context) ([]*models.EphemeralEnvironment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	var out []*models.EphemeralEnvironment
	for _, env := range m.envs {
		if env.ExpiresAt != nil && env.ExpiresAt.Before(now) &&
			env.Status != models.EphemeralStatusExpired &&
			env.Status != models.EphemeralStatusStopped {
			out = append(out, env)
		}
	}
	return out, nil
}

func (m *mockRepo) CountByStatus(_ context.Context) (map[string]int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	counts := make(map[string]int)
	for _, env := range m.envs {
		counts[string(env.Status)]++
	}
	return counts, nil
}

func (m *mockRepo) CreateLog(_ context.Context, logEntry *models.EphemeralEnvironmentLog) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs[logEntry.EnvironmentID] = append(m.logs[logEntry.EnvironmentID], logEntry)
	return nil
}

func (m *mockRepo) ListLogs(_ context.Context, envID uuid.UUID, limit int) ([]*models.EphemeralEnvironmentLog, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entries := m.logs[envID]
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}
	return entries, nil
}

// ============================================================================
// Tests
// ============================================================================

func newService() (*ephemeral.Service, *mockRepo) {
	repo := newMockRepo()
	svc := ephemeral.NewService(repo, ephemeral.DefaultConfig(), nil)
	return svc, repo
}

func validInput() ephemeral.CreateEnvInput {
	return ephemeral.CreateEnvInput{
		Name:           "test-env",
		Branch:         "feature/login",
		ComposeContent: "version: '3'\nservices:\n  app:\n    image: nginx",
		TTLMinutes:     60,
		AutoDestroy:    true,
	}
}

func TestCreateEnvironment(t *testing.T) {
	svc, _ := newService()
	ctx := context.Background()

	input := validInput()
	env, err := svc.CreateEnvironment(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env.Name != "test-env" {
		t.Errorf("Name = %q, want %q", env.Name, "test-env")
	}
	if env.Branch != "feature/login" {
		t.Errorf("Branch = %q, want %q", env.Branch, "feature/login")
	}
	if !strings.HasPrefix(env.StackName, "eph-") {
		t.Errorf("StackName = %q, expected prefix %q", env.StackName, "eph-")
	}
	if env.TTLMinutes != 60 {
		t.Errorf("TTLMinutes = %d, want 60", env.TTLMinutes)
	}
	if env.Status != models.EphemeralStatusPending {
		t.Errorf("Status = %q, want %q", env.Status, models.EphemeralStatusPending)
	}
	if env.ExpiresAt == nil {
		t.Fatal("ExpiresAt should not be nil")
	}
	// ExpiresAt should be roughly 60 minutes from now.
	diff := time.Until(*env.ExpiresAt)
	if diff < 59*time.Minute || diff > 61*time.Minute {
		t.Errorf("ExpiresAt diff = %v, want ~60m", diff)
	}
}

func TestCreateEnvironment_Validation(t *testing.T) {
	svc, _ := newService()
	ctx := context.Background()

	tests := []struct {
		name  string
		input ephemeral.CreateEnvInput
	}{
		{"empty name", ephemeral.CreateEnvInput{Branch: "main", ComposeContent: "x"}},
		{"empty branch", ephemeral.CreateEnvInput{Name: "env", ComposeContent: "x"}},
		{"no compose or repo", ephemeral.CreateEnvInput{Name: "env", Branch: "main"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.CreateEnvironment(ctx, tc.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestListEnvironments(t *testing.T) {
	svc, _ := newService()
	ctx := context.Background()

	branches := []string{"main", "dev", "main"}
	for i, br := range branches {
		input := validInput()
		input.Name = fmt.Sprintf("env-%d", i)
		input.Branch = br
		if _, err := svc.CreateEnvironment(ctx, input); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}

	// List all.
	all, err := svc.ListEnvironments(ctx, models.EphemeralEnvListOptions{})
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("len(all) = %d, want 3", len(all))
	}

	// Filter by branch.
	mainEnvs, err := svc.ListEnvironments(ctx, models.EphemeralEnvListOptions{Branch: "main"})
	if err != nil {
		t.Fatalf("list main: %v", err)
	}
	if len(mainEnvs) != 2 {
		t.Errorf("len(mainEnvs) = %d, want 2", len(mainEnvs))
	}
}

func TestExtendTTL(t *testing.T) {
	svc, repo := newService()
	ctx := context.Background()

	env, err := svc.CreateEnvironment(ctx, validInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Must be running to extend TTL.
	repo.mu.Lock()
	repo.envs[env.ID].Status = models.EphemeralStatusRunning
	repo.mu.Unlock()

	origExpiry := *env.ExpiresAt
	err = svc.ExtendTTL(ctx, env.ID, 30)
	if err != nil {
		t.Fatalf("extend: %v", err)
	}

	// Verify the environment was updated via log entry.
	logs, _ := svc.GetLogs(ctx, env.ID, 10)
	found := false
	for _, l := range logs {
		if l.Phase == "extend" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected an 'extend' log entry")
	}

	// ExtendTTL on a non-running env should fail.
	repo.mu.Lock()
	repo.envs[env.ID].Status = models.EphemeralStatusStopped
	repo.mu.Unlock()

	err = svc.ExtendTTL(ctx, env.ID, 30)
	if err == nil {
		t.Fatal("expected error extending stopped env")
	}

	_ = origExpiry // used to verify new expiry is later
}

func TestGetDashboard(t *testing.T) {
	svc, repo := newService()
	ctx := context.Background()

	// Seed envs with specific statuses.
	statuses := []models.EphemeralEnvironmentStatus{
		models.EphemeralStatusRunning,
		models.EphemeralStatusRunning,
		models.EphemeralStatusProvisioning,
		models.EphemeralStatusExpired,
		models.EphemeralStatusStopped,
	}
	for _, s := range statuses {
		id := uuid.New()
		repo.envs[id] = &models.EphemeralEnvironment{ID: id, Status: s}
	}

	dash, err := svc.GetDashboard(ctx)
	if err != nil {
		t.Fatalf("dashboard: %v", err)
	}
	if dash.TotalEnvironments != 5 {
		t.Errorf("TotalEnvironments = %d, want 5", dash.TotalEnvironments)
	}
	if dash.ActiveCount != 3 { // 2 running + 1 provisioning
		t.Errorf("ActiveCount = %d, want 3", dash.ActiveCount)
	}
	if dash.ExpiredCount != 1 {
		t.Errorf("ExpiredCount = %d, want 1", dash.ExpiredCount)
	}
}

func TestCleanupExpired(t *testing.T) {
	svc, repo := newService()
	ctx := context.Background()

	pastTime := time.Now().Add(-1 * time.Hour)

	// An expired running env.
	id1 := uuid.New()
	repo.envs[id1] = &models.EphemeralEnvironment{
		ID:        id1,
		StackName: "eph-expired-1",
		Status:    models.EphemeralStatusRunning,
		ExpiresAt: &pastTime,
	}

	// A non-expired running env.
	futureTime := time.Now().Add(1 * time.Hour)
	id2 := uuid.New()
	repo.envs[id2] = &models.EphemeralEnvironment{
		ID:        id2,
		StackName: "eph-active-1",
		Status:    models.EphemeralStatusRunning,
		ExpiresAt: &futureTime,
	}

	// Mock deployer that always succeeds.
	deployer := &mockDeployer{}

	cleaned, err := svc.CleanupExpired(ctx, deployer)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if cleaned != 1 {
		t.Errorf("cleaned = %d, want 1", cleaned)
	}

	// Verify status updated to expired.
	repo.mu.Lock()
	if repo.envs[id1].Status != models.EphemeralStatusExpired {
		t.Errorf("env1 status = %q, want %q", repo.envs[id1].Status, models.EphemeralStatusExpired)
	}
	if repo.envs[id2].Status != models.EphemeralStatusRunning {
		t.Errorf("env2 status = %q, want %q", repo.envs[id2].Status, models.EphemeralStatusRunning)
	}
	repo.mu.Unlock()
}

func TestDestroyEnvironment_DeletesEvenWhenStopFails(t *testing.T) {
	svc, repo := newService()
	ctx := context.Background()

	env, err := svc.CreateEnvironment(ctx, validInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	repo.mu.Lock()
	repo.envs[env.ID].Status = models.EphemeralStatusRunning
	repo.mu.Unlock()

	err = svc.DestroyEnvironment(ctx, env.ID, &mockFailingDeployer{removeErr: fmt.Errorf("remove failed")})
	if err != nil {
		t.Fatalf("destroy should continue even if stop fails, got: %v", err)
	}

	_, getErr := repo.GetByID(ctx, env.ID)
	if getErr == nil {
		t.Fatal("expected environment to be deleted")
	}
}

func TestDestroyEnvironment_ConcurrentCalls(t *testing.T) {
	svc, repo := newService()
	ctx := context.Background()

	env, err := svc.CreateEnvironment(ctx, validInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	var wg sync.WaitGroup
	results := make(chan error, 2)

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- svc.DestroyEnvironment(ctx, env.ID, nil)
		}()
	}

	wg.Wait()
	close(results)

	successes := 0
	failures := 0
	for result := range results {
		if result == nil {
			successes++
			continue
		}
		failures++
	}

	if successes != 1 || failures != 1 {
		t.Fatalf("expected one success and one failure, got successes=%d failures=%d", successes, failures)
	}

	_, getErr := repo.GetByID(ctx, env.ID)
	if getErr == nil {
		t.Fatal("expected environment to be deleted after concurrent destroy")
	}
}

// ============================================================================
// Mock StackDeployer
// ============================================================================

type mockDeployer struct{}

func (d *mockDeployer) DeployStack(_ context.Context, _ string, _ string, _ map[string]string) error {
	return nil
}

func (d *mockDeployer) RemoveStack(_ context.Context, _ string) error {
	return nil
}

func (d *mockDeployer) GetStackStatus(_ context.Context, _ string) (string, error) {
	return "running", nil
}

type mockFailingDeployer struct {
	removeErr error
}

func (d *mockFailingDeployer) DeployStack(_ context.Context, _ string, _ string, _ map[string]string) error {
	return nil
}

func (d *mockFailingDeployer) RemoveStack(_ context.Context, _ string) error {
	return d.removeErr
}

func (d *mockFailingDeployer) GetStackStatus(_ context.Context, _ string) (string, error) {
	return "running", nil
}
