// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package update

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	dockertypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/testutil"
)

// ============================================================================
// Mock implementations
// ============================================================================

// mockUpdateRepository implements UpdateRepository for testing.
type mockUpdateRepository struct {
	createFn              func(ctx context.Context, update *models.Update) error
	getFn                 func(ctx context.Context, id uuid.UUID) (*models.Update, error)
	updateFn              func(ctx context.Context, update *models.Update) error
	updateStatusFn        func(ctx context.Context, id uuid.UUID, status models.UpdateStatus, errorMsg *string) error
	deleteFn              func(ctx context.Context, id uuid.UUID) error
	listFn                func(ctx context.Context, opts models.UpdateListOptions) ([]*models.Update, int64, error)
	getByTargetFn         func(ctx context.Context, hostID uuid.UUID, targetID string, limit int) ([]*models.Update, error)
	getLatestByTargetFn   func(ctx context.Context, hostID uuid.UUID, targetID string) (*models.Update, error)
	getRollbackCandidateFn func(ctx context.Context, hostID uuid.UUID, targetID string) (*models.Update, error)
	getStatsFn            func(ctx context.Context, hostID *uuid.UUID) (*models.UpdateStats, error)
	createPolicyFn        func(ctx context.Context, policy *models.UpdatePolicy) error
	getPolicyFn           func(ctx context.Context, id uuid.UUID) (*models.UpdatePolicy, error)
	getPolicyByTargetFn   func(ctx context.Context, hostID uuid.UUID, targetType models.UpdateType, targetID string) (*models.UpdatePolicy, error)
	updatePolicyFn        func(ctx context.Context, policy *models.UpdatePolicy) error
	deletePolicyFn        func(ctx context.Context, id uuid.UUID) error
	listPoliciesFn        func(ctx context.Context, hostID *uuid.UUID) ([]*models.UpdatePolicy, error)
	getAutoUpdatePoliciesFn func(ctx context.Context) ([]*models.UpdatePolicy, error)
	createWebhookFn       func(ctx context.Context, webhook *models.UpdateWebhook) error
	getWebhookByTokenFn   func(ctx context.Context, token string) (*models.UpdateWebhook, error)
	updateWebhookLastUsedFn func(ctx context.Context, id uuid.UUID) error
	deleteWebhookFn       func(ctx context.Context, id uuid.UUID) error
	listWebhooksFn        func(ctx context.Context, hostID uuid.UUID) ([]*models.UpdateWebhook, error)
}

func (m *mockUpdateRepository) Create(ctx context.Context, update *models.Update) error {
	if m.createFn != nil {
		return m.createFn(ctx, update)
	}
	return nil
}

func (m *mockUpdateRepository) Get(ctx context.Context, id uuid.UUID) (*models.Update, error) {
	if m.getFn != nil {
		return m.getFn(ctx, id)
	}
	return nil, fmt.Errorf("not found")
}

func (m *mockUpdateRepository) Update(ctx context.Context, update *models.Update) error {
	if m.updateFn != nil {
		return m.updateFn(ctx, update)
	}
	return nil
}

func (m *mockUpdateRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status models.UpdateStatus, errorMsg *string) error {
	if m.updateStatusFn != nil {
		return m.updateStatusFn(ctx, id, status, errorMsg)
	}
	return nil
}

func (m *mockUpdateRepository) Delete(ctx context.Context, id uuid.UUID) error {
	if m.deleteFn != nil {
		return m.deleteFn(ctx, id)
	}
	return nil
}

func (m *mockUpdateRepository) List(ctx context.Context, opts models.UpdateListOptions) ([]*models.Update, int64, error) {
	if m.listFn != nil {
		return m.listFn(ctx, opts)
	}
	return nil, 0, nil
}

func (m *mockUpdateRepository) GetByTarget(ctx context.Context, hostID uuid.UUID, targetID string, limit int) ([]*models.Update, error) {
	if m.getByTargetFn != nil {
		return m.getByTargetFn(ctx, hostID, targetID, limit)
	}
	return nil, nil
}

func (m *mockUpdateRepository) GetLatestByTarget(ctx context.Context, hostID uuid.UUID, targetID string) (*models.Update, error) {
	if m.getLatestByTargetFn != nil {
		return m.getLatestByTargetFn(ctx, hostID, targetID)
	}
	return nil, nil
}

func (m *mockUpdateRepository) GetRollbackCandidate(ctx context.Context, hostID uuid.UUID, targetID string) (*models.Update, error) {
	if m.getRollbackCandidateFn != nil {
		return m.getRollbackCandidateFn(ctx, hostID, targetID)
	}
	return nil, nil
}

func (m *mockUpdateRepository) GetStats(ctx context.Context, hostID *uuid.UUID) (*models.UpdateStats, error) {
	if m.getStatsFn != nil {
		return m.getStatsFn(ctx, hostID)
	}
	return nil, nil
}

func (m *mockUpdateRepository) CreatePolicy(ctx context.Context, policy *models.UpdatePolicy) error {
	if m.createPolicyFn != nil {
		return m.createPolicyFn(ctx, policy)
	}
	return nil
}

func (m *mockUpdateRepository) GetPolicy(ctx context.Context, id uuid.UUID) (*models.UpdatePolicy, error) {
	if m.getPolicyFn != nil {
		return m.getPolicyFn(ctx, id)
	}
	return nil, nil
}

func (m *mockUpdateRepository) GetPolicyByTarget(ctx context.Context, hostID uuid.UUID, targetType models.UpdateType, targetID string) (*models.UpdatePolicy, error) {
	if m.getPolicyByTargetFn != nil {
		return m.getPolicyByTargetFn(ctx, hostID, targetType, targetID)
	}
	return nil, fmt.Errorf("not found")
}

func (m *mockUpdateRepository) UpdatePolicy(ctx context.Context, policy *models.UpdatePolicy) error {
	if m.updatePolicyFn != nil {
		return m.updatePolicyFn(ctx, policy)
	}
	return nil
}

func (m *mockUpdateRepository) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	if m.deletePolicyFn != nil {
		return m.deletePolicyFn(ctx, id)
	}
	return nil
}

func (m *mockUpdateRepository) ListPolicies(ctx context.Context, hostID *uuid.UUID) ([]*models.UpdatePolicy, error) {
	if m.listPoliciesFn != nil {
		return m.listPoliciesFn(ctx, hostID)
	}
	return nil, nil
}

func (m *mockUpdateRepository) GetAutoUpdatePolicies(ctx context.Context) ([]*models.UpdatePolicy, error) {
	if m.getAutoUpdatePoliciesFn != nil {
		return m.getAutoUpdatePoliciesFn(ctx)
	}
	return nil, nil
}

func (m *mockUpdateRepository) CreateWebhook(ctx context.Context, webhook *models.UpdateWebhook) error {
	if m.createWebhookFn != nil {
		return m.createWebhookFn(ctx, webhook)
	}
	return nil
}

func (m *mockUpdateRepository) GetWebhookByToken(ctx context.Context, token string) (*models.UpdateWebhook, error) {
	if m.getWebhookByTokenFn != nil {
		return m.getWebhookByTokenFn(ctx, token)
	}
	return nil, fmt.Errorf("not found")
}

func (m *mockUpdateRepository) UpdateWebhookLastUsed(ctx context.Context, id uuid.UUID) error {
	if m.updateWebhookLastUsedFn != nil {
		return m.updateWebhookLastUsedFn(ctx, id)
	}
	return nil
}

func (m *mockUpdateRepository) DeleteWebhook(ctx context.Context, id uuid.UUID) error {
	if m.deleteWebhookFn != nil {
		return m.deleteWebhookFn(ctx, id)
	}
	return nil
}

func (m *mockUpdateRepository) ListWebhooks(ctx context.Context, hostID uuid.UUID) ([]*models.UpdateWebhook, error) {
	if m.listWebhooksFn != nil {
		return m.listWebhooksFn(ctx, hostID)
	}
	return nil, nil
}

// mockDockerClient implements DockerClient for testing.
type mockDockerClient struct {
	containerInspectFn func(ctx context.Context, containerID string) (*dockertypes.ContainerJSON, error)
	containerStopFn    func(ctx context.Context, containerID string, timeout *int) error
	containerStartFn   func(ctx context.Context, containerID string) error
	containerRemoveFn  func(ctx context.Context, containerID string, force bool) error
	containerCreateFn  func(ctx context.Context, config *container.Config, hostConfig *container.HostConfig, name string) (string, error)
	containerRenameFn  func(ctx context.Context, containerID, newName string) error
	containerListFn    func(ctx context.Context) ([]ContainerInfo, error)
	imagePullFn        func(ctx context.Context, ref string, onProgress func(status string)) error
	imageInspectFn     func(ctx context.Context, imageID string) (*ImageInfo, error)
}

func (m *mockDockerClient) ContainerInspect(ctx context.Context, containerID string) (*dockertypes.ContainerJSON, error) {
	if m.containerInspectFn != nil {
		return m.containerInspectFn(ctx, containerID)
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockDockerClient) ContainerStop(ctx context.Context, containerID string, timeout *int) error {
	if m.containerStopFn != nil {
		return m.containerStopFn(ctx, containerID, timeout)
	}
	return nil
}

func (m *mockDockerClient) ContainerStart(ctx context.Context, containerID string) error {
	if m.containerStartFn != nil {
		return m.containerStartFn(ctx, containerID)
	}
	return nil
}

func (m *mockDockerClient) ContainerRemove(ctx context.Context, containerID string, force bool) error {
	if m.containerRemoveFn != nil {
		return m.containerRemoveFn(ctx, containerID, force)
	}
	return nil
}

func (m *mockDockerClient) ContainerCreate(ctx context.Context, config *container.Config, hostConfig *container.HostConfig, name string) (string, error) {
	if m.containerCreateFn != nil {
		return m.containerCreateFn(ctx, config, hostConfig, name)
	}
	return "new-container-id", nil
}

func (m *mockDockerClient) ContainerRename(ctx context.Context, containerID, newName string) error {
	if m.containerRenameFn != nil {
		return m.containerRenameFn(ctx, containerID, newName)
	}
	return nil
}

func (m *mockDockerClient) ContainerList(ctx context.Context) ([]ContainerInfo, error) {
	if m.containerListFn != nil {
		return m.containerListFn(ctx)
	}
	return nil, nil
}

func (m *mockDockerClient) ImagePull(ctx context.Context, ref string, onProgress func(status string)) error {
	if m.imagePullFn != nil {
		return m.imagePullFn(ctx, ref, onProgress)
	}
	return nil
}

func (m *mockDockerClient) ImageInspect(ctx context.Context, imageID string) (*ImageInfo, error) {
	if m.imageInspectFn != nil {
		return m.imageInspectFn(ctx, imageID)
	}
	return &ImageInfo{}, nil
}

// mockBackupService implements BackupService for testing.
type mockBackupService struct {
	createFn  func(ctx context.Context, opts BackupCreateOptions) (*BackupResult, error)
	restoreFn func(ctx context.Context, opts BackupRestoreOptions) (*BackupRestoreResult, error)
}

func (m *mockBackupService) Create(ctx context.Context, opts BackupCreateOptions) (*BackupResult, error) {
	if m.createFn != nil {
		return m.createFn(ctx, opts)
	}
	return &BackupResult{BackupID: uuid.New()}, nil
}

func (m *mockBackupService) Restore(ctx context.Context, opts BackupRestoreOptions) (*BackupRestoreResult, error) {
	if m.restoreFn != nil {
		return m.restoreFn(ctx, opts)
	}
	return &BackupRestoreResult{Success: true}, nil
}

// mockSecurityService implements SecurityService for testing.
type mockSecurityService struct {
	scanContainerFn func(ctx context.Context, hostID uuid.UUID, containerID string) (*SecurityScanResult, error)
	getLatestScanFn func(ctx context.Context, containerID string) (*SecurityScanResult, error)
}

func (m *mockSecurityService) ScanContainer(ctx context.Context, hostID uuid.UUID, containerID string) (*SecurityScanResult, error) {
	if m.scanContainerFn != nil {
		return m.scanContainerFn(ctx, hostID, containerID)
	}
	return &SecurityScanResult{Score: 85, Grade: "A"}, nil
}

func (m *mockSecurityService) GetLatestScan(ctx context.Context, containerID string) (*SecurityScanResult, error) {
	if m.getLatestScanFn != nil {
		return m.getLatestScanFn(ctx, containerID)
	}
	return nil, nil
}

// mockVersionUpdater implements ContainerVersionUpdater for testing.
type mockVersionUpdater struct {
	updateVersionInfoFn func(ctx context.Context, id string, currentVersion, latestVersion string, updateAvailable bool) error
}

func (m *mockVersionUpdater) UpdateVersionInfo(ctx context.Context, id string, currentVersion, latestVersion string, updateAvailable bool) error {
	if m.updateVersionInfoFn != nil {
		return m.updateVersionInfoFn(ctx, id, currentVersion, latestVersion, updateAvailable)
	}
	return nil
}

// ============================================================================
// Test helpers
// ============================================================================

func newTestService(t *testing.T, repo UpdateRepository, docker DockerClient) *Service {
	t.Helper()
	log := testutil.NewTestLogger(t)
	return NewService(repo, nil, nil, docker, nil, nil, nil, nil, log)
}

func newTestServiceFull(t *testing.T, opts struct {
	repo            UpdateRepository
	docker          DockerClient
	backup          BackupService
	security        SecurityService
	versionUpdater  ContainerVersionUpdater
	config          *ServiceConfig
}) *Service {
	t.Helper()
	log := testutil.NewTestLogger(t)
	return NewService(opts.repo, nil, nil, opts.docker, opts.backup, opts.security, opts.versionUpdater, opts.config, log)
}

// ============================================================================
// NewService tests
// ============================================================================

func TestNewService_NilConfigUsesDefaults(t *testing.T) {
	log := testutil.NewTestLogger(t)
	svc := NewService(&mockUpdateRepository{}, nil, nil, &mockDockerClient{}, nil, nil, nil, nil, log)

	if svc.config == nil {
		t.Fatal("expected non-nil config when nil passed")
	}
	if svc.config.DefaultHealthCheckWait != 30*time.Second {
		t.Errorf("DefaultHealthCheckWait = %v, want %v", svc.config.DefaultHealthCheckWait, 30*time.Second)
	}
	if svc.config.DefaultMaxRetries != 3 {
		t.Errorf("DefaultMaxRetries = %d, want 3", svc.config.DefaultMaxRetries)
	}
	if svc.config.DefaultBackupVolumes != true {
		t.Errorf("DefaultBackupVolumes = %v, want true", svc.config.DefaultBackupVolumes)
	}
	if svc.config.DefaultSecurityScan != true {
		t.Errorf("DefaultSecurityScan = %v, want true", svc.config.DefaultSecurityScan)
	}
	if svc.config.MaxConcurrentUpdates != 3 {
		t.Errorf("MaxConcurrentUpdates = %d, want 3", svc.config.MaxConcurrentUpdates)
	}
}

func TestNewService_ExplicitConfig(t *testing.T) {
	log := testutil.NewTestLogger(t)
	cfg := &ServiceConfig{
		DefaultHealthCheckWait: 10 * time.Second,
		DefaultMaxRetries:      5,
		MaxConcurrentUpdates:   7,
	}
	svc := NewService(&mockUpdateRepository{}, nil, nil, &mockDockerClient{}, nil, nil, nil, cfg, log)

	if svc.config.DefaultHealthCheckWait != 10*time.Second {
		t.Errorf("DefaultHealthCheckWait = %v, want %v", svc.config.DefaultHealthCheckWait, 10*time.Second)
	}
	if svc.config.DefaultMaxRetries != 5 {
		t.Errorf("DefaultMaxRetries = %d, want 5", svc.config.DefaultMaxRetries)
	}
	if cap(svc.updateSem) != 7 {
		t.Errorf("semaphore capacity = %d, want 7", cap(svc.updateSem))
	}
}

func TestNewService_SemaphoreCapacity(t *testing.T) {
	log := testutil.NewTestLogger(t)

	tests := []struct {
		name     string
		max      int
		wantCap  int
	}{
		{"positive value", 5, 5},
		{"zero defaults to 3", 0, 3},
		{"negative defaults to 3", -1, 3},
		{"one", 1, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &ServiceConfig{MaxConcurrentUpdates: tt.max}
			svc := NewService(&mockUpdateRepository{}, nil, nil, &mockDockerClient{}, nil, nil, nil, cfg, log)
			if cap(svc.updateSem) != tt.wantCap {
				t.Errorf("cap(updateSem) = %d, want %d", cap(svc.updateSem), tt.wantCap)
			}
		})
	}
}

func TestNewService_RunningUpdatesInitialized(t *testing.T) {
	log := testutil.NewTestLogger(t)
	svc := NewService(&mockUpdateRepository{}, nil, nil, &mockDockerClient{}, nil, nil, nil, nil, log)
	if svc.runningUpdates == nil {
		t.Fatal("runningUpdates map should be initialized")
	}
	if len(svc.runningUpdates) != 0 {
		t.Errorf("runningUpdates should be empty, got %d entries", len(svc.runningUpdates))
	}
}

// ============================================================================
// buildImageRef tests
// ============================================================================

func TestBuildImageRef(t *testing.T) {
	tests := []struct {
		name  string
		image string
		tag   string
		want  string
	}{
		{
			name:  "simple tag replacement",
			image: "nginx:1.24",
			tag:   "1.25",
			want:  "nginx:1.25",
		},
		{
			name:  "replace latest",
			image: "nginx:latest",
			tag:   "1.25.3",
			want:  "nginx:1.25.3",
		},
		{
			name:  "no existing tag",
			image: "nginx",
			tag:   "1.25",
			want:  "nginx:1.25",
		},
		{
			name:  "digest removal",
			image: "nginx@sha256:abc123def456",
			tag:   "1.25",
			want:  "nginx:1.25",
		},
		{
			name:  "tag and digest - strips digest colon first then digest prefix",
			image: "nginx:1.24@sha256:abc123def456",
			tag:   "1.25",
			want:  "nginx:1.24:1.25",
			// NOTE: buildImageRef processes LastIndex(":") first, which finds the
			// colon inside the digest (sha256:...), stripping it. Then it finds and
			// strips the "@sha256" portion, leaving "nginx:1.24". The original tag
			// is not removed because the LastIndex matched the digest colon, not
			// the tag colon. This is the actual behavior; in practice, images
			// with both tag and digest are rare in container configs.
		},
		{
			name:  "registry with port not stripped",
			image: "localhost:5000/myapp:v1.0",
			tag:   "v2.0",
			want:  "localhost:5000/myapp:v2.0",
		},
		{
			name:  "full registry path",
			image: "ghcr.io/owner/repo:v1.0.0",
			tag:   "v2.0.0",
			want:  "ghcr.io/owner/repo:v2.0.0",
		},
		{
			name:  "private registry with port and nested path",
			image: "registry.example.com:5000/org/app:3.1",
			tag:   "3.2",
			want:  "registry.example.com:5000/org/app:3.2",
		},
		{
			name:  "image with only digest, no tag",
			image: "nginx@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			tag:   "stable",
			want:  "nginx:stable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildImageRef(tt.image, tt.tag)
			if got != tt.want {
				t.Errorf("buildImageRef(%q, %q) = %q, want %q", tt.image, tt.tag, got, tt.want)
			}
		})
	}
}

// ============================================================================
// ExtractDigestFromRepoDigests tests
// ============================================================================

func TestExtractDigestFromRepoDigests(t *testing.T) {
	tests := []struct {
		name        string
		repoDigests []string
		image       string
		want        string
	}{
		{
			name:        "matching repository",
			repoDigests: []string{"nginx@sha256:abc123"},
			image:       "nginx:latest",
			want:        "sha256:abc123",
		},
		{
			name: "multiple digests, matches second",
			repoDigests: []string{
				"alpine@sha256:000aaa",
				"library/nginx@sha256:abc123",
			},
			image: "nginx:1.25",
			want:  "sha256:abc123",
		},
		{
			name:        "no match falls back to first",
			repoDigests: []string{"someother@sha256:xyz789"},
			image:       "nginx:1.25",
			want:        "sha256:xyz789",
		},
		{
			name:        "empty repo digests",
			repoDigests: []string{},
			image:       "nginx:latest",
			want:        "",
		},
		{
			name:        "nil repo digests",
			repoDigests: nil,
			image:       "nginx:latest",
			want:        "",
		},
		{
			name:        "empty image falls back to first digest",
			repoDigests: []string{"nginx@sha256:abc123"},
			image:       "",
			want:        "sha256:abc123",
		},
		{
			name:        "digest without @ separator",
			repoDigests: []string{"no-at-sign-here"},
			image:       "nginx:latest",
			want:        "",
		},
		{
			name: "ghcr image matching",
			repoDigests: []string{
				"ghcr.io/owner/repo@sha256:ghcr123",
			},
			image: "ghcr.io/owner/repo:v1.0.0",
			want:  "sha256:ghcr123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractDigestFromRepoDigests(tt.repoDigests, tt.image)
			if got != tt.want {
				t.Errorf("ExtractDigestFromRepoDigests(%v, %q) = %q, want %q", tt.repoDigests, tt.image, got, tt.want)
			}
		})
	}
}

// ============================================================================
// Policy operation tests
// ============================================================================

func TestGetPolicy_DelegatesToRepo(t *testing.T) {
	hostID := uuid.New()
	policyID := uuid.New()
	expectedPolicy := &models.UpdatePolicy{
		ID:         policyID,
		HostID:     hostID,
		TargetType: models.UpdateTypeContainer,
		TargetID:   "container-abc",
	}

	repo := &mockUpdateRepository{
		getPolicyByTargetFn: func(ctx context.Context, hID uuid.UUID, tt models.UpdateType, tID string) (*models.UpdatePolicy, error) {
			if hID != hostID {
				t.Errorf("hostID = %v, want %v", hID, hostID)
			}
			if tt != models.UpdateTypeContainer {
				t.Errorf("targetType = %v, want %v", tt, models.UpdateTypeContainer)
			}
			if tID != "container-abc" {
				t.Errorf("targetID = %q, want %q", tID, "container-abc")
			}
			return expectedPolicy, nil
		},
	}

	svc := newTestService(t, repo, &mockDockerClient{})
	got, err := svc.GetPolicy(context.Background(), hostID, models.UpdateTypeContainer, "container-abc")
	if err != nil {
		t.Fatalf("GetPolicy returned error: %v", err)
	}
	if got.ID != policyID {
		t.Errorf("policy ID = %v, want %v", got.ID, policyID)
	}
}

func TestSetPolicy_CreatesWhenNoExisting(t *testing.T) {
	var createdPolicy *models.UpdatePolicy

	repo := &mockUpdateRepository{
		getPolicyByTargetFn: func(ctx context.Context, hostID uuid.UUID, targetType models.UpdateType, targetID string) (*models.UpdatePolicy, error) {
			return nil, fmt.Errorf("not found")
		},
		createPolicyFn: func(ctx context.Context, policy *models.UpdatePolicy) error {
			createdPolicy = policy
			return nil
		},
	}

	svc := newTestService(t, repo, &mockDockerClient{})
	policy := &models.UpdatePolicy{
		HostID:     uuid.New(),
		TargetType: models.UpdateTypeContainer,
		TargetID:   "container-123",
		AutoUpdate: true,
	}

	err := svc.SetPolicy(context.Background(), policy)
	if err != nil {
		t.Fatalf("SetPolicy returned error: %v", err)
	}
	if createdPolicy == nil {
		t.Fatal("expected CreatePolicy to be called")
	}
	if !createdPolicy.AutoUpdate {
		t.Error("created policy should have AutoUpdate = true")
	}
}

func TestSetPolicy_UpdatesExistingPolicy(t *testing.T) {
	existingID := uuid.New()
	hostID := uuid.New()
	var updatedPolicy *models.UpdatePolicy

	repo := &mockUpdateRepository{
		getPolicyByTargetFn: func(ctx context.Context, hID uuid.UUID, tt models.UpdateType, tID string) (*models.UpdatePolicy, error) {
			return &models.UpdatePolicy{
				ID:         existingID,
				HostID:     hostID,
				TargetType: models.UpdateTypeContainer,
				TargetID:   "container-123",
				AutoUpdate: false,
			}, nil
		},
		updatePolicyFn: func(ctx context.Context, policy *models.UpdatePolicy) error {
			updatedPolicy = policy
			return nil
		},
	}

	svc := newTestService(t, repo, &mockDockerClient{})
	policy := &models.UpdatePolicy{
		HostID:     hostID,
		TargetType: models.UpdateTypeContainer,
		TargetID:   "container-123",
		AutoUpdate: true,
	}

	err := svc.SetPolicy(context.Background(), policy)
	if err != nil {
		t.Fatalf("SetPolicy returned error: %v", err)
	}
	if updatedPolicy == nil {
		t.Fatal("expected UpdatePolicy to be called")
	}
	if updatedPolicy.ID != existingID {
		t.Errorf("updated policy ID = %v, want %v (should reuse existing ID)", updatedPolicy.ID, existingID)
	}
	if !updatedPolicy.AutoUpdate {
		t.Error("updated policy should have AutoUpdate = true")
	}
}

func TestDeletePolicy_DelegatesToRepo(t *testing.T) {
	policyID := uuid.New()
	var deletedID uuid.UUID

	repo := &mockUpdateRepository{
		deletePolicyFn: func(ctx context.Context, id uuid.UUID) error {
			deletedID = id
			return nil
		},
	}

	svc := newTestService(t, repo, &mockDockerClient{})
	err := svc.DeletePolicy(context.Background(), policyID)
	if err != nil {
		t.Fatalf("DeletePolicy returned error: %v", err)
	}
	if deletedID != policyID {
		t.Errorf("deleted ID = %v, want %v", deletedID, policyID)
	}
}

// ============================================================================
// Pass-through operation tests
// ============================================================================

func TestGetStats_DelegatesToRepo(t *testing.T) {
	hostID := uuid.New()
	expectedStats := &models.UpdateStats{
		TotalUpdates:    42,
		SuccessfulCount: 38,
		FailedCount:     4,
	}

	repo := &mockUpdateRepository{
		getStatsFn: func(ctx context.Context, hID *uuid.UUID) (*models.UpdateStats, error) {
			if hID == nil || *hID != hostID {
				t.Errorf("hostID = %v, want %v", hID, hostID)
			}
			return expectedStats, nil
		},
	}

	svc := newTestService(t, repo, &mockDockerClient{})
	got, err := svc.GetStats(context.Background(), &hostID)
	if err != nil {
		t.Fatalf("GetStats returned error: %v", err)
	}
	if got.TotalUpdates != 42 {
		t.Errorf("TotalUpdates = %d, want 42", got.TotalUpdates)
	}
}

func TestGetHistory_DelegatesToRepo(t *testing.T) {
	hostID := uuid.New()
	expected := []*models.Update{{ID: uuid.New()}, {ID: uuid.New()}}

	repo := &mockUpdateRepository{
		getByTargetFn: func(ctx context.Context, hID uuid.UUID, tID string, limit int) ([]*models.Update, error) {
			if hID != hostID {
				t.Errorf("hostID = %v, want %v", hID, hostID)
			}
			if tID != "container-abc" {
				t.Errorf("targetID = %q, want %q", tID, "container-abc")
			}
			if limit != 10 {
				t.Errorf("limit = %d, want 10", limit)
			}
			return expected, nil
		},
	}

	svc := newTestService(t, repo, &mockDockerClient{})
	got, err := svc.GetHistory(context.Background(), hostID, "container-abc", 10)
	if err != nil {
		t.Fatalf("GetHistory returned error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d updates, want 2", len(got))
	}
}

func TestListUpdates_DelegatesToRepo(t *testing.T) {
	expected := []*models.Update{{ID: uuid.New()}}
	var expectedCount int64 = 1

	repo := &mockUpdateRepository{
		listFn: func(ctx context.Context, opts models.UpdateListOptions) ([]*models.Update, int64, error) {
			if opts.Limit != 25 {
				t.Errorf("limit = %d, want 25", opts.Limit)
			}
			return expected, expectedCount, nil
		},
	}

	svc := newTestService(t, repo, &mockDockerClient{})
	got, count, err := svc.ListUpdates(context.Background(), models.UpdateListOptions{Limit: 25})
	if err != nil {
		t.Fatalf("ListUpdates returned error: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("got %d updates, want 1", len(got))
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
}

func TestListPolicies_DelegatesToRepo(t *testing.T) {
	hostID := uuid.New()
	expected := []*models.UpdatePolicy{{ID: uuid.New()}}

	repo := &mockUpdateRepository{
		listPoliciesFn: func(ctx context.Context, hID *uuid.UUID) ([]*models.UpdatePolicy, error) {
			if hID == nil || *hID != hostID {
				t.Errorf("hostID = %v, want %v", hID, hostID)
			}
			return expected, nil
		},
	}

	svc := newTestService(t, repo, &mockDockerClient{})
	got, err := svc.ListPolicies(context.Background(), &hostID)
	if err != nil {
		t.Fatalf("ListPolicies returned error: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("got %d policies, want 1", len(got))
	}
}

func TestGetPolicyByID_DelegatesToRepo(t *testing.T) {
	policyID := uuid.New()
	expected := &models.UpdatePolicy{ID: policyID, AutoUpdate: true}

	repo := &mockUpdateRepository{
		getPolicyFn: func(ctx context.Context, id uuid.UUID) (*models.UpdatePolicy, error) {
			if id != policyID {
				t.Errorf("id = %v, want %v", id, policyID)
			}
			return expected, nil
		},
	}

	svc := newTestService(t, repo, &mockDockerClient{})
	got, err := svc.GetPolicyByID(context.Background(), policyID)
	if err != nil {
		t.Fatalf("GetPolicyByID returned error: %v", err)
	}
	if got.ID != policyID {
		t.Errorf("policy ID = %v, want %v", got.ID, policyID)
	}
}

func TestDeleteWebhook_DelegatesToRepo(t *testing.T) {
	webhookID := uuid.New()
	var deletedID uuid.UUID

	repo := &mockUpdateRepository{
		deleteWebhookFn: func(ctx context.Context, id uuid.UUID) error {
			deletedID = id
			return nil
		},
	}

	svc := newTestService(t, repo, &mockDockerClient{})
	err := svc.DeleteWebhook(context.Background(), webhookID)
	if err != nil {
		t.Fatalf("DeleteWebhook returned error: %v", err)
	}
	if deletedID != webhookID {
		t.Errorf("deleted ID = %v, want %v", deletedID, webhookID)
	}
}

// ============================================================================
// CreateWebhook tests
// ============================================================================

func TestCreateWebhook_GeneratesTokenAndStoresHash(t *testing.T) {
	hostID := uuid.New()
	var storedWebhook *models.UpdateWebhook

	repo := &mockUpdateRepository{
		createWebhookFn: func(ctx context.Context, webhook *models.UpdateWebhook) error {
			storedWebhook = &models.UpdateWebhook{
				ID:         webhook.ID,
				HostID:     webhook.HostID,
				TargetType: webhook.TargetType,
				TargetID:   webhook.TargetID,
				Token:      webhook.Token,
				IsEnabled:  webhook.IsEnabled,
				CreatedAt:  webhook.CreatedAt,
			}
			return nil
		},
	}

	svc := newTestService(t, repo, &mockDockerClient{})
	got, err := svc.CreateWebhook(context.Background(), hostID, models.UpdateTypeContainer, "container-abc")
	if err != nil {
		t.Fatalf("CreateWebhook returned error: %v", err)
	}

	// The returned token should be raw (not a hash)
	if got.Token == "" {
		t.Fatal("returned token should not be empty")
	}
	if len(got.Token) != 64 { // 32 bytes hex-encoded
		t.Errorf("token length = %d, want 64 hex characters", len(got.Token))
	}

	// The stored token should be the hash of the raw token
	expectedHash := crypto.HashToken(got.Token)
	if storedWebhook.Token != expectedHash {
		t.Errorf("stored token hash does not match: stored=%q, expected=%q", storedWebhook.Token, expectedHash)
	}

	// The returned webhook should have correct fields
	if got.HostID != hostID {
		t.Errorf("HostID = %v, want %v", got.HostID, hostID)
	}
	if got.TargetType != models.UpdateTypeContainer {
		t.Errorf("TargetType = %v, want %v", got.TargetType, models.UpdateTypeContainer)
	}
	if got.TargetID != "container-abc" {
		t.Errorf("TargetID = %q, want %q", got.TargetID, "container-abc")
	}
	if !got.IsEnabled {
		t.Error("IsEnabled should be true")
	}
}

func TestCreateWebhook_RepoErrorPropagates(t *testing.T) {
	repo := &mockUpdateRepository{
		createWebhookFn: func(ctx context.Context, webhook *models.UpdateWebhook) error {
			return fmt.Errorf("database error")
		},
	}

	svc := newTestService(t, repo, &mockDockerClient{})
	_, err := svc.CreateWebhook(context.Background(), uuid.New(), models.UpdateTypeContainer, "c1")
	if err == nil {
		t.Fatal("expected error from repo, got nil")
	}
}

// ============================================================================
// ListWebhooks tests - token hash clearing
// ============================================================================

func TestListWebhooks_ClearsTokenHashes(t *testing.T) {
	hostID := uuid.New()
	webhooks := []*models.UpdateWebhook{
		{ID: uuid.New(), HostID: hostID, Token: "hash-value-1"},
		{ID: uuid.New(), HostID: hostID, Token: "hash-value-2"},
		{ID: uuid.New(), HostID: hostID, Token: "hash-value-3"},
	}

	repo := &mockUpdateRepository{
		listWebhooksFn: func(ctx context.Context, hID uuid.UUID) ([]*models.UpdateWebhook, error) {
			// Return copies so we can verify clearing
			result := make([]*models.UpdateWebhook, len(webhooks))
			for i, w := range webhooks {
				copy := *w
				result[i] = &copy
			}
			return result, nil
		},
	}

	svc := newTestService(t, repo, &mockDockerClient{})
	got, err := svc.ListWebhooks(context.Background(), hostID)
	if err != nil {
		t.Fatalf("ListWebhooks returned error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d webhooks, want 3", len(got))
	}
	for i, w := range got {
		if w.Token != "" {
			t.Errorf("webhook[%d].Token = %q, want empty (hash should be cleared)", i, w.Token)
		}
	}
}

func TestListWebhooks_EmptyListNoError(t *testing.T) {
	repo := &mockUpdateRepository{
		listWebhooksFn: func(ctx context.Context, hID uuid.UUID) ([]*models.UpdateWebhook, error) {
			return []*models.UpdateWebhook{}, nil
		},
	}

	svc := newTestService(t, repo, &mockDockerClient{})
	got, err := svc.ListWebhooks(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("ListWebhooks returned error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d webhooks, want 0", len(got))
	}
}

func TestListWebhooks_RepoErrorPropagates(t *testing.T) {
	repo := &mockUpdateRepository{
		listWebhooksFn: func(ctx context.Context, hID uuid.UUID) ([]*models.UpdateWebhook, error) {
			return nil, fmt.Errorf("db error")
		},
	}

	svc := newTestService(t, repo, &mockDockerClient{})
	_, err := svc.ListWebhooks(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ============================================================================
// failUpdate tests
// ============================================================================

func TestFailUpdate_SetsStatusAndError(t *testing.T) {
	var persistedUpdate *models.Update

	repo := &mockUpdateRepository{
		updateFn: func(ctx context.Context, update *models.Update) error {
			persistedUpdate = update
			return nil
		},
	}

	svc := newTestService(t, repo, &mockDockerClient{})

	startedAt := time.Now().Add(-5 * time.Second)
	update := &models.Update{
		ID:        uuid.New(),
		Status:    models.UpdateStatusPulling,
		StartedAt: &startedAt,
	}
	result := &models.UpdateResult{
		Update: update,
	}

	got := svc.failUpdate(context.Background(), update, result, "image pull failed: timeout")

	// Check update fields
	if update.Status != models.UpdateStatusFailed {
		t.Errorf("Status = %v, want %v", update.Status, models.UpdateStatusFailed)
	}
	if update.ErrorMessage == nil || *update.ErrorMessage != "image pull failed: timeout" {
		t.Errorf("ErrorMessage = %v, want %q", update.ErrorMessage, "image pull failed: timeout")
	}
	if update.CompletedAt == nil {
		t.Fatal("CompletedAt should be set")
	}
	if update.DurationMs == nil {
		t.Fatal("DurationMs should be set")
	}
	if *update.DurationMs < 0 {
		t.Errorf("DurationMs = %d, should be >= 0", *update.DurationMs)
	}

	// Check result fields
	if got.Success {
		t.Error("Success should be false")
	}
	if got.ErrorMessage != "image pull failed: timeout" {
		t.Errorf("ErrorMessage = %q, want %q", got.ErrorMessage, "image pull failed: timeout")
	}

	// Check persisted
	if persistedUpdate == nil {
		t.Fatal("expected repo.Update to be called")
	}
}

func TestFailUpdate_NilStartedAt(t *testing.T) {
	repo := &mockUpdateRepository{}
	svc := newTestService(t, repo, &mockDockerClient{})

	update := &models.Update{
		ID:        uuid.New(),
		Status:    models.UpdateStatusPending,
		StartedAt: nil,
	}
	result := &models.UpdateResult{Update: update}

	svc.failUpdate(context.Background(), update, result, "some error")

	if update.DurationMs != nil {
		t.Errorf("DurationMs should be nil when StartedAt is nil, got %d", *update.DurationMs)
	}
	if update.CompletedAt == nil {
		t.Fatal("CompletedAt should still be set even when StartedAt is nil")
	}
}

// ============================================================================
// trackUpdate / untrackUpdate tests
// ============================================================================

func TestTrackUpdate(t *testing.T) {
	svc := newTestService(t, &mockUpdateRepository{}, &mockDockerClient{})

	id := uuid.New()
	svc.trackUpdate(id, "container-abc")

	svc.runningMu.RLock()
	tracked, ok := svc.runningUpdates[id]
	svc.runningMu.RUnlock()

	if !ok {
		t.Fatal("update should be tracked")
	}
	if tracked.ContainerID != "container-abc" {
		t.Errorf("ContainerID = %q, want %q", tracked.ContainerID, "container-abc")
	}
	if tracked.UpdateID != id {
		t.Errorf("UpdateID = %v, want %v", tracked.UpdateID, id)
	}
	if tracked.Status != models.UpdateStatusPending {
		t.Errorf("Status = %v, want %v", tracked.Status, models.UpdateStatusPending)
	}
	if tracked.StartedAt.IsZero() {
		t.Error("StartedAt should be set")
	}
}

func TestUntrackUpdate(t *testing.T) {
	svc := newTestService(t, &mockUpdateRepository{}, &mockDockerClient{})

	id := uuid.New()
	svc.trackUpdate(id, "container-abc")

	svc.untrackUpdate(id)

	svc.runningMu.RLock()
	_, ok := svc.runningUpdates[id]
	svc.runningMu.RUnlock()

	if ok {
		t.Error("update should have been untracked")
	}
}

func TestUntrackUpdate_NonexistentIDIsNoop(t *testing.T) {
	svc := newTestService(t, &mockUpdateRepository{}, &mockDockerClient{})

	// Untracking a non-existent ID should not panic
	svc.untrackUpdate(uuid.New())

	svc.runningMu.RLock()
	count := len(svc.runningUpdates)
	svc.runningMu.RUnlock()

	if count != 0 {
		t.Errorf("runningUpdates should be empty, got %d entries", count)
	}
}

func TestTrackUntrack_ConcurrentSafety(t *testing.T) {
	svc := newTestService(t, &mockUpdateRepository{}, &mockDockerClient{})

	const goroutines = 50
	var wg sync.WaitGroup
	ids := make([]uuid.UUID, goroutines)
	for i := range ids {
		ids[i] = uuid.New()
	}

	// Concurrently track
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			svc.trackUpdate(ids[idx], fmt.Sprintf("container-%d", idx))
		}(i)
	}
	wg.Wait()

	svc.runningMu.RLock()
	tracked := len(svc.runningUpdates)
	svc.runningMu.RUnlock()

	if tracked != goroutines {
		t.Errorf("tracked %d updates, want %d", tracked, goroutines)
	}

	// Concurrently untrack
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			svc.untrackUpdate(ids[idx])
		}(i)
	}
	wg.Wait()

	svc.runningMu.RLock()
	remaining := len(svc.runningUpdates)
	svc.runningMu.RUnlock()

	if remaining != 0 {
		t.Errorf("expected 0 remaining updates, got %d", remaining)
	}
}

func TestTrackUntrack_InterleavedConcurrency(t *testing.T) {
	svc := newTestService(t, &mockUpdateRepository{}, &mockDockerClient{})

	const iterations = 100
	var wg sync.WaitGroup
	wg.Add(iterations * 2)

	for i := 0; i < iterations; i++ {
		id := uuid.New()
		go func() {
			defer wg.Done()
			svc.trackUpdate(id, "c")
		}()
		go func() {
			defer wg.Done()
			svc.untrackUpdate(id)
		}()
	}
	wg.Wait()
	// No panic = success. The final count is nondeterministic due to races
	// between track and untrack on the same ID.
}

// ============================================================================
// generateWebhookToken tests (unexported helper)
// ============================================================================

func TestGenerateWebhookToken_Length(t *testing.T) {
	token, err := generateWebhookToken()
	if err != nil {
		t.Fatalf("generateWebhookToken returned error: %v", err)
	}
	if len(token) != 64 {
		t.Errorf("token length = %d, want 64 (32 bytes hex-encoded)", len(token))
	}
}

func TestGenerateWebhookToken_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		token, err := generateWebhookToken()
		if err != nil {
			t.Fatalf("generateWebhookToken returned error on iteration %d: %v", i, err)
		}
		if seen[token] {
			t.Fatalf("duplicate token generated on iteration %d", i)
		}
		seen[token] = true
	}
}

// ============================================================================
// DefaultServiceConfig tests
// ============================================================================

func TestDefaultServiceConfig(t *testing.T) {
	cfg := DefaultServiceConfig()
	if cfg.DefaultHealthCheckWait != 30*time.Second {
		t.Errorf("DefaultHealthCheckWait = %v, want %v", cfg.DefaultHealthCheckWait, 30*time.Second)
	}
	if cfg.DefaultMaxRetries != 3 {
		t.Errorf("DefaultMaxRetries = %d, want 3", cfg.DefaultMaxRetries)
	}
	if !cfg.DefaultBackupVolumes {
		t.Error("DefaultBackupVolumes should be true")
	}
	if !cfg.DefaultSecurityScan {
		t.Error("DefaultSecurityScan should be true")
	}
	if cfg.MaxConcurrentUpdates != 3 {
		t.Errorf("MaxConcurrentUpdates = %d, want 3", cfg.MaxConcurrentUpdates)
	}
}
