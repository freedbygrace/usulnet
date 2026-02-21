// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package backup

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// Mock Implementations
// ============================================================================

// mockStorage implements Storage for testing.
type mockStorage struct {
	typeName  string
	writeErr  error
	readErr   error
	deleteErr error
	existsVal bool
	existsErr error
	sizeVal   int64
	sizeErr   error
	listVal   []StorageEntry
	listErr   error
	statsVal  *StorageStats
	statsErr  error
	closeErr  error

	// Track calls
	writtenPaths  []string
	deletedPaths  []string
	readPaths     []string
	mu            sync.Mutex
	readData      io.ReadCloser
}

func (m *mockStorage) Type() string { return m.typeName }

func (m *mockStorage) Write(_ context.Context, path string, _ io.Reader, _ int64) error {
	m.mu.Lock()
	m.writtenPaths = append(m.writtenPaths, path)
	m.mu.Unlock()
	return m.writeErr
}

func (m *mockStorage) Read(_ context.Context, path string) (io.ReadCloser, error) {
	m.mu.Lock()
	m.readPaths = append(m.readPaths, path)
	m.mu.Unlock()
	if m.readErr != nil {
		return nil, m.readErr
	}
	if m.readData != nil {
		return m.readData, nil
	}
	return io.NopCloser(strings.NewReader("mock-data")), nil
}

func (m *mockStorage) Delete(_ context.Context, path string) error {
	m.mu.Lock()
	m.deletedPaths = append(m.deletedPaths, path)
	m.mu.Unlock()
	return m.deleteErr
}

func (m *mockStorage) Exists(_ context.Context, _ string) (bool, error) {
	return m.existsVal, m.existsErr
}

func (m *mockStorage) Size(_ context.Context, _ string) (int64, error) {
	return m.sizeVal, m.sizeErr
}

func (m *mockStorage) List(_ context.Context, _ string) ([]StorageEntry, error) {
	return m.listVal, m.listErr
}

func (m *mockStorage) Stats(_ context.Context) (*StorageStats, error) {
	return m.statsVal, m.statsErr
}

func (m *mockStorage) Close() error { return m.closeErr }

// mockRepository implements Repository for testing.
type mockRepository struct {
	// Data stores
	backups   map[uuid.UUID]*models.Backup
	schedules map[uuid.UUID]*models.BackupSchedule

	// Error injection
	createErr              error
	getErr                 error
	updateErr              error
	deleteErr              error
	listVal                []*models.Backup
	listTotal              int64
	listErr                error
	getByHostErr           error
	getStatsVal            *models.BackupStats
	getStatsErr            error
	createScheduleErr      error
	getScheduleErr         error
	listSchedulesVal       []*models.BackupSchedule
	listSchedulesErr       error
	updateScheduleErr      error
	deleteScheduleErr      error
	getDueSchedulesVal     []*models.BackupSchedule
	getDueSchedulesErr     error
	updateScheduleLastErr  error
	deleteExpiredVal       []uuid.UUID
	deleteExpiredErr       error

	// Call tracking
	mu             sync.Mutex
	createdBackups []*models.Backup
	updatedBackups []*models.Backup
	deletedIDs     []uuid.UUID
}

func newMockRepository() *mockRepository {
	return &mockRepository{
		backups:   make(map[uuid.UUID]*models.Backup),
		schedules: make(map[uuid.UUID]*models.BackupSchedule),
	}
}

func (m *mockRepository) Create(_ context.Context, backup *models.Backup) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.createErr != nil {
		return m.createErr
	}
	m.backups[backup.ID] = backup
	m.createdBackups = append(m.createdBackups, backup)
	return nil
}

func (m *mockRepository) Get(_ context.Context, id uuid.UUID) (*models.Backup, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getErr != nil {
		return nil, m.getErr
	}
	b, ok := m.backups[id]
	if !ok {
		return nil, fmt.Errorf("backup not found: %s", id)
	}
	return b, nil
}

func (m *mockRepository) Update(_ context.Context, backup *models.Backup) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updateErr != nil {
		return m.updateErr
	}
	m.backups[backup.ID] = backup
	m.updatedBackups = append(m.updatedBackups, backup)
	return nil
}

func (m *mockRepository) Delete(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.backups, id)
	m.deletedIDs = append(m.deletedIDs, id)
	return nil
}

func (m *mockRepository) List(_ context.Context, _ models.BackupListOptions) ([]*models.Backup, int64, error) {
	if m.listErr != nil {
		return nil, 0, m.listErr
	}
	return m.listVal, m.listTotal, nil
}

func (m *mockRepository) GetByHostAndTarget(_ context.Context, _ uuid.UUID, _ string) ([]*models.Backup, error) {
	if m.getByHostErr != nil {
		return nil, m.getByHostErr
	}
	// Return all backups from the map
	var result []*models.Backup
	m.mu.Lock()
	for _, b := range m.backups {
		result = append(result, b)
	}
	m.mu.Unlock()
	return result, nil
}

func (m *mockRepository) GetStats(_ context.Context, _ *uuid.UUID) (*models.BackupStats, error) {
	if m.getStatsErr != nil {
		return nil, m.getStatsErr
	}
	if m.getStatsVal != nil {
		return m.getStatsVal, nil
	}
	return &models.BackupStats{}, nil
}

func (m *mockRepository) CreateSchedule(_ context.Context, schedule *models.BackupSchedule) error {
	if m.createScheduleErr != nil {
		return m.createScheduleErr
	}
	m.mu.Lock()
	m.schedules[schedule.ID] = schedule
	m.mu.Unlock()
	return nil
}

func (m *mockRepository) GetSchedule(_ context.Context, id uuid.UUID) (*models.BackupSchedule, error) {
	if m.getScheduleErr != nil {
		return nil, m.getScheduleErr
	}
	m.mu.Lock()
	s, ok := m.schedules[id]
	m.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("schedule not found: %s", id)
	}
	return s, nil
}

func (m *mockRepository) ListSchedules(_ context.Context, _ *uuid.UUID) ([]*models.BackupSchedule, error) {
	if m.listSchedulesErr != nil {
		return nil, m.listSchedulesErr
	}
	if m.listSchedulesVal != nil {
		return m.listSchedulesVal, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []*models.BackupSchedule
	for _, s := range m.schedules {
		result = append(result, s)
	}
	return result, nil
}

func (m *mockRepository) UpdateSchedule(_ context.Context, schedule *models.BackupSchedule) error {
	if m.updateScheduleErr != nil {
		return m.updateScheduleErr
	}
	m.mu.Lock()
	m.schedules[schedule.ID] = schedule
	m.mu.Unlock()
	return nil
}

func (m *mockRepository) DeleteSchedule(_ context.Context, id uuid.UUID) error {
	if m.deleteScheduleErr != nil {
		return m.deleteScheduleErr
	}
	m.mu.Lock()
	delete(m.schedules, id)
	m.mu.Unlock()
	return nil
}

func (m *mockRepository) GetDueSchedules(_ context.Context) ([]*models.BackupSchedule, error) {
	if m.getDueSchedulesErr != nil {
		return nil, m.getDueSchedulesErr
	}
	return m.getDueSchedulesVal, nil
}

func (m *mockRepository) UpdateScheduleLastRun(_ context.Context, _ uuid.UUID, _ models.BackupStatus, _ *time.Time) error {
	return m.updateScheduleLastErr
}

func (m *mockRepository) DeleteExpired(_ context.Context) ([]uuid.UUID, error) {
	return m.deleteExpiredVal, m.deleteExpiredErr
}

// mockVolumeProvider implements VolumeProvider for testing.
type mockVolumeProvider struct {
	getVolumeVal      *VolumeInfo
	getVolumeErr      error
	mountpointVal     string
	mountpointErr     error
	volumeExistsVal   bool
	volumeExistsErr   error
	createVolumeVal   *VolumeInfo
	createVolumeErr   error
	listVolumesVal    []*VolumeInfo
	listVolumesErr    error
	copyVolumeDataErr error
}

func (m *mockVolumeProvider) GetVolume(_ context.Context, _ uuid.UUID, _ string) (*VolumeInfo, error) {
	return m.getVolumeVal, m.getVolumeErr
}

func (m *mockVolumeProvider) GetVolumeMountpoint(_ context.Context, _ uuid.UUID, _ string) (string, error) {
	return m.mountpointVal, m.mountpointErr
}

func (m *mockVolumeProvider) VolumeExists(_ context.Context, _ uuid.UUID, _ string) (bool, error) {
	return m.volumeExistsVal, m.volumeExistsErr
}

func (m *mockVolumeProvider) CreateVolume(_ context.Context, _ uuid.UUID, _ CreateVolumeOptions) (*VolumeInfo, error) {
	return m.createVolumeVal, m.createVolumeErr
}

func (m *mockVolumeProvider) ListVolumes(_ context.Context, _ uuid.UUID) ([]*VolumeInfo, error) {
	return m.listVolumesVal, m.listVolumesErr
}

func (m *mockVolumeProvider) CopyVolumeData(_ context.Context, _ uuid.UUID, _ string, _ string) error {
	return m.copyVolumeDataErr
}

// mockContainerProvider implements ContainerProvider for testing.
type mockContainerProvider struct {
	getContainerVal       *ContainerInfo
	getContainerErr       error
	getContainerByNameVal *ContainerInfo
	getContainerByNameErr error
	stopContainerErr      error
	startContainerErr     error
	isRunningVal          bool
	isRunningErr          error
	listContainersVal     []*ContainerInfo
	listContainersErr     error
}

func (m *mockContainerProvider) GetContainer(_ context.Context, _ uuid.UUID, _ string) (*ContainerInfo, error) {
	return m.getContainerVal, m.getContainerErr
}

func (m *mockContainerProvider) GetContainerByName(_ context.Context, _ uuid.UUID, _ string) (*ContainerInfo, error) {
	return m.getContainerByNameVal, m.getContainerByNameErr
}

func (m *mockContainerProvider) StopContainer(_ context.Context, _ uuid.UUID, _ string, _ *int) error {
	return m.stopContainerErr
}

func (m *mockContainerProvider) StartContainer(_ context.Context, _ uuid.UUID, _ string) error {
	return m.startContainerErr
}

func (m *mockContainerProvider) IsContainerRunning(_ context.Context, _ uuid.UUID, _ string) (bool, error) {
	return m.isRunningVal, m.isRunningErr
}

func (m *mockContainerProvider) ListContainersUsingVolume(_ context.Context, _ uuid.UUID, _ string) ([]*ContainerInfo, error) {
	return m.listContainersVal, m.listContainersErr
}

// mockStackProvider implements StackProvider for testing.
type mockStackProvider struct {
	getStackVal           *StackInfo
	getStackErr           error
	getStackContainersVal []StackContainerInfo
	getStackContainersErr error
	deployStackVal        uuid.UUID
	deployStackErr        error
	stopStackErr          error
}

func (m *mockStackProvider) GetStack(_ context.Context, _ uuid.UUID) (*StackInfo, error) {
	return m.getStackVal, m.getStackErr
}

func (m *mockStackProvider) GetStackContainers(_ context.Context, _ uuid.UUID) ([]StackContainerInfo, error) {
	return m.getStackContainersVal, m.getStackContainersErr
}

func (m *mockStackProvider) DeployStack(_ context.Context, _ uuid.UUID, _ string, _ string, _ *string) (uuid.UUID, error) {
	return m.deployStackVal, m.deployStackErr
}

func (m *mockStackProvider) StopStack(_ context.Context, _ uuid.UUID) error {
	return m.stopStackErr
}

// mockLimitProvider implements license.LimitProvider for testing.
type mockLimitProvider struct {
	limits license.Limits
}

func (m *mockLimitProvider) GetLimits() license.Limits {
	return m.limits
}

// Verify compile-time interface satisfaction.
var (
	_ Storage           = (*mockStorage)(nil)
	_ Repository        = (*mockRepository)(nil)
	_ VolumeProvider    = (*mockVolumeProvider)(nil)
	_ ContainerProvider = (*mockContainerProvider)(nil)
	_ StackProvider     = (*mockStackProvider)(nil)
	_ license.LimitProvider = (*mockLimitProvider)(nil)
)

// ============================================================================
// Test Helpers
// ============================================================================

func testConfig() Config {
	return Config{
		StoragePath:          "/tmp/test-backups",
		StorageType:          "local",
		DefaultCompression:   models.BackupCompressionGzip,
		CompressionLevel:     6,
		DefaultRetentionDays: 30,
		MaxBackupsPerTarget:  10,
		CleanupInterval:      0, // disable background workers in tests
		MaxConcurrentBackups: 3,
		VerifyAfterBackup:    false,
	}
}

func testService(t *testing.T) (*Service, *mockStorage, *mockRepository) {
	t.Helper()
	storage := &mockStorage{typeName: "local"}
	repo := newMockRepository()
	vol := &mockVolumeProvider{}
	ctr := &mockContainerProvider{}
	cfg := testConfig()

	svc, err := NewService(storage, repo, vol, ctr, cfg, logger.Nop())
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return svc, storage, repo
}

// ============================================================================
// DefaultConfig Tests
// ============================================================================

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.StoragePath != "/data/backups" {
		t.Errorf("StoragePath = %q, want %q", cfg.StoragePath, "/data/backups")
	}
	if cfg.StorageType != "local" {
		t.Errorf("StorageType = %q, want %q", cfg.StorageType, "local")
	}
	if cfg.DefaultCompression != models.BackupCompressionGzip {
		t.Errorf("DefaultCompression = %q, want %q", cfg.DefaultCompression, models.BackupCompressionGzip)
	}
	if cfg.CompressionLevel != 6 {
		t.Errorf("CompressionLevel = %d, want 6", cfg.CompressionLevel)
	}
	if cfg.DefaultRetentionDays != 30 {
		t.Errorf("DefaultRetentionDays = %d, want 30", cfg.DefaultRetentionDays)
	}
	if cfg.MaxBackupsPerTarget != 10 {
		t.Errorf("MaxBackupsPerTarget = %d, want 10", cfg.MaxBackupsPerTarget)
	}
	if cfg.CleanupInterval != 24*time.Hour {
		t.Errorf("CleanupInterval = %v, want 24h", cfg.CleanupInterval)
	}
	if cfg.MaxConcurrentBackups != 3 {
		t.Errorf("MaxConcurrentBackups = %d, want 3", cfg.MaxConcurrentBackups)
	}
	if !cfg.VerifyAfterBackup {
		t.Error("VerifyAfterBackup should be true")
	}
}

// ============================================================================
// DefaultRetentionPolicy Tests
// ============================================================================

func TestDefaultRetentionPolicy(t *testing.T) {
	policy := DefaultRetentionPolicy()

	if policy.MaxBackups != 50 {
		t.Errorf("MaxBackups = %d, want 50", policy.MaxBackups)
	}
	if policy.MaxAgeDays != 90 {
		t.Errorf("MaxAgeDays = %d, want 90", policy.MaxAgeDays)
	}
	if policy.MinBackups != 3 {
		t.Errorf("MinBackups = %d, want 3", policy.MinBackups)
	}
	if policy.KeepDaily != 7 {
		t.Errorf("KeepDaily = %d, want 7", policy.KeepDaily)
	}
	if policy.KeepWeekly != 4 {
		t.Errorf("KeepWeekly = %d, want 4", policy.KeepWeekly)
	}
	if policy.KeepMonthly != 6 {
		t.Errorf("KeepMonthly = %d, want 6", policy.KeepMonthly)
	}
}

// ============================================================================
// NewService Tests
// ============================================================================

func TestNewService_Basic(t *testing.T) {
	storage := &mockStorage{typeName: "local"}
	repo := newMockRepository()
	vol := &mockVolumeProvider{}
	ctr := &mockContainerProvider{}
	cfg := testConfig()

	svc, err := NewService(storage, repo, vol, ctr, cfg, logger.Nop())
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if svc == nil {
		t.Fatal("NewService() returned nil")
	}
	if svc.creator == nil {
		t.Error("creator should not be nil")
	}
	if svc.restorer == nil {
		t.Error("restorer should not be nil")
	}
	if svc.retention == nil {
		t.Error("retention should not be nil")
	}
}

func TestNewService_NilLogger(t *testing.T) {
	storage := &mockStorage{typeName: "local"}
	repo := newMockRepository()
	vol := &mockVolumeProvider{}
	ctr := &mockContainerProvider{}
	cfg := testConfig()

	svc, err := NewService(storage, repo, vol, ctr, cfg, nil)
	if err != nil {
		t.Fatalf("NewService(nil logger) error = %v", err)
	}
	if svc == nil {
		t.Fatal("NewService(nil logger) returned nil")
	}
}

func TestNewService_WithStackProvider(t *testing.T) {
	storage := &mockStorage{typeName: "local"}
	repo := newMockRepository()
	vol := &mockVolumeProvider{}
	ctr := &mockContainerProvider{}
	cfg := testConfig()
	sp := &mockStackProvider{}

	svc, err := NewService(storage, repo, vol, ctr, cfg, logger.Nop(), WithStackProviderOption(sp))
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if svc == nil {
		t.Fatal("NewService() returned nil")
	}
}

func TestNewService_ConcurrencyDefault(t *testing.T) {
	storage := &mockStorage{typeName: "local"}
	repo := newMockRepository()
	vol := &mockVolumeProvider{}
	ctr := &mockContainerProvider{}
	cfg := testConfig()
	cfg.MaxConcurrentBackups = 0 // should default to 3

	svc, err := NewService(storage, repo, vol, ctr, cfg, logger.Nop())
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	// Semaphore capacity should be 3 (default)
	if cap(svc.semaphore) != 3 {
		t.Errorf("semaphore capacity = %d, want 3", cap(svc.semaphore))
	}
}

func TestNewService_CustomConcurrency(t *testing.T) {
	storage := &mockStorage{typeName: "local"}
	repo := newMockRepository()
	vol := &mockVolumeProvider{}
	ctr := &mockContainerProvider{}
	cfg := testConfig()
	cfg.MaxConcurrentBackups = 5

	svc, err := NewService(storage, repo, vol, ctr, cfg, logger.Nop())
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if cap(svc.semaphore) != 5 {
		t.Errorf("semaphore capacity = %d, want 5", cap(svc.semaphore))
	}
}

// ============================================================================
// Service Lifecycle Tests
// ============================================================================

func TestService_StartAndStop(t *testing.T) {
	svc, _, _ := testService(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Stop should succeed without hanging
	if err := svc.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestService_StopIdempotent(t *testing.T) {
	svc, _, _ := testService(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc.Start(ctx)

	// Multiple stops should be safe
	if err := svc.Stop(); err != nil {
		t.Fatalf("first Stop() error = %v", err)
	}
	if err := svc.Stop(); err != nil {
		t.Fatalf("second Stop() error = %v", err)
	}
}

// ============================================================================
// CRUD Operations Tests
// ============================================================================

func TestService_Get(t *testing.T) {
	svc, _, repo := testService(t)
	ctx := context.Background()

	id := uuid.New()
	expected := &models.Backup{
		ID:       id,
		HostID:   uuid.New(),
		Type:     models.BackupTypeVolume,
		TargetID: "my-volume",
		Status:   models.BackupStatusCompleted,
	}
	repo.backups[id] = expected

	got, err := svc.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.ID != expected.ID {
		t.Errorf("Get().ID = %v, want %v", got.ID, expected.ID)
	}
	if got.TargetID != "my-volume" {
		t.Errorf("Get().TargetID = %q, want %q", got.TargetID, "my-volume")
	}
}

func TestService_Get_NotFound(t *testing.T) {
	svc, _, _ := testService(t)
	ctx := context.Background()

	_, err := svc.Get(ctx, uuid.New())
	if err == nil {
		t.Fatal("Get() expected error for missing backup")
	}
}

func TestService_List(t *testing.T) {
	svc, _, repo := testService(t)
	ctx := context.Background()

	repo.listVal = []*models.Backup{
		{ID: uuid.New(), TargetID: "vol-1"},
		{ID: uuid.New(), TargetID: "vol-2"},
	}
	repo.listTotal = 2

	backups, total, err := svc.List(ctx, models.BackupListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if total != 2 {
		t.Errorf("List() total = %d, want 2", total)
	}
	if len(backups) != 2 {
		t.Errorf("List() len = %d, want 2", len(backups))
	}
}

func TestService_List_Error(t *testing.T) {
	svc, _, repo := testService(t)
	ctx := context.Background()
	repo.listErr = fmt.Errorf("db error")

	_, _, err := svc.List(ctx, models.BackupListOptions{})
	if err == nil {
		t.Fatal("List() expected error")
	}
}

func TestService_ListByTarget(t *testing.T) {
	svc, _, repo := testService(t)
	ctx := context.Background()

	hostID := uuid.New()
	b := &models.Backup{ID: uuid.New(), HostID: hostID, TargetID: "my-vol"}
	repo.backups[b.ID] = b

	backups, err := svc.ListByTarget(ctx, hostID, "my-vol")
	if err != nil {
		t.Fatalf("ListByTarget() error = %v", err)
	}
	if len(backups) != 1 {
		t.Errorf("ListByTarget() len = %d, want 1", len(backups))
	}
}

func TestService_Delete(t *testing.T) {
	svc, storage, repo := testService(t)
	ctx := context.Background()

	id := uuid.New()
	repo.backups[id] = &models.Backup{
		ID:   id,
		Path: "host1/volume/backup.tar.gz",
	}

	if err := svc.Delete(ctx, id); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify storage delete was called
	storage.mu.Lock()
	if len(storage.deletedPaths) != 1 || storage.deletedPaths[0] != "host1/volume/backup.tar.gz" {
		t.Errorf("storage.Delete called with %v, want [host1/volume/backup.tar.gz]", storage.deletedPaths)
	}
	storage.mu.Unlock()

	// Verify repo delete was called
	repo.mu.Lock()
	if len(repo.deletedIDs) != 1 || repo.deletedIDs[0] != id {
		t.Errorf("repo.Delete called with %v, want [%s]", repo.deletedIDs, id)
	}
	repo.mu.Unlock()
}

func TestService_Delete_NotFound(t *testing.T) {
	svc, _, _ := testService(t)
	ctx := context.Background()

	err := svc.Delete(ctx, uuid.New())
	if err == nil {
		t.Fatal("Delete() expected error for missing backup")
	}
}

func TestService_Delete_StorageErrorNonFatal(t *testing.T) {
	svc, storage, repo := testService(t)
	ctx := context.Background()

	id := uuid.New()
	repo.backups[id] = &models.Backup{ID: id, Path: "some/path"}
	storage.deleteErr = fmt.Errorf("storage unavailable")

	// Delete should still succeed (storage error is logged, not fatal)
	// because repo.Delete is called regardless
	err := svc.Delete(ctx, id)
	if err != nil {
		t.Fatalf("Delete() error = %v, want nil (storage errors are non-fatal)", err)
	}
}

func TestService_GetStats(t *testing.T) {
	svc, _, repo := testService(t)
	ctx := context.Background()

	expected := &models.BackupStats{
		TotalBackups:     10,
		CompletedBackups: 8,
		FailedBackups:    2,
		TotalSize:        1024 * 1024,
	}
	repo.getStatsVal = expected

	stats, err := svc.GetStats(ctx, nil)
	if err != nil {
		t.Fatalf("GetStats() error = %v", err)
	}
	if stats.TotalBackups != 10 {
		t.Errorf("GetStats().TotalBackups = %d, want 10", stats.TotalBackups)
	}
	if stats.CompletedBackups != 8 {
		t.Errorf("GetStats().CompletedBackups = %d, want 8", stats.CompletedBackups)
	}
}

func TestService_GetStorageInfo(t *testing.T) {
	svc, storage, repo := testService(t)
	ctx := context.Background()

	storage.statsVal = &StorageStats{
		TotalSpace:     1000000,
		UsedSpace:      500000,
		AvailableSpace: 500000,
		FileCount:      42,
	}
	repo.getStatsVal = &models.BackupStats{TotalBackups: 42}

	info, err := svc.GetStorageInfo(ctx)
	if err != nil {
		t.Fatalf("GetStorageInfo() error = %v", err)
	}
	if info.Type != "local" {
		t.Errorf("Type = %q, want %q", info.Type, "local")
	}
	if info.TotalSize != 1000000 {
		t.Errorf("TotalSize = %d, want 1000000", info.TotalSize)
	}
	if info.UsedSize != 500000 {
		t.Errorf("UsedSize = %d, want 500000", info.UsedSize)
	}
	if info.BackupCount != 42 {
		t.Errorf("BackupCount = %d, want 42", info.BackupCount)
	}
}

// ============================================================================
// Download Tests
// ============================================================================

func TestService_Download(t *testing.T) {
	svc, _, repo := testService(t)
	ctx := context.Background()

	id := uuid.New()
	repo.backups[id] = &models.Backup{
		ID:        id,
		Path:      "host1/volume/backup.tar.gz",
		Filename:  "my-vol_volume_20260101-120000.tar.gz",
		SizeBytes: 4096,
	}

	info, err := svc.Download(ctx, id)
	if err != nil {
		t.Fatalf("Download() error = %v", err)
	}
	if info.Filename != "my-vol_volume_20260101-120000.tar.gz" {
		t.Errorf("Filename = %q", info.Filename)
	}
	if info.Size != 4096 {
		t.Errorf("Size = %d, want 4096", info.Size)
	}
	if info.ContentType != "application/octet-stream" {
		t.Errorf("ContentType = %q, want %q", info.ContentType, "application/octet-stream")
	}
	if info.Reader == nil {
		t.Error("Reader should not be nil")
	} else {
		info.Reader.Close()
	}
}

func TestService_Download_NotFound(t *testing.T) {
	svc, _, _ := testService(t)
	ctx := context.Background()

	_, err := svc.Download(ctx, uuid.New())
	if err == nil {
		t.Fatal("Download() expected error for missing backup")
	}
}

func TestService_Download_StorageError(t *testing.T) {
	svc, storage, repo := testService(t)
	ctx := context.Background()

	id := uuid.New()
	repo.backups[id] = &models.Backup{ID: id, Path: "some/path"}
	storage.readErr = fmt.Errorf("storage read failed")

	_, err := svc.Download(ctx, id)
	if err == nil {
		t.Fatal("Download() expected error when storage read fails")
	}
}

// ============================================================================
// Event Handler Tests
// ============================================================================

func TestService_OnEvent_Registration(t *testing.T) {
	svc, _, _ := testService(t)

	var called atomic.Int32
	svc.OnEvent(func(e Event) {
		called.Add(1)
	})

	svc.emitEvent(Event{Type: EventBackupStarted, Timestamp: time.Now()})

	// Give goroutine time to execute
	time.Sleep(50 * time.Millisecond)

	if called.Load() != 1 {
		t.Errorf("handler called %d times, want 1", called.Load())
	}
}

func TestService_OnEvent_MultipleHandlers(t *testing.T) {
	svc, _, _ := testService(t)

	var count1, count2 atomic.Int32

	svc.OnEvent(func(e Event) { count1.Add(1) })
	svc.OnEvent(func(e Event) { count2.Add(1) })

	svc.emitEvent(Event{Type: EventBackupCompleted, Timestamp: time.Now()})

	time.Sleep(50 * time.Millisecond)

	if count1.Load() != 1 {
		t.Errorf("handler1 called %d times, want 1", count1.Load())
	}
	if count2.Load() != 1 {
		t.Errorf("handler2 called %d times, want 1", count2.Load())
	}
}

func TestService_OnEvent_EventFields(t *testing.T) {
	svc, _, _ := testService(t)

	hostID := uuid.New()
	backupID := uuid.New()
	var received Event
	var wg sync.WaitGroup
	wg.Add(1)

	svc.OnEvent(func(e Event) {
		received = e
		wg.Done()
	})

	svc.emitEvent(Event{
		Type:     EventBackupCompleted,
		BackupID: &backupID,
		HostID:   hostID,
		TargetID: "my-volume",
		Status:   models.BackupStatusCompleted,
		Message:  "done",
	})

	wg.Wait()

	if received.Type != EventBackupCompleted {
		t.Errorf("Type = %q, want %q", received.Type, EventBackupCompleted)
	}
	if *received.BackupID != backupID {
		t.Errorf("BackupID = %v, want %v", *received.BackupID, backupID)
	}
	if received.HostID != hostID {
		t.Errorf("HostID = %v, want %v", received.HostID, hostID)
	}
	if received.TargetID != "my-volume" {
		t.Errorf("TargetID = %q, want %q", received.TargetID, "my-volume")
	}
}

func TestService_OnEvent_ConcurrentRegistration(t *testing.T) {
	svc, _, _ := testService(t)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			svc.OnEvent(func(e Event) {})
		}()
	}
	wg.Wait()

	svc.eventMu.RLock()
	count := len(svc.eventHandlers)
	svc.eventMu.RUnlock()

	if count != 10 {
		t.Errorf("handler count = %d, want 10", count)
	}
}

// ============================================================================
// SetLimitProvider Tests
// ============================================================================

func TestService_SetLimitProvider(t *testing.T) {
	svc, _, _ := testService(t)

	lp := &mockLimitProvider{limits: license.Limits{MaxBackupDestinations: 5}}
	svc.SetLimitProvider(lp)

	svc.limitMu.RLock()
	got := svc.limitProvider
	svc.limitMu.RUnlock()

	if got == nil {
		t.Fatal("limitProvider should not be nil after SetLimitProvider")
	}
	if got.GetLimits().MaxBackupDestinations != 5 {
		t.Errorf("MaxBackupDestinations = %d, want 5", got.GetLimits().MaxBackupDestinations)
	}
}

func TestService_SetLimitProvider_ThreadSafety(t *testing.T) {
	svc, _, _ := testService(t)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			svc.SetLimitProvider(&mockLimitProvider{
				limits: license.Limits{MaxBackupDestinations: n},
			})
		}(i)
		go func() {
			defer wg.Done()
			svc.limitMu.RLock()
			_ = svc.limitProvider
			svc.limitMu.RUnlock()
		}()
	}
	wg.Wait()

	// Test passes if no race condition detected (run with -race)
}

func TestService_SetLimitProvider_Nil(t *testing.T) {
	svc, _, _ := testService(t)
	svc.SetLimitProvider(&mockLimitProvider{})

	// Setting nil should work
	svc.SetLimitProvider(nil)

	svc.limitMu.RLock()
	got := svc.limitProvider
	svc.limitMu.RUnlock()

	if got != nil {
		t.Error("limitProvider should be nil after SetLimitProvider(nil)")
	}
}

// ============================================================================
// Schedule Operations Tests
// ============================================================================

func TestService_CreateSchedule(t *testing.T) {
	svc, _, _ := testService(t)
	ctx := context.Background()
	hostID := uuid.New()
	userID := uuid.New()

	input := models.CreateBackupScheduleInput{
		Type:     models.BackupTypeVolume,
		TargetID: "my-volume",
		Schedule: "0 2 * * *",
		IsEnabled: true,
	}

	schedule, err := svc.CreateSchedule(ctx, input, hostID, &userID)
	if err != nil {
		t.Fatalf("CreateSchedule() error = %v", err)
	}
	if schedule == nil {
		t.Fatal("CreateSchedule() returned nil")
	}
	if schedule.HostID != hostID {
		t.Errorf("HostID = %v, want %v", schedule.HostID, hostID)
	}
	if schedule.TargetID != "my-volume" {
		t.Errorf("TargetID = %q, want %q", schedule.TargetID, "my-volume")
	}
	if schedule.Schedule != "0 2 * * *" {
		t.Errorf("Schedule = %q, want %q", schedule.Schedule, "0 2 * * *")
	}
	if !schedule.IsEnabled {
		t.Error("IsEnabled should be true")
	}
	if schedule.NextRunAt == nil {
		t.Error("NextRunAt should be set")
	}
	if schedule.CreatedBy == nil || *schedule.CreatedBy != userID {
		t.Error("CreatedBy should be set to userID")
	}
}

func TestService_CreateSchedule_DefaultCompression(t *testing.T) {
	svc, _, _ := testService(t)
	ctx := context.Background()

	input := models.CreateBackupScheduleInput{
		Type:     models.BackupTypeVolume,
		TargetID: "vol",
		Schedule: "0 2 * * *",
	}

	schedule, err := svc.CreateSchedule(ctx, input, uuid.New(), nil)
	if err != nil {
		t.Fatalf("CreateSchedule() error = %v", err)
	}
	if schedule.Compression != models.BackupCompressionGzip {
		t.Errorf("Compression = %q, want default %q", schedule.Compression, models.BackupCompressionGzip)
	}
}

func TestService_CreateSchedule_DefaultRetention(t *testing.T) {
	svc, _, _ := testService(t)
	ctx := context.Background()

	input := models.CreateBackupScheduleInput{
		Type:     models.BackupTypeVolume,
		TargetID: "vol",
		Schedule: "0 2 * * *",
	}

	schedule, err := svc.CreateSchedule(ctx, input, uuid.New(), nil)
	if err != nil {
		t.Fatalf("CreateSchedule() error = %v", err)
	}
	if schedule.RetentionDays != 30 {
		t.Errorf("RetentionDays = %d, want 30 (config default)", schedule.RetentionDays)
	}
	if schedule.MaxBackups != 10 {
		t.Errorf("MaxBackups = %d, want 10 (hardcoded default)", schedule.MaxBackups)
	}
}

func TestService_CreateSchedule_LicenseLimitEnforced(t *testing.T) {
	svc, _, repo := testService(t)
	ctx := context.Background()

	// Set limit to 1
	svc.SetLimitProvider(&mockLimitProvider{
		limits: license.Limits{MaxBackupDestinations: 1},
	})

	// Pre-populate one schedule
	repo.listSchedulesVal = []*models.BackupSchedule{
		{ID: uuid.New(), TargetID: "existing"},
	}

	input := models.CreateBackupScheduleInput{
		Type:     models.BackupTypeVolume,
		TargetID: "new-vol",
		Schedule: "0 2 * * *",
	}

	_, err := svc.CreateSchedule(ctx, input, uuid.New(), nil)
	if err == nil {
		t.Fatal("CreateSchedule() expected license limit error")
	}
	if !strings.Contains(err.Error(), "limit reached") {
		t.Errorf("error = %q, should contain 'limit reached'", err.Error())
	}
}

func TestService_CreateSchedule_LicenseLimitZeroMeansUnlimited(t *testing.T) {
	svc, _, _ := testService(t)
	ctx := context.Background()

	// Limit 0 means unlimited
	svc.SetLimitProvider(&mockLimitProvider{
		limits: license.Limits{MaxBackupDestinations: 0},
	})

	input := models.CreateBackupScheduleInput{
		Type:     models.BackupTypeVolume,
		TargetID: "vol",
		Schedule: "0 2 * * *",
	}

	_, err := svc.CreateSchedule(ctx, input, uuid.New(), nil)
	if err != nil {
		t.Fatalf("CreateSchedule() error = %v, want nil (limit 0 = unlimited)", err)
	}
}

func TestService_CreateSchedule_RepoError(t *testing.T) {
	svc, _, repo := testService(t)
	ctx := context.Background()

	repo.createScheduleErr = fmt.Errorf("db error")

	input := models.CreateBackupScheduleInput{
		Type:     models.BackupTypeVolume,
		TargetID: "vol",
		Schedule: "0 2 * * *",
	}

	_, err := svc.CreateSchedule(ctx, input, uuid.New(), nil)
	if err == nil {
		t.Fatal("CreateSchedule() expected error from repo")
	}
}

func TestService_GetSchedule(t *testing.T) {
	svc, _, repo := testService(t)
	ctx := context.Background()

	id := uuid.New()
	repo.schedules[id] = &models.BackupSchedule{
		ID:       id,
		TargetID: "my-vol",
		Schedule: "0 3 * * *",
	}

	schedule, err := svc.GetSchedule(ctx, id)
	if err != nil {
		t.Fatalf("GetSchedule() error = %v", err)
	}
	if schedule.TargetID != "my-vol" {
		t.Errorf("TargetID = %q, want %q", schedule.TargetID, "my-vol")
	}
}

func TestService_ListSchedules(t *testing.T) {
	svc, _, repo := testService(t)
	ctx := context.Background()

	repo.listSchedulesVal = []*models.BackupSchedule{
		{ID: uuid.New()},
		{ID: uuid.New()},
	}

	schedules, err := svc.ListSchedules(ctx, nil)
	if err != nil {
		t.Fatalf("ListSchedules() error = %v", err)
	}
	if len(schedules) != 2 {
		t.Errorf("len = %d, want 2", len(schedules))
	}
}

func TestService_DeleteSchedule(t *testing.T) {
	svc, _, repo := testService(t)
	ctx := context.Background()

	id := uuid.New()
	repo.schedules[id] = &models.BackupSchedule{ID: id}

	if err := svc.DeleteSchedule(ctx, id); err != nil {
		t.Fatalf("DeleteSchedule() error = %v", err)
	}

	repo.mu.Lock()
	_, exists := repo.schedules[id]
	repo.mu.Unlock()
	if exists {
		t.Error("schedule should have been deleted from repo")
	}
}

func TestService_UpdateSchedule(t *testing.T) {
	svc, _, repo := testService(t)
	ctx := context.Background()

	id := uuid.New()
	repo.schedules[id] = &models.BackupSchedule{
		ID:            id,
		Schedule:      "0 2 * * *",
		Compression:   models.BackupCompressionGzip,
		RetentionDays: 30,
		MaxBackups:    10,
		IsEnabled:     true,
	}

	newSchedule := "0 4 * * *"
	newCompression := models.BackupCompressionZstd
	newRetention := 60
	newMaxBackups := 20
	newEnabled := false

	updated, err := svc.UpdateSchedule(ctx, id, models.UpdateBackupScheduleInput{
		Schedule:      &newSchedule,
		Compression:   &newCompression,
		RetentionDays: &newRetention,
		MaxBackups:    &newMaxBackups,
		IsEnabled:     &newEnabled,
	})
	if err != nil {
		t.Fatalf("UpdateSchedule() error = %v", err)
	}
	if updated.Schedule != "0 4 * * *" {
		t.Errorf("Schedule = %q, want %q", updated.Schedule, "0 4 * * *")
	}
	if updated.Compression != models.BackupCompressionZstd {
		t.Errorf("Compression = %q, want %q", updated.Compression, models.BackupCompressionZstd)
	}
	if updated.RetentionDays != 60 {
		t.Errorf("RetentionDays = %d, want 60", updated.RetentionDays)
	}
	if updated.MaxBackups != 20 {
		t.Errorf("MaxBackups = %d, want 20", updated.MaxBackups)
	}
	if updated.IsEnabled {
		t.Error("IsEnabled should be false")
	}
}

func TestService_UpdateSchedule_PartialUpdate(t *testing.T) {
	svc, _, repo := testService(t)
	ctx := context.Background()

	id := uuid.New()
	repo.schedules[id] = &models.BackupSchedule{
		ID:            id,
		Schedule:      "0 2 * * *",
		Compression:   models.BackupCompressionGzip,
		RetentionDays: 30,
		IsEnabled:     true,
	}

	// Only update enabled state
	newEnabled := false
	updated, err := svc.UpdateSchedule(ctx, id, models.UpdateBackupScheduleInput{
		IsEnabled: &newEnabled,
	})
	if err != nil {
		t.Fatalf("UpdateSchedule() error = %v", err)
	}
	// Non-updated fields should be preserved
	if updated.Schedule != "0 2 * * *" {
		t.Errorf("Schedule = %q, want %q (preserved)", updated.Schedule, "0 2 * * *")
	}
	if updated.Compression != models.BackupCompressionGzip {
		t.Errorf("Compression = %q, want %q (preserved)", updated.Compression, models.BackupCompressionGzip)
	}
	if updated.RetentionDays != 30 {
		t.Errorf("RetentionDays = %d, want 30 (preserved)", updated.RetentionDays)
	}
	if updated.IsEnabled {
		t.Error("IsEnabled should be false (updated)")
	}
}

func TestService_UpdateSchedule_NotFound(t *testing.T) {
	svc, _, _ := testService(t)
	ctx := context.Background()

	_, err := svc.UpdateSchedule(ctx, uuid.New(), models.UpdateBackupScheduleInput{})
	if err == nil {
		t.Fatal("UpdateSchedule() expected error for missing schedule")
	}
}

// ============================================================================
// RetentionManager Tests
// ============================================================================

func TestRetentionManager_Cleanup_NilPolicyUsesDefault(t *testing.T) {
	storage := &mockStorage{typeName: "local"}
	repo := newMockRepository()
	cfg := testConfig()
	rm := NewRetentionManager(storage, repo, cfg, logger.Nop())

	ctx := context.Background()
	repo.listVal = nil
	repo.listTotal = 0

	result, err := rm.Cleanup(ctx, nil)
	if err != nil {
		t.Fatalf("Cleanup(nil policy) error = %v", err)
	}
	if result == nil {
		t.Fatal("Cleanup() returned nil result")
	}
}

func TestRetentionManager_Cleanup_ExpiredBackups(t *testing.T) {
	storage := &mockStorage{typeName: "local"}
	repo := newMockRepository()
	cfg := testConfig()
	rm := NewRetentionManager(storage, repo, cfg, logger.Nop())

	ctx := context.Background()

	// Create expired backup records
	id1 := uuid.New()
	id2 := uuid.New()
	repo.backups[id1] = &models.Backup{
		ID:        id1,
		Path:      "host/vol/backup1.tar.gz",
		SizeBytes: 1000,
		Status:    models.BackupStatusCompleted,
	}
	repo.backups[id2] = &models.Backup{
		ID:        id2,
		Path:      "host/vol/backup2.tar.gz",
		SizeBytes: 2000,
		Status:    models.BackupStatusCompleted,
	}

	repo.deleteExpiredVal = []uuid.UUID{id1, id2}
	// List returns nothing for retention policy phase
	repo.listVal = nil
	repo.listTotal = 0

	result, err := rm.Cleanup(ctx, &RetentionPolicy{})
	if err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if result.DeletedCount != 2 {
		t.Errorf("DeletedCount = %d, want 2", result.DeletedCount)
	}
	if result.DeletedSize != 3000 {
		t.Errorf("DeletedSize = %d, want 3000", result.DeletedSize)
	}
	if result.FailedCount != 0 {
		t.Errorf("FailedCount = %d, want 0", result.FailedCount)
	}
	if len(result.DeletedBackups) != 2 {
		t.Errorf("DeletedBackups len = %d, want 2", len(result.DeletedBackups))
	}
}

func TestRetentionManager_Cleanup_StorageDeleteFails(t *testing.T) {
	storage := &mockStorage{
		typeName:  "local",
		deleteErr: fmt.Errorf("disk full"),
	}
	repo := newMockRepository()
	cfg := testConfig()
	rm := NewRetentionManager(storage, repo, cfg, logger.Nop())

	ctx := context.Background()

	id := uuid.New()
	repo.backups[id] = &models.Backup{
		ID:   id,
		Path: "host/vol/backup.tar.gz",
	}
	repo.deleteExpiredVal = []uuid.UUID{id}
	repo.listVal = nil
	repo.listTotal = 0

	result, err := rm.Cleanup(ctx, &RetentionPolicy{})
	if err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if result.FailedCount != 1 {
		t.Errorf("FailedCount = %d, want 1", result.FailedCount)
	}
	if result.DeletedCount != 0 {
		t.Errorf("DeletedCount = %d, want 0", result.DeletedCount)
	}
	if len(result.Errors) != 1 {
		t.Errorf("Errors len = %d, want 1", len(result.Errors))
	}
}

func TestRetentionManager_Cleanup_GetExpiredRecordFails(t *testing.T) {
	storage := &mockStorage{typeName: "local"}
	repo := newMockRepository()
	cfg := testConfig()
	rm := NewRetentionManager(storage, repo, cfg, logger.Nop())

	ctx := context.Background()

	// ID exists in expired list but not in repo
	id := uuid.New()
	repo.deleteExpiredVal = []uuid.UUID{id}
	repo.listVal = nil
	repo.listTotal = 0

	result, err := rm.Cleanup(ctx, &RetentionPolicy{})
	if err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if result.FailedCount != 1 {
		t.Errorf("FailedCount = %d, want 1", result.FailedCount)
	}
	if len(result.FailedBackups) != 1 {
		t.Errorf("FailedBackups len = %d, want 1", len(result.FailedBackups))
	}
}

func TestRetentionManager_Cleanup_RepoDeleteFails(t *testing.T) {
	storage := &mockStorage{typeName: "local"}
	repo := newMockRepository()
	repo.deleteErr = fmt.Errorf("constraint violation")
	cfg := testConfig()
	rm := NewRetentionManager(storage, repo, cfg, logger.Nop())

	ctx := context.Background()

	id := uuid.New()
	repo.backups[id] = &models.Backup{ID: id, Path: "some/path"}
	repo.deleteExpiredVal = []uuid.UUID{id}
	repo.listVal = nil
	repo.listTotal = 0

	result, err := rm.Cleanup(ctx, &RetentionPolicy{})
	if err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	// Storage delete succeeds, but repo delete fails
	if result.FailedCount != 1 {
		t.Errorf("FailedCount = %d, want 1", result.FailedCount)
	}
	if result.DeletedCount != 0 {
		t.Errorf("DeletedCount = %d, want 0", result.DeletedCount)
	}
}

func TestRetentionManager_PruneTarget(t *testing.T) {
	storage := &mockStorage{typeName: "local"}
	repo := newMockRepository()
	cfg := testConfig()
	rm := NewRetentionManager(storage, repo, cfg, logger.Nop())

	ctx := context.Background()
	hostID := uuid.New()

	// Create 5 backups with different creation times
	now := time.Now()
	for i := 0; i < 5; i++ {
		id := uuid.New()
		repo.backups[id] = &models.Backup{
			ID:        id,
			HostID:    hostID,
			TargetID:  "my-vol",
			Status:    models.BackupStatusCompleted,
			Path:      fmt.Sprintf("host/%s.tar.gz", id),
			SizeBytes: 100,
			CreatedAt: now.Add(-time.Duration(i) * time.Hour),
		}
	}

	result, err := rm.PruneTarget(ctx, hostID, "my-vol", 2)
	if err != nil {
		t.Fatalf("PruneTarget() error = %v", err)
	}
	// Should delete 3 (keep newest 2)
	if result.DeletedCount != 3 {
		t.Errorf("DeletedCount = %d, want 3", result.DeletedCount)
	}
	if result.DeletedSize != 300 {
		t.Errorf("DeletedSize = %d, want 300", result.DeletedSize)
	}
}

func TestRetentionManager_PruneTarget_SkipsIncomplete(t *testing.T) {
	storage := &mockStorage{typeName: "local"}
	repo := newMockRepository()
	cfg := testConfig()
	rm := NewRetentionManager(storage, repo, cfg, logger.Nop())

	ctx := context.Background()
	hostID := uuid.New()

	now := time.Now()
	// Newest (keep)
	id1 := uuid.New()
	repo.backups[id1] = &models.Backup{
		ID: id1, HostID: hostID, TargetID: "vol",
		Status: models.BackupStatusCompleted, Path: "p1",
		CreatedAt: now,
	}
	// Second-oldest: running (should be skipped, not deleted)
	id2 := uuid.New()
	repo.backups[id2] = &models.Backup{
		ID: id2, HostID: hostID, TargetID: "vol",
		Status: models.BackupStatusRunning, Path: "p2",
		CreatedAt: now.Add(-2 * time.Hour),
	}
	// Oldest: completed (should be deleted)
	id3 := uuid.New()
	repo.backups[id3] = &models.Backup{
		ID: id3, HostID: hostID, TargetID: "vol",
		Status: models.BackupStatusCompleted, Path: "p3",
		CreatedAt: now.Add(-3 * time.Hour),
	}

	result, err := rm.PruneTarget(ctx, hostID, "vol", 1)
	if err != nil {
		t.Fatalf("PruneTarget() error = %v", err)
	}
	if result.SkippedCount != 1 {
		t.Errorf("SkippedCount = %d, want 1 (running backup)", result.SkippedCount)
	}
	if result.DeletedCount != 1 {
		t.Errorf("DeletedCount = %d, want 1", result.DeletedCount)
	}
}

func TestRetentionManager_CleanupOrphaned(t *testing.T) {
	storage := &mockStorage{typeName: "local"}
	repo := newMockRepository()
	cfg := testConfig()
	rm := NewRetentionManager(storage, repo, cfg, logger.Nop())

	ctx := context.Background()

	// Storage has 3 files
	storage.listVal = []StorageEntry{
		{Path: "host/vol/backup1.tar.gz", Size: 100},
		{Path: "host/vol/backup2.tar.gz", Size: 200},
		{Path: "host/vol/orphan.tar.gz", Size: 300},
	}

	// DB only knows about 2
	repo.listVal = []*models.Backup{
		{ID: uuid.New(), Path: "host/vol/backup1.tar.gz"},
		{ID: uuid.New(), Path: "host/vol/backup2.tar.gz"},
	}
	repo.listTotal = 2

	result, err := rm.CleanupOrphaned(ctx)
	if err != nil {
		t.Fatalf("CleanupOrphaned() error = %v", err)
	}
	if result.DeletedCount != 1 {
		t.Errorf("DeletedCount = %d, want 1 (orphaned file)", result.DeletedCount)
	}
	if result.DeletedSize != 300 {
		t.Errorf("DeletedSize = %d, want 300", result.DeletedSize)
	}
	if result.ProcessedCount != 3 {
		t.Errorf("ProcessedCount = %d, want 3", result.ProcessedCount)
	}
}

func TestRetentionManager_CleanupOrphaned_StorageListError(t *testing.T) {
	storage := &mockStorage{
		typeName: "local",
		listErr:  fmt.Errorf("network error"),
	}
	repo := newMockRepository()
	cfg := testConfig()
	rm := NewRetentionManager(storage, repo, cfg, logger.Nop())

	_, err := rm.CleanupOrphaned(context.Background())
	if err == nil {
		t.Fatal("CleanupOrphaned() expected error when storage.List fails")
	}
}

func TestRetentionManager_GetStorageUsage(t *testing.T) {
	storage := &mockStorage{
		typeName: "s3",
		statsVal: &StorageStats{
			TotalSpace: 10000,
			UsedSpace:  3000,
		},
	}
	repo := newMockRepository()
	repo.getStatsVal = &models.BackupStats{TotalBackups: 15}
	cfg := testConfig()
	rm := NewRetentionManager(storage, repo, cfg, logger.Nop())

	info, err := rm.GetStorageUsage(context.Background())
	if err != nil {
		t.Fatalf("GetStorageUsage() error = %v", err)
	}
	if info.Type != "s3" {
		t.Errorf("Type = %q, want %q", info.Type, "s3")
	}
	if info.TotalSize != 10000 {
		t.Errorf("TotalSize = %d, want 10000", info.TotalSize)
	}
	if info.UsedSize != 3000 {
		t.Errorf("UsedSize = %d, want 3000", info.UsedSize)
	}
	if info.BackupCount != 15 {
		t.Errorf("BackupCount = %d, want 15", info.BackupCount)
	}
}

func TestRetentionManager_GetStorageUsage_StorageError(t *testing.T) {
	storage := &mockStorage{
		typeName: "local",
		statsErr: fmt.Errorf("stats unavailable"),
	}
	repo := newMockRepository()
	cfg := testConfig()
	rm := NewRetentionManager(storage, repo, cfg, logger.Nop())

	_, err := rm.GetStorageUsage(context.Background())
	if err == nil {
		t.Fatal("GetStorageUsage() expected error")
	}
}

func TestRetentionManager_GetStorageUsage_RepoError(t *testing.T) {
	storage := &mockStorage{
		typeName: "local",
		statsVal: &StorageStats{TotalSpace: 100},
	}
	repo := newMockRepository()
	repo.getStatsErr = fmt.Errorf("db error")
	cfg := testConfig()
	rm := NewRetentionManager(storage, repo, cfg, logger.Nop())

	_, err := rm.GetStorageUsage(context.Background())
	if err == nil {
		t.Fatal("GetStorageUsage() expected error")
	}
}

// ============================================================================
// selectBackupsToDelete Tests
// ============================================================================

func TestSelectBackupsToDelete_Empty(t *testing.T) {
	storage := &mockStorage{typeName: "local"}
	repo := newMockRepository()
	rm := NewRetentionManager(storage, repo, testConfig(), logger.Nop())

	result := rm.selectBackupsToDelete(nil, &RetentionPolicy{})
	if len(result) != 0 {
		t.Errorf("selectBackupsToDelete(nil) len = %d, want 0", len(result))
	}
}

func TestSelectBackupsToDelete_KeepsMinBackups(t *testing.T) {
	storage := &mockStorage{typeName: "local"}
	repo := newMockRepository()
	rm := NewRetentionManager(storage, repo, testConfig(), logger.Nop())

	now := time.Now()
	backups := make([]*models.Backup, 5)
	for i := 0; i < 5; i++ {
		backups[i] = &models.Backup{
			ID:        uuid.New(),
			CreatedAt: now.Add(-time.Duration(i) * 24 * time.Hour),
		}
	}

	// With MinBackups=3, even if all are old, at least 3 are kept
	policy := &RetentionPolicy{
		MinBackups: 3,
		MaxAgeDays: 1, // everything older than 1 day is eligible
	}

	result := rm.selectBackupsToDelete(backups, policy)
	// The 3 newest should be kept, leaving 2 eligible for deletion
	// But only those older than MaxAgeDays AND not min-kept are deleted
	// backups[0] is today (kept by min), backups[1] is 1 day (kept by min),
	// backups[2] is 2 days (kept by min), backups[3] is 3 days, backups[4] is 4 days
	if len(result) > 2 {
		t.Errorf("should delete at most 2, got %d", len(result))
	}
}

func TestSelectBackupsToDelete_MaxAge(t *testing.T) {
	storage := &mockStorage{typeName: "local"}
	repo := newMockRepository()
	rm := NewRetentionManager(storage, repo, testConfig(), logger.Nop())

	now := time.Now()
	backups := []*models.Backup{
		{ID: uuid.New(), CreatedAt: now},                              // 0 days
		{ID: uuid.New(), CreatedAt: now.Add(-5 * 24 * time.Hour)},    // 5 days
		{ID: uuid.New(), CreatedAt: now.Add(-100 * 24 * time.Hour)},  // 100 days
	}

	policy := &RetentionPolicy{
		MaxAgeDays: 30,
		MinBackups: 0,
	}

	result := rm.selectBackupsToDelete(backups, policy)
	// Only the 100-day-old backup should be deleted
	if len(result) != 1 {
		t.Errorf("len = %d, want 1", len(result))
	}
	if len(result) > 0 && result[0].ID != backups[2].ID {
		t.Errorf("deleted wrong backup: got %v, want %v", result[0].ID, backups[2].ID)
	}
}

// ============================================================================
// Service.Cleanup Tests
// ============================================================================

func TestService_Cleanup_EmitsEvents(t *testing.T) {
	svc, _, repo := testService(t)
	ctx := context.Background()

	repo.listVal = nil
	repo.listTotal = 0

	var events []EventType
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(2) // expect started + completed

	svc.OnEvent(func(e Event) {
		mu.Lock()
		events = append(events, e.Type)
		mu.Unlock()
		wg.Done()
	})

	_, err := svc.Cleanup(ctx, nil)
	if err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}

	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 {
		t.Fatalf("event count = %d, want 2", len(events))
	}

	hasStarted := false
	hasCompleted := false
	for _, et := range events {
		if et == EventCleanupStarted {
			hasStarted = true
		}
		if et == EventCleanupCompleted {
			hasCompleted = true
		}
	}
	if !hasStarted {
		t.Error("missing EventCleanupStarted")
	}
	if !hasCompleted {
		t.Error("missing EventCleanupCompleted")
	}
}

// ============================================================================
// Archive Utility Tests
// ============================================================================

func TestGetCompressionExtension(t *testing.T) {
	tests := []struct {
		compression models.BackupCompression
		want        string
	}{
		{models.BackupCompressionGzip, ".tar.gz"},
		{models.BackupCompressionZstd, ".tar.zst"},
		{models.BackupCompressionNone, ".tar"},
		{"unknown", ".tar.gz"}, // default
	}

	for _, tt := range tests {
		t.Run(string(tt.compression), func(t *testing.T) {
			got := GetCompressionExtension(tt.compression)
			if got != tt.want {
				t.Errorf("GetCompressionExtension(%q) = %q, want %q", tt.compression, got, tt.want)
			}
		})
	}
}

func TestDetectCompression(t *testing.T) {
	tests := []struct {
		filename string
		want     models.BackupCompression
	}{
		{"backup.tar.gz", models.BackupCompressionGzip},
		{"backup.tgz", models.BackupCompressionGzip},
		{"backup.tar.zst", models.BackupCompressionZstd},
		{"backup.tar.zstd", models.BackupCompressionZstd},
		{"backup.tar", models.BackupCompressionNone},
		{"backup.unknown", models.BackupCompressionGzip}, // default
		{"BACKUP.TAR.GZ", models.BackupCompressionGzip},  // case insensitive
		{"data.TAR.ZST", models.BackupCompressionZstd},   // case insensitive
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			got := DetectCompression(tt.filename)
			if got != tt.want {
				t.Errorf("DetectCompression(%q) = %q, want %q", tt.filename, got, tt.want)
			}
		})
	}
}

func TestCalculateChecksum(t *testing.T) {
	data := "hello world"
	checksum, err := CalculateChecksum(strings.NewReader(data))
	if err != nil {
		t.Fatalf("CalculateChecksum() error = %v", err)
	}
	if checksum == "" {
		t.Fatal("CalculateChecksum() returned empty string")
	}
	// SHA256 of "hello world" is known
	expected := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if checksum != expected {
		t.Errorf("checksum = %q, want %q", checksum, expected)
	}
}

func TestCalculateChecksum_Empty(t *testing.T) {
	checksum, err := CalculateChecksum(strings.NewReader(""))
	if err != nil {
		t.Fatalf("CalculateChecksum() error = %v", err)
	}
	// SHA256 of empty string
	expected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if checksum != expected {
		t.Errorf("checksum = %q, want %q", checksum, expected)
	}
}

// ============================================================================
// sanitizeFilename Tests
// ============================================================================

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"simple", "simple"},
		{"with-dash", "with-dash"},
		{"with_under", "with_under"},
		{"with.dot", "with.dot"},
		{"UPPER", "UPPER"},
		{"with spaces", "with_spaces"},
		{"special!@#$%", "special_____"},
		{"/leading/slash", "_leading_slash"},
		{"mixed-123_test.v2", "mixed-123_test.v2"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizeFilename(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeFilename(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ============================================================================
// Config Struct Tests
// ============================================================================

func TestConfig_ZeroValue(t *testing.T) {
	cfg := Config{}
	if cfg.StoragePath != "" {
		t.Errorf("zero StoragePath = %q, want empty", cfg.StoragePath)
	}
	if cfg.EncryptionEnabled {
		t.Error("zero EncryptionEnabled should be false")
	}
	if cfg.MaxConcurrentBackups != 0 {
		t.Errorf("zero MaxConcurrentBackups = %d, want 0", cfg.MaxConcurrentBackups)
	}
	if cfg.VerifyAfterBackup {
		t.Error("zero VerifyAfterBackup should be false")
	}
}

// ============================================================================
// Event Type Constants Tests
// ============================================================================

func TestEventTypeConstants(t *testing.T) {
	// Verify event type string values
	tests := []struct {
		event EventType
		want  string
	}{
		{EventBackupStarted, "backup.started"},
		{EventBackupCompleted, "backup.completed"},
		{EventBackupFailed, "backup.failed"},
		{EventRestoreStarted, "restore.started"},
		{EventRestoreCompleted, "restore.completed"},
		{EventRestoreFailed, "restore.failed"},
		{EventCleanupStarted, "cleanup.started"},
		{EventCleanupCompleted, "cleanup.completed"},
		{EventCleanupFailed, "cleanup.failed"},
	}

	for _, tt := range tests {
		if string(tt.event) != tt.want {
			t.Errorf("EventType %q != %q", tt.event, tt.want)
		}
	}
}

// ============================================================================
// StorageEntry / StorageStats Struct Tests
// ============================================================================

func TestStorageEntry_Fields(t *testing.T) {
	now := time.Now()
	entry := StorageEntry{
		Path:         "host/vol/backup.tar.gz",
		Size:         4096,
		ModTime:      now,
		IsDir:        false,
		ETag:         "abc123",
		StorageClass: "STANDARD",
	}
	if entry.Path != "host/vol/backup.tar.gz" {
		t.Errorf("Path = %q", entry.Path)
	}
	if entry.Size != 4096 {
		t.Errorf("Size = %d", entry.Size)
	}
	if entry.IsDir {
		t.Error("IsDir should be false")
	}
}

func TestStorageStats_Fields(t *testing.T) {
	stats := StorageStats{
		TotalSpace:     1000000,
		UsedSpace:      400000,
		AvailableSpace: 600000,
		FileCount:      50,
	}
	if stats.AvailableSpace != 600000 {
		t.Errorf("AvailableSpace = %d", stats.AvailableSpace)
	}
}

// ============================================================================
// CleanupResult Struct Tests
// ============================================================================

func TestCleanupResult_ZeroValue(t *testing.T) {
	result := CleanupResult{}
	if result.DeletedCount != 0 {
		t.Errorf("DeletedCount = %d", result.DeletedCount)
	}
	if result.DeletedSize != 0 {
		t.Errorf("DeletedSize = %d", result.DeletedSize)
	}
	if result.FailedCount != 0 {
		t.Errorf("FailedCount = %d", result.FailedCount)
	}
	if result.SkippedCount != 0 {
		t.Errorf("SkippedCount = %d", result.SkippedCount)
	}
	if len(result.DeletedBackups) != 0 {
		t.Errorf("DeletedBackups should be empty")
	}
	if len(result.Errors) != 0 {
		t.Errorf("Errors should be empty")
	}
}

// ============================================================================
// Progress Struct Tests
// ============================================================================

func TestProgress_Fields(t *testing.T) {
	p := Progress{
		Phase:          "archiving",
		Percent:        45.5,
		Message:        "Creating archive...",
		BytesProcessed: 1024,
		BytesTotal:     2048,
		CurrentFile:    "data/file.txt",
	}
	if p.Phase != "archiving" {
		t.Errorf("Phase = %q", p.Phase)
	}
	if p.Percent != 45.5 {
		t.Errorf("Percent = %f", p.Percent)
	}
	if p.BytesProcessed != 1024 {
		t.Errorf("BytesProcessed = %d", p.BytesProcessed)
	}
}

// ============================================================================
// ArchiveResult / ExtractResult / ArchiveEntry Tests
// ============================================================================

func TestArchiveResult_Fields(t *testing.T) {
	r := ArchiveResult{
		OriginalSize: 10000,
		FileCount:    42,
		Checksum:     "sha256:abc123",
	}
	if r.OriginalSize != 10000 {
		t.Errorf("OriginalSize = %d", r.OriginalSize)
	}
	if r.FileCount != 42 {
		t.Errorf("FileCount = %d", r.FileCount)
	}
}

func TestExtractResult_Fields(t *testing.T) {
	r := ExtractResult{
		BytesWritten: 5000,
		FileCount:    20,
	}
	if r.BytesWritten != 5000 {
		t.Errorf("BytesWritten = %d", r.BytesWritten)
	}
}

func TestArchiveEntry_Fields(t *testing.T) {
	now := time.Now()
	entry := ArchiveEntry{
		Name:       "data/file.txt",
		Size:       1234,
		Mode:       0644,
		ModTime:    now,
		IsDir:      false,
		LinkTarget: "",
	}
	if entry.Name != "data/file.txt" {
		t.Errorf("Name = %q", entry.Name)
	}
	if entry.IsDir {
		t.Error("IsDir should be false")
	}
}

// ============================================================================
// CreateOptions / RestoreOptions / VerifyOptions Tests
// ============================================================================

func TestCreateOptions_Fields(t *testing.T) {
	hostID := uuid.New()
	userID := uuid.New()
	retDays := 30

	opts := CreateOptions{
		HostID:        hostID,
		Type:          models.BackupTypeVolume,
		TargetID:      "my-vol",
		TargetName:    "My Volume",
		Trigger:       models.BackupTriggerManual,
		Compression:   models.BackupCompressionGzip,
		Encrypt:       true,
		RetentionDays: &retDays,
		StopContainer: false,
		CreatedBy:     &userID,
	}
	if opts.HostID != hostID {
		t.Errorf("HostID mismatch")
	}
	if opts.Type != models.BackupTypeVolume {
		t.Errorf("Type = %q", opts.Type)
	}
	if *opts.RetentionDays != 30 {
		t.Errorf("RetentionDays = %d", *opts.RetentionDays)
	}
}

func TestRestoreOptions_Fields(t *testing.T) {
	opts := RestoreOptions{
		BackupID:          uuid.New(),
		TargetName:        "restored-vol",
		OverwriteExisting: true,
		StopContainers:    true,
		StartAfterRestore: false,
	}
	if !opts.OverwriteExisting {
		t.Error("OverwriteExisting should be true")
	}
	if !opts.StopContainers {
		t.Error("StopContainers should be true")
	}
}

func TestVerifyOptions_Fields(t *testing.T) {
	opts := VerifyOptions{
		CheckChecksum:   true,
		CheckContents:   true,
		CheckDecryption: false,
		FullExtract:     true,
		ChecksumOnly:    false,
	}
	if !opts.CheckChecksum {
		t.Error("CheckChecksum should be true")
	}
	if !opts.FullExtract {
		t.Error("FullExtract should be true")
	}
}

// ============================================================================
// StackInfo / StackContainerInfo Tests
// ============================================================================

func TestStackInfo_Fields(t *testing.T) {
	info := StackInfo{
		ID:          uuid.New(),
		HostID:      uuid.New(),
		Name:        "my-stack",
		ComposeFile: "version: '3'\nservices:\n  web:\n    image: nginx",
		Services:    []string{"web", "db"},
		Labels:      map[string]string{"env": "prod"},
	}
	if info.Name != "my-stack" {
		t.Errorf("Name = %q", info.Name)
	}
	if len(info.Services) != 2 {
		t.Errorf("Services len = %d", len(info.Services))
	}
}

func TestStackContainerInfo_Fields(t *testing.T) {
	info := StackContainerInfo{
		ID:      "abc123",
		Name:    "my-stack_web_1",
		Image:   "nginx:latest",
		Volumes: []string{"data-vol"},
		Labels:  map[string]string{"com.docker.compose.service": "web"},
	}
	if info.ID != "abc123" {
		t.Errorf("ID = %q", info.ID)
	}
	if len(info.Volumes) != 1 {
		t.Errorf("Volumes len = %d", len(info.Volumes))
	}
}

// ============================================================================
// VolumeInfo / CreateVolumeOptions / ContainerInfo Tests
// ============================================================================

func TestVolumeInfo_Fields(t *testing.T) {
	info := VolumeInfo{
		Name:       "my-vol",
		Driver:     "local",
		Mountpoint: "/var/lib/docker/volumes/my-vol/_data",
		Labels:     map[string]string{"backup": "true"},
		Options:    map[string]string{"type": "tmpfs"},
		Scope:      "local",
	}
	if info.Name != "my-vol" {
		t.Errorf("Name = %q", info.Name)
	}
	if info.Mountpoint != "/var/lib/docker/volumes/my-vol/_data" {
		t.Errorf("Mountpoint = %q", info.Mountpoint)
	}
}

func TestCreateVolumeOptions_Fields(t *testing.T) {
	opts := CreateVolumeOptions{
		Name:       "new-vol",
		Driver:     "local",
		DriverOpts: map[string]string{"size": "1G"},
		Labels:     map[string]string{"created-by": "backup"},
	}
	if opts.Name != "new-vol" {
		t.Errorf("Name = %q", opts.Name)
	}
}

func TestContainerInfo_Fields(t *testing.T) {
	info := ContainerInfo{
		ID:      "container123",
		Name:    "my-container",
		Image:   "nginx:latest",
		State:   "running",
		Status:  "Up 2 hours",
		Volumes: []string{"vol1", "vol2"},
		Labels:  map[string]string{"app": "web"},
	}
	if info.ID != "container123" {
		t.Errorf("ID = %q", info.ID)
	}
	if len(info.Volumes) != 2 {
		t.Errorf("Volumes len = %d", len(info.Volumes))
	}
}

// ============================================================================
// keysFromSet Tests
// ============================================================================

func TestKeysFromSet(t *testing.T) {
	set := map[string]bool{
		"a": true,
		"b": true,
		"c": true,
	}
	keys := keysFromSet(set)
	if len(keys) != 3 {
		t.Errorf("len = %d, want 3", len(keys))
	}

	// Verify all keys are present (order may vary)
	found := make(map[string]bool)
	for _, k := range keys {
		found[k] = true
	}
	for k := range set {
		if !found[k] {
			t.Errorf("missing key %q", k)
		}
	}
}

func TestKeysFromSet_Empty(t *testing.T) {
	keys := keysFromSet(map[string]bool{})
	if len(keys) != 0 {
		t.Errorf("len = %d, want 0", len(keys))
	}
}

// ============================================================================
// min Tests
// ============================================================================

func TestMin(t *testing.T) {
	tests := []struct {
		a, b, want int
	}{
		{1, 2, 1},
		{2, 1, 1},
		{0, 0, 0},
		{-1, 1, -1},
		{5, 5, 5},
	}
	for _, tt := range tests {
		got := min(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("min(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

// ============================================================================
// WithStackProviderOption Tests
// ============================================================================

func TestWithStackProviderOption(t *testing.T) {
	sp := &mockStackProvider{}
	opt := WithStackProviderOption(sp)

	opts := &serviceOptions{}
	opt(opts)

	if opts.stackProvider == nil {
		t.Fatal("stackProvider should be set")
	}
}

// ============================================================================
// NewRetentionManager Tests
// ============================================================================

func TestNewRetentionManager(t *testing.T) {
	storage := &mockStorage{typeName: "local"}
	repo := newMockRepository()
	cfg := testConfig()

	rm := NewRetentionManager(storage, repo, cfg, logger.Nop())
	if rm == nil {
		t.Fatal("NewRetentionManager() returned nil")
	}
	if rm.storage != storage {
		t.Error("storage not set correctly")
	}
	if rm.repo != repo {
		t.Error("repo not set correctly")
	}
}

// ============================================================================
// Creator Option Tests
// ============================================================================

func TestWithStackProvider(t *testing.T) {
	sp := &mockStackProvider{}
	opt := WithStackProvider(sp)

	creator := &Creator{}
	opt(creator)

	if creator.stackProvider == nil {
		t.Fatal("stackProvider should be set on creator")
	}
}

// ============================================================================
// Restorer Option Tests
// ============================================================================

func TestWithRestorerStackProvider(t *testing.T) {
	sp := &mockStackProvider{}
	opt := WithRestorerStackProvider(sp)

	restorer := &Restorer{}
	opt(restorer)

	if restorer.stackProvider == nil {
		t.Fatal("stackProvider should be set on restorer")
	}
}

// ============================================================================
// TarArchiver Tests
// ============================================================================

func TestNewTarArchiver(t *testing.T) {
	archiver := NewTarArchiver()
	if archiver == nil {
		t.Fatal("NewTarArchiver() returned nil")
	}
	if archiver.BufferSize != 32*1024 {
		t.Errorf("BufferSize = %d, want %d", archiver.BufferSize, 32*1024)
	}
	if archiver.ProgressCallback != nil {
		t.Error("ProgressCallback should be nil by default")
	}
}

// ============================================================================
// nopWriteCloser Tests
// ============================================================================

func TestNopWriteCloser_Close(t *testing.T) {
	nwc := nopWriteCloser{Writer: io.Discard}
	if err := nwc.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

// ============================================================================
// CreateResult / RestoreResult Tests
// ============================================================================

func TestCreateResult_Fields(t *testing.T) {
	r := CreateResult{
		Duration:     5 * time.Second,
		OriginalSize: 10000,
		FinalSize:    5000,
		FileCount:    42,
		Verified:     true,
	}
	if r.Duration != 5*time.Second {
		t.Errorf("Duration = %v", r.Duration)
	}
	if r.FinalSize != 5000 {
		t.Errorf("FinalSize = %d", r.FinalSize)
	}
	if !r.Verified {
		t.Error("Verified should be true")
	}
}

func TestRestoreResult_Fields(t *testing.T) {
	r := RestoreResult{
		BackupID:     uuid.New(),
		TargetID:     "vol-1",
		TargetName:   "My Volume",
		Duration:     3 * time.Second,
		BytesWritten: 8000,
		FileCount:    20,
	}
	if r.TargetID != "vol-1" {
		t.Errorf("TargetID = %q", r.TargetID)
	}
	if r.BytesWritten != 8000 {
		t.Errorf("BytesWritten = %d", r.BytesWritten)
	}
}
