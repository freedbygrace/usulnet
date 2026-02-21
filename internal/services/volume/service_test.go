// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package volume

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

type mockHostProvider struct {
	client docker.ClientAPI
	err    error
}

func (m *mockHostProvider) GetClient(_ context.Context, _ uuid.UUID) (docker.ClientAPI, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.client, nil
}

// mockDockerClient implements docker.ClientAPI by embedding the interface and
// overriding only volume-related methods.
type mockDockerClient struct {
	docker.ClientAPI

	volumeListResult []docker.Volume
	volumeListErr    error
	volumeGetResult  *docker.Volume
	volumeGetErr     error
	volumeCreateRet  *docker.Volume
	volumeCreateErr  error
	volumeRemoveErr  error
	volumePruneSpace uint64
	volumePruneNames []string
	volumePruneErr   error
	volumeExistsRet  bool
	volumeExistsErr  error
	volumeUsedByRet  []string
	volumeUsedByErr  error
}

func (m *mockDockerClient) VolumeList(_ context.Context, _ docker.VolumeListOptions) ([]docker.Volume, error) {
	return m.volumeListResult, m.volumeListErr
}

func (m *mockDockerClient) VolumeGet(_ context.Context, _ string) (*docker.Volume, error) {
	return m.volumeGetResult, m.volumeGetErr
}

func (m *mockDockerClient) VolumeCreate(_ context.Context, _ docker.VolumeCreateOptions) (*docker.Volume, error) {
	return m.volumeCreateRet, m.volumeCreateErr
}

func (m *mockDockerClient) VolumeRemove(_ context.Context, _ string, _ bool) error {
	return m.volumeRemoveErr
}

func (m *mockDockerClient) VolumePrune(_ context.Context, _ map[string][]string) (uint64, []string, error) {
	return m.volumePruneSpace, m.volumePruneNames, m.volumePruneErr
}

func (m *mockDockerClient) VolumeExists(_ context.Context, _ string) (bool, error) {
	return m.volumeExistsRet, m.volumeExistsErr
}

func (m *mockDockerClient) VolumeUsedBy(_ context.Context, _ string) ([]string, error) {
	return m.volumeUsedByRet, m.volumeUsedByErr
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestService(client *mockDockerClient) *Service {
	return NewService(&mockHostProvider{client: client}, logger.Nop())
}

func testHostID() uuid.UUID {
	return uuid.MustParse("00000000-0000-0000-0000-000000000001")
}

// ---------------------------------------------------------------------------
// Interface compliance
// ---------------------------------------------------------------------------

func TestMock_InterfaceCompliance(t *testing.T) {
	var _ HostClientProvider = (*mockHostProvider)(nil)
}

// ---------------------------------------------------------------------------
// Tests: NewService
// ---------------------------------------------------------------------------

func TestNewService(t *testing.T) {
	svc := NewService(&mockHostProvider{}, nil)
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

// ---------------------------------------------------------------------------
// Tests: List
// ---------------------------------------------------------------------------

func TestList_HappyPath(t *testing.T) {
	now := time.Now()
	client := &mockDockerClient{
		volumeListResult: []docker.Volume{
			{Name: "vol1", Driver: "local", CreatedAt: now},
			{Name: "vol2", Driver: "local", CreatedAt: now},
		},
		volumeGetResult: &docker.Volume{
			Name: "vol1", Driver: "local", Mountpoint: "/var/lib/docker/volumes/vol1",
			UsageData: &docker.VolumeUsage{Size: 1024, RefCount: 1},
			CreatedAt: now,
		},
	}
	svc := newTestService(client)

	vols, err := svc.List(context.Background(), testHostID())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vols) != 2 {
		t.Fatalf("expected 2 volumes, got %d", len(vols))
	}
}

func TestList_HostClientError(t *testing.T) {
	svc := NewService(&mockHostProvider{err: fmt.Errorf("host offline")}, logger.Nop())

	_, err := svc.List(context.Background(), testHostID())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestList_DockerError(t *testing.T) {
	client := &mockDockerClient{volumeListErr: fmt.Errorf("docker error")}
	svc := newTestService(client)

	_, err := svc.List(context.Background(), testHostID())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "list volumes") {
		t.Errorf("error = %q, want wrapped", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Tests: Get
// ---------------------------------------------------------------------------

func TestGet_HappyPath(t *testing.T) {
	client := &mockDockerClient{
		volumeGetResult: &docker.Volume{
			Name: "mydata", Driver: "local", Mountpoint: "/data",
			Labels:    map[string]string{"app": "test"},
			UsageData: &docker.VolumeUsage{Size: 2048, RefCount: 2},
		},
	}
	svc := newTestService(client)

	vol, err := svc.Get(context.Background(), testHostID(), "mydata")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vol.Name != "mydata" {
		t.Errorf("name = %q, want %q", vol.Name, "mydata")
	}
	if vol.UsageData == nil {
		t.Fatal("expected non-nil UsageData")
	}
	if vol.UsageData.Size != 2048 {
		t.Errorf("size = %d, want 2048", vol.UsageData.Size)
	}
}

func TestGet_NotFound(t *testing.T) {
	client := &mockDockerClient{volumeGetErr: fmt.Errorf("volume not found")}
	svc := newTestService(client)

	_, err := svc.Get(context.Background(), testHostID(), "nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Tests: Create
// ---------------------------------------------------------------------------

func TestCreate_HappyPath(t *testing.T) {
	client := &mockDockerClient{
		volumeCreateRet: &docker.Volume{
			Name: "newvol", Driver: "local", Mountpoint: "/var/lib/docker/volumes/newvol",
		},
	}
	svc := newTestService(client)

	input := &models.CreateVolumeInput{
		Name:   "newvol",
		Driver: "local",
		Labels: map[string]string{"env": "test"},
	}

	vol, err := svc.Create(context.Background(), testHostID(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vol.Name != "newvol" {
		t.Errorf("name = %q, want %q", vol.Name, "newvol")
	}
}

func TestCreate_Error(t *testing.T) {
	client := &mockDockerClient{volumeCreateErr: fmt.Errorf("driver error")}
	svc := newTestService(client)

	_, err := svc.Create(context.Background(), testHostID(), &models.CreateVolumeInput{Name: "fail"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "create volume") {
		t.Errorf("error = %q, want wrapped", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Tests: Delete
// ---------------------------------------------------------------------------

func TestDelete_HappyPath(t *testing.T) {
	client := &mockDockerClient{}
	svc := newTestService(client)

	err := svc.Delete(context.Background(), testHostID(), "vol1", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDelete_Force(t *testing.T) {
	client := &mockDockerClient{}
	svc := newTestService(client)

	err := svc.Delete(context.Background(), testHostID(), "vol1", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDelete_Error(t *testing.T) {
	client := &mockDockerClient{volumeRemoveErr: fmt.Errorf("volume in use")}
	svc := newTestService(client)

	err := svc.Delete(context.Background(), testHostID(), "vol1", false)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "remove volume") {
		t.Errorf("error = %q, want wrapped", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Tests: Prune
// ---------------------------------------------------------------------------

func TestPrune_HappyPath(t *testing.T) {
	client := &mockDockerClient{
		volumePruneSpace: 1048576,
		volumePruneNames: []string{"orphan1", "orphan2"},
	}
	svc := newTestService(client)

	result, err := svc.Prune(context.Background(), testHostID())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.ItemsDeleted) != 2 {
		t.Errorf("expected 2 deleted items, got %d", len(result.ItemsDeleted))
	}
	if result.SpaceReclaimed != 1048576 {
		t.Errorf("space = %d, want 1048576", result.SpaceReclaimed)
	}
}

func TestPrune_Error(t *testing.T) {
	client := &mockDockerClient{volumePruneErr: fmt.Errorf("prune failed")}
	svc := newTestService(client)

	_, err := svc.Prune(context.Background(), testHostID())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Tests: Exists
// ---------------------------------------------------------------------------

func TestExists_True(t *testing.T) {
	client := &mockDockerClient{volumeExistsRet: true}
	svc := newTestService(client)

	exists, err := svc.Exists(context.Background(), testHostID(), "vol1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !exists {
		t.Error("expected true, got false")
	}
}

func TestExists_False(t *testing.T) {
	client := &mockDockerClient{volumeExistsRet: false}
	svc := newTestService(client)

	exists, err := svc.Exists(context.Background(), testHostID(), "vol1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exists {
		t.Error("expected false, got true")
	}
}

// ---------------------------------------------------------------------------
// Tests: UsedBy
// ---------------------------------------------------------------------------

func TestUsedBy_HappyPath(t *testing.T) {
	client := &mockDockerClient{
		volumeUsedByRet: []string{"container1", "container2"},
	}
	svc := newTestService(client)

	containers, err := svc.UsedBy(context.Background(), testHostID(), "vol1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(containers) != 2 {
		t.Errorf("expected 2 containers, got %d", len(containers))
	}
}

func TestUsedBy_Empty(t *testing.T) {
	client := &mockDockerClient{volumeUsedByRet: []string{}}
	svc := newTestService(client)

	containers, err := svc.UsedBy(context.Background(), testHostID(), "vol1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(containers) != 0 {
		t.Errorf("expected 0 containers, got %d", len(containers))
	}
}

// ---------------------------------------------------------------------------
// Tests: GetStats
// ---------------------------------------------------------------------------

func TestGetStats_HappyPath(t *testing.T) {
	client := &mockDockerClient{
		volumeListResult: []docker.Volume{
			{Name: "vol1"},
			{Name: "vol2"},
		},
		volumeGetResult: &docker.Volume{
			Name:      "vol1",
			UsageData: &docker.VolumeUsage{Size: 1024, RefCount: 1},
		},
	}
	svc := newTestService(client)

	stats, err := svc.GetStats(context.Background(), testHostID())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.Total != 2 {
		t.Errorf("total = %d, want 2", stats.Total)
	}
}

// ---------------------------------------------------------------------------
// Tests: VolumeInfo
// ---------------------------------------------------------------------------

func TestVolumeInfo_HappyPath(t *testing.T) {
	client := &mockDockerClient{
		volumeGetResult: &docker.Volume{
			Name:       "data-vol",
			Driver:     "local",
			Mountpoint: "/var/lib/docker/volumes/data-vol",
			Labels:     map[string]string{"backup": "true"},
			UsageData:  &docker.VolumeUsage{Size: 4096},
		},
	}
	svc := newTestService(client)

	info, err := svc.VolumeInfo(context.Background(), testHostID(), "data-vol")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Name != "data-vol" {
		t.Errorf("name = %q, want %q", info.Name, "data-vol")
	}
	if info.Size != 4096 {
		t.Errorf("size = %d, want 4096", info.Size)
	}
	if info.Mountpoint != "/var/lib/docker/volumes/data-vol" {
		t.Errorf("mountpoint = %q", info.Mountpoint)
	}
}

func TestVolumeInfo_NoUsageData(t *testing.T) {
	client := &mockDockerClient{
		volumeGetResult: &docker.Volume{
			Name:   "no-usage",
			Driver: "local",
		},
	}
	svc := newTestService(client)

	info, err := svc.VolumeInfo(context.Background(), testHostID(), "no-usage")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Size != 0 {
		t.Errorf("size = %d, want 0 (no usage data)", info.Size)
	}
}

// ---------------------------------------------------------------------------
// Tests: dockerToModel conversion
// ---------------------------------------------------------------------------

func TestDockerToModel_BasicFields(t *testing.T) {
	svc := newTestService(&mockDockerClient{})
	hostID := testHostID()
	now := time.Now()

	v := &docker.Volume{
		Name:       "test-vol",
		Driver:     "local",
		Mountpoint: "/data",
		Labels:     map[string]string{"env": "prod"},
		Scope:      "local",
		Options:    map[string]string{"type": "tmpfs"},
		CreatedAt:  now,
	}

	model := svc.dockerToModel(v, hostID)
	if model.Name != "test-vol" {
		t.Errorf("Name = %q, want %q", model.Name, "test-vol")
	}
	if model.HostID != hostID {
		t.Errorf("HostID = %v, want %v", model.HostID, hostID)
	}
	if model.Driver != "local" {
		t.Errorf("Driver = %q, want %q", model.Driver, "local")
	}
	if model.UsageData != nil {
		t.Error("expected nil UsageData when source has none")
	}
}

func TestDockerToModel_WithUsageData(t *testing.T) {
	svc := newTestService(&mockDockerClient{})

	v := &docker.Volume{
		Name:      "used-vol",
		Driver:    "local",
		UsageData: &docker.VolumeUsage{Size: 8192, RefCount: 3},
	}

	model := svc.dockerToModel(v, testHostID())
	if model.UsageData == nil {
		t.Fatal("expected non-nil UsageData")
	}
	if model.UsageData.Size != 8192 {
		t.Errorf("Size = %d, want 8192", model.UsageData.Size)
	}
	if model.UsageData.RefCount != 3 {
		t.Errorf("RefCount = %d, want 3", model.UsageData.RefCount)
	}
}

// ---------------------------------------------------------------------------
// Tests: ListByDriver
// ---------------------------------------------------------------------------

func TestListByDriver_HappyPath(t *testing.T) {
	client := &mockDockerClient{
		volumeListResult: []docker.Volume{
			{Name: "nfs-vol", Driver: "nfs"},
		},
	}
	svc := newTestService(client)

	vols, err := svc.ListByDriver(context.Background(), testHostID(), "nfs")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vols) != 1 {
		t.Fatalf("expected 1 volume, got %d", len(vols))
	}
}

func TestListByDriver_Error(t *testing.T) {
	client := &mockDockerClient{volumeListErr: fmt.Errorf("docker error")}
	svc := newTestService(client)

	_, err := svc.ListByDriver(context.Background(), testHostID(), "local")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Tests: ListByLabel
// ---------------------------------------------------------------------------

func TestListByLabel_HappyPath(t *testing.T) {
	client := &mockDockerClient{
		volumeListResult: []docker.Volume{
			{Name: "labeled-vol", Labels: map[string]string{"env": "test"}},
		},
	}
	svc := newTestService(client)

	vols, err := svc.ListByLabel(context.Background(), testHostID(), map[string]string{"env": "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vols) != 1 {
		t.Fatalf("expected 1 volume, got %d", len(vols))
	}
}
