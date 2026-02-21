// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package capture

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ---------------------------------------------------------------------------
// Mock repository
// ---------------------------------------------------------------------------

type mockCaptureRepo struct {
	captures  map[uuid.UUID]*models.PacketCapture
	createErr error
	getErr    error
	listErr   error
	updateErr error
	deleteErr error
}

func newMockCaptureRepo() *mockCaptureRepo {
	return &mockCaptureRepo{
		captures: make(map[uuid.UUID]*models.PacketCapture),
	}
}

func (r *mockCaptureRepo) Create(_ context.Context, capture *models.PacketCapture) error {
	if r.createErr != nil {
		return r.createErr
	}
	if capture.ID == uuid.Nil {
		capture.ID = uuid.New()
	}
	capture.CreatedAt = time.Now()
	capture.UpdatedAt = time.Now()
	capture.StartedAt = time.Now()
	r.captures[capture.ID] = capture
	return nil
}

func (r *mockCaptureRepo) GetByID(_ context.Context, id uuid.UUID) (*models.PacketCapture, error) {
	if r.getErr != nil {
		return nil, r.getErr
	}
	c, ok := r.captures[id]
	if !ok {
		return nil, fmt.Errorf("capture not found")
	}
	return c, nil
}

func (r *mockCaptureRepo) ListByUser(_ context.Context, userID uuid.UUID) ([]*models.PacketCapture, error) {
	if r.listErr != nil {
		return nil, r.listErr
	}
	var result []*models.PacketCapture
	for _, c := range r.captures {
		if c.UserID == userID {
			result = append(result, c)
		}
	}
	return result, nil
}

func (r *mockCaptureRepo) UpdateStatus(_ context.Context, id uuid.UUID, status models.CaptureStatus, msg string) error {
	if r.updateErr != nil {
		return r.updateErr
	}
	c, ok := r.captures[id]
	if !ok {
		return fmt.Errorf("capture not found")
	}
	c.Status = status
	c.StatusMsg = msg
	return nil
}

func (r *mockCaptureRepo) UpdateStats(_ context.Context, id uuid.UUID, packetCount int64, fileSize int64) error {
	if r.updateErr != nil {
		return r.updateErr
	}
	c, ok := r.captures[id]
	if !ok {
		return fmt.Errorf("capture not found")
	}
	c.PacketCount = packetCount
	c.FileSize = fileSize
	return nil
}

func (r *mockCaptureRepo) Stop(_ context.Context, id uuid.UUID, packetCount int64, fileSize int64) error {
	if r.updateErr != nil {
		return r.updateErr
	}
	c, ok := r.captures[id]
	if !ok {
		return fmt.Errorf("capture not found")
	}
	now := time.Now()
	c.StoppedAt = &now
	c.PacketCount = packetCount
	c.FileSize = fileSize
	return nil
}

func (r *mockCaptureRepo) SetPID(_ context.Context, id uuid.UUID, pid int) error {
	c, ok := r.captures[id]
	if !ok {
		return fmt.Errorf("capture not found")
	}
	c.PID = pid
	return nil
}

func (r *mockCaptureRepo) Delete(_ context.Context, id uuid.UUID) error {
	if r.deleteErr != nil {
		return r.deleteErr
	}
	delete(r.captures, id)
	return nil
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func testLogger(t *testing.T) *logger.Logger {
	t.Helper()
	log, err := logger.NewWithOutput("error", "console", io.Discard)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	return log
}

func testCaptureDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// newTestService creates a Service with tcpdump forced empty (unavailable)
// so we can test the non-exec paths without requiring tcpdump.
func newTestService(t *testing.T, repo CaptureRepository) *Service {
	t.Helper()
	log := testLogger(t)
	dir := testCaptureDir(t)
	svc := &Service{
		repo:       repo,
		logger:     log.Named("capture"),
		captureDir: dir,
		active:     make(map[uuid.UUID]*activeCapture),
		tcpdump:    "", // not available
	}
	return svc
}

// ---------------------------------------------------------------------------
// NewService
// ---------------------------------------------------------------------------

func TestNewService(t *testing.T) {
	repo := newMockCaptureRepo()
	log := testLogger(t)
	dir := testCaptureDir(t)

	svc := NewService(repo, dir, log)
	if svc == nil {
		t.Fatal("NewService returned nil")
	}
	if svc.repo != repo {
		t.Error("repo not set")
	}
	if svc.captureDir != dir {
		t.Errorf("captureDir = %q, want %q", svc.captureDir, dir)
	}
	if svc.active == nil {
		t.Error("active map not initialized")
	}
}

func TestNewService_CreatesDir(t *testing.T) {
	repo := newMockCaptureRepo()
	log := testLogger(t)
	dir := filepath.Join(t.TempDir(), "nested", "captures")

	svc := NewService(repo, dir, log)
	if svc == nil {
		t.Fatal("NewService returned nil")
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("capture directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("capture path is not a directory")
	}
}

// ---------------------------------------------------------------------------
// Available
// ---------------------------------------------------------------------------

func TestAvailable_NoTcpdump(t *testing.T) {
	svc := newTestService(t, newMockCaptureRepo())
	if svc.Available() {
		t.Error("Available() = true, want false when tcpdump path is empty")
	}
}

func TestAvailable_WithTcpdump(t *testing.T) {
	svc := newTestService(t, newMockCaptureRepo())
	svc.tcpdump = "/usr/bin/tcpdump"
	if !svc.Available() {
		t.Error("Available() = false, want true when tcpdump path is set")
	}
}

// ---------------------------------------------------------------------------
// StartCapture — tcpdump unavailable
// ---------------------------------------------------------------------------

func TestStartCapture_NoTcpdump(t *testing.T) {
	svc := newTestService(t, newMockCaptureRepo())
	userID := uuid.New()
	input := models.CreateCaptureInput{
		Name:      "test",
		Interface: "eth0",
	}

	_, err := svc.StartCapture(context.Background(), userID, input)
	if err == nil {
		t.Fatal("expected error when tcpdump is unavailable")
	}
	if got := err.Error(); got == "" {
		t.Error("error message is empty")
	}
}

// ---------------------------------------------------------------------------
// GetCapture
// ---------------------------------------------------------------------------

func TestGetCapture_Success(t *testing.T) {
	repo := newMockCaptureRepo()
	svc := newTestService(t, repo)

	id := uuid.New()
	repo.captures[id] = &models.PacketCapture{
		ID:        id,
		UserID:    uuid.New(),
		Name:      "test-capture",
		Interface: "eth0",
		Status:    models.CaptureStatusCompleted,
		FilePath:  "/nonexistent/path.pcap",
	}

	capture, err := svc.GetCapture(context.Background(), id)
	if err != nil {
		t.Fatalf("GetCapture error: %v", err)
	}
	if capture.Name != "test-capture" {
		t.Errorf("Name = %q, want %q", capture.Name, "test-capture")
	}
	if capture.Interface != "eth0" {
		t.Errorf("Interface = %q, want %q", capture.Interface, "eth0")
	}
}

func TestGetCapture_NotFound(t *testing.T) {
	repo := newMockCaptureRepo()
	svc := newTestService(t, repo)

	_, err := svc.GetCapture(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected error for non-existent capture")
	}
}

func TestGetCapture_RepoError(t *testing.T) {
	repo := newMockCaptureRepo()
	repo.getErr = fmt.Errorf("database connection lost")
	svc := newTestService(t, repo)

	_, err := svc.GetCapture(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected error from repo failure")
	}
}

func TestGetCapture_RunningUpdatesFileSize(t *testing.T) {
	repo := newMockCaptureRepo()
	svc := newTestService(t, repo)

	// Create a real temp file to get a valid file size
	tmpFile := filepath.Join(svc.captureDir, "test.pcap")
	if err := os.WriteFile(tmpFile, []byte("fake pcap data here"), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	id := uuid.New()
	repo.captures[id] = &models.PacketCapture{
		ID:       id,
		Status:   models.CaptureStatusRunning,
		FilePath: tmpFile,
		FileSize: 0,
	}

	capture, err := svc.GetCapture(context.Background(), id)
	if err != nil {
		t.Fatalf("GetCapture error: %v", err)
	}
	if capture.FileSize == 0 {
		t.Error("expected FileSize to be updated for running capture with existing file")
	}
}

func TestGetCapture_RunningMissingFile(t *testing.T) {
	repo := newMockCaptureRepo()
	svc := newTestService(t, repo)

	id := uuid.New()
	repo.captures[id] = &models.PacketCapture{
		ID:       id,
		Status:   models.CaptureStatusRunning,
		FilePath: "/nonexistent/missing.pcap",
		FileSize: 0,
	}

	capture, err := svc.GetCapture(context.Background(), id)
	if err != nil {
		t.Fatalf("GetCapture error: %v", err)
	}
	// FileSize should remain 0 when file does not exist
	if capture.FileSize != 0 {
		t.Errorf("FileSize = %d, want 0 for missing file", capture.FileSize)
	}
}

// ---------------------------------------------------------------------------
// ListCaptures
// ---------------------------------------------------------------------------

func TestListCaptures_Success(t *testing.T) {
	repo := newMockCaptureRepo()
	svc := newTestService(t, repo)

	userID := uuid.New()
	otherUser := uuid.New()

	repo.captures[uuid.New()] = &models.PacketCapture{
		ID:     uuid.New(),
		UserID: userID,
		Name:   "capture-1",
		Status: models.CaptureStatusCompleted,
	}
	repo.captures[uuid.New()] = &models.PacketCapture{
		ID:     uuid.New(),
		UserID: userID,
		Name:   "capture-2",
		Status: models.CaptureStatusStopped,
	}
	repo.captures[uuid.New()] = &models.PacketCapture{
		ID:     uuid.New(),
		UserID: otherUser,
		Name:   "other-capture",
		Status: models.CaptureStatusCompleted,
	}

	captures, err := svc.ListCaptures(context.Background(), userID)
	if err != nil {
		t.Fatalf("ListCaptures error: %v", err)
	}
	if len(captures) != 2 {
		t.Errorf("got %d captures, want 2", len(captures))
	}
}

func TestListCaptures_Empty(t *testing.T) {
	repo := newMockCaptureRepo()
	svc := newTestService(t, repo)

	captures, err := svc.ListCaptures(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("ListCaptures error: %v", err)
	}
	if len(captures) != 0 {
		t.Errorf("got %d captures, want 0", len(captures))
	}
}

func TestListCaptures_RepoError(t *testing.T) {
	repo := newMockCaptureRepo()
	repo.listErr = fmt.Errorf("list failed")
	svc := newTestService(t, repo)

	_, err := svc.ListCaptures(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected error from repo failure")
	}
}

func TestListCaptures_UpdatesRunningFileSizes(t *testing.T) {
	repo := newMockCaptureRepo()
	svc := newTestService(t, repo)

	tmpFile := filepath.Join(svc.captureDir, "running.pcap")
	if err := os.WriteFile(tmpFile, []byte("some pcap bytes"), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	userID := uuid.New()
	id := uuid.New()
	repo.captures[id] = &models.PacketCapture{
		ID:       id,
		UserID:   userID,
		Status:   models.CaptureStatusRunning,
		FilePath: tmpFile,
		FileSize: 0,
	}

	captures, err := svc.ListCaptures(context.Background(), userID)
	if err != nil {
		t.Fatalf("ListCaptures error: %v", err)
	}
	if len(captures) != 1 {
		t.Fatalf("got %d captures, want 1", len(captures))
	}
	if captures[0].FileSize == 0 {
		t.Error("expected FileSize to be updated for running capture")
	}
}

// ---------------------------------------------------------------------------
// StopCapture
// ---------------------------------------------------------------------------

func TestStopCapture_NotActive(t *testing.T) {
	repo := newMockCaptureRepo()
	svc := newTestService(t, repo)

	id := uuid.New()
	repo.captures[id] = &models.PacketCapture{
		ID:     id,
		Status: models.CaptureStatusRunning,
	}

	err := svc.StopCapture(context.Background(), id)
	if err != nil {
		t.Fatalf("StopCapture error: %v", err)
	}

	c := repo.captures[id]
	if c.Status != models.CaptureStatusStopped {
		t.Errorf("Status = %q, want %q", c.Status, models.CaptureStatusStopped)
	}
}

func TestStopCapture_Active(t *testing.T) {
	repo := newMockCaptureRepo()
	svc := newTestService(t, repo)

	id := uuid.New()
	cancelled := false
	ac := &activeCapture{
		ID:     id,
		cancel: func() { cancelled = true },
	}
	svc.mu.Lock()
	svc.active[id] = ac
	svc.mu.Unlock()

	err := svc.StopCapture(context.Background(), id)
	if err != nil {
		t.Fatalf("StopCapture error: %v", err)
	}
	if !cancelled {
		t.Error("expected cancel to be called for active capture")
	}
}

// ---------------------------------------------------------------------------
// DeleteCapture
// ---------------------------------------------------------------------------

func TestDeleteCapture_Success(t *testing.T) {
	repo := newMockCaptureRepo()
	svc := newTestService(t, repo)

	// Create a temp file to be deleted
	tmpFile := filepath.Join(svc.captureDir, "delete-me.pcap")
	if err := os.WriteFile(tmpFile, []byte("data"), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	id := uuid.New()
	repo.captures[id] = &models.PacketCapture{
		ID:       id,
		Status:   models.CaptureStatusCompleted,
		FilePath: tmpFile,
	}

	err := svc.DeleteCapture(context.Background(), id)
	if err != nil {
		t.Fatalf("DeleteCapture error: %v", err)
	}

	// Capture should be removed from repo
	if _, exists := repo.captures[id]; exists {
		t.Error("capture still exists in repo after delete")
	}

	// File should be removed
	if _, err := os.Stat(tmpFile); !os.IsNotExist(err) {
		t.Error("pcap file not deleted")
	}
}

func TestDeleteCapture_NotFound(t *testing.T) {
	repo := newMockCaptureRepo()
	svc := newTestService(t, repo)

	err := svc.DeleteCapture(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected error for non-existent capture")
	}
}

func TestDeleteCapture_RepoDeleteError(t *testing.T) {
	repo := newMockCaptureRepo()
	repo.deleteErr = fmt.Errorf("delete failed")
	svc := newTestService(t, repo)

	id := uuid.New()
	repo.captures[id] = &models.PacketCapture{
		ID:       id,
		Status:   models.CaptureStatusCompleted,
		FilePath: "",
	}

	err := svc.DeleteCapture(context.Background(), id)
	if err == nil {
		t.Fatal("expected error from repo delete failure")
	}
}

func TestDeleteCapture_EmptyFilePath(t *testing.T) {
	repo := newMockCaptureRepo()
	svc := newTestService(t, repo)

	id := uuid.New()
	repo.captures[id] = &models.PacketCapture{
		ID:       id,
		Status:   models.CaptureStatusCompleted,
		FilePath: "",
	}

	err := svc.DeleteCapture(context.Background(), id)
	if err != nil {
		t.Fatalf("DeleteCapture error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetPcapPath
// ---------------------------------------------------------------------------

func TestGetPcapPath_Success(t *testing.T) {
	repo := newMockCaptureRepo()
	svc := newTestService(t, repo)

	tmpFile := filepath.Join(svc.captureDir, "existing.pcap")
	if err := os.WriteFile(tmpFile, []byte("pcap"), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	id := uuid.New()
	repo.captures[id] = &models.PacketCapture{
		ID:       id,
		FilePath: tmpFile,
	}

	path, err := svc.GetPcapPath(context.Background(), id)
	if err != nil {
		t.Fatalf("GetPcapPath error: %v", err)
	}
	if path != tmpFile {
		t.Errorf("path = %q, want %q", path, tmpFile)
	}
}

func TestGetPcapPath_NotFound(t *testing.T) {
	repo := newMockCaptureRepo()
	svc := newTestService(t, repo)

	_, err := svc.GetPcapPath(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected error for non-existent capture")
	}
}

func TestGetPcapPath_EmptyPath(t *testing.T) {
	repo := newMockCaptureRepo()
	svc := newTestService(t, repo)

	id := uuid.New()
	repo.captures[id] = &models.PacketCapture{
		ID:       id,
		FilePath: "",
	}

	_, err := svc.GetPcapPath(context.Background(), id)
	if err == nil {
		t.Fatal("expected error for empty file path")
	}
}

func TestGetPcapPath_FileDoesNotExist(t *testing.T) {
	repo := newMockCaptureRepo()
	svc := newTestService(t, repo)

	id := uuid.New()
	repo.captures[id] = &models.PacketCapture{
		ID:       id,
		FilePath: "/nonexistent/path.pcap",
	}

	_, err := svc.GetPcapPath(context.Background(), id)
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

// ---------------------------------------------------------------------------
// AnalyzeCapture — tcpdump unavailable
// ---------------------------------------------------------------------------

func TestAnalyzeCapture_NoTcpdump(t *testing.T) {
	repo := newMockCaptureRepo()
	svc := newTestService(t, repo)

	_, err := svc.AnalyzeCapture(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected error when tcpdump is unavailable")
	}
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

func TestCleanup_CancelsAllActive(t *testing.T) {
	repo := newMockCaptureRepo()
	svc := newTestService(t, repo)

	cancelled := make([]uuid.UUID, 0)
	for i := 0; i < 3; i++ {
		id := uuid.New()
		ac := &activeCapture{
			ID:     id,
			cancel: func() { cancelled = append(cancelled, id) },
		}
		svc.active[id] = ac
	}

	svc.Cleanup()

	if len(cancelled) != 3 {
		t.Errorf("cancelled %d captures, want 3", len(cancelled))
	}
}

func TestCleanup_Empty(t *testing.T) {
	svc := newTestService(t, newMockCaptureRepo())
	// Should not panic with no active captures
	svc.Cleanup()
}

// ---------------------------------------------------------------------------
// parseAddress (pure function)
// ---------------------------------------------------------------------------

func TestParseAddress(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantIP   string
		wantFull string
	}{
		{
			name:     "ipv4 with port",
			raw:      "192.168.1.1.443",
			wantIP:   "192.168.1.1",
			wantFull: "192.168.1.1:443",
		},
		{
			name:     "ipv4 with port and trailing colon",
			raw:      "10.0.0.1.8080:",
			wantIP:   "10.0.0.1",
			wantFull: "10.0.0.1:8080",
		},
		{
			name:     "ipv4 with port and trailing comma",
			raw:      "172.16.0.5.22,",
			wantIP:   "172.16.0.5",
			wantFull: "172.16.0.5:22",
		},
		{
			name:     "empty string",
			raw:      "",
			wantIP:   "",
			wantFull: "",
		},
		{
			name:     "no dot at all",
			raw:      "localhost",
			wantIP:   "localhost",
			wantFull: "localhost",
		},
		{
			name:     "non-numeric after last dot",
			raw:      "some.hostname.local",
			wantIP:   "some.hostname.local",
			wantFull: "some.hostname.local",
		},
		{
			name:     "single dot with port",
			raw:      "host.80",
			wantIP:   "host",
			wantFull: "host:80",
		},
		{
			name:     "trailing colon only",
			raw:      "192.168.1.1.443:",
			wantIP:   "192.168.1.1",
			wantFull: "192.168.1.1:443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIP, gotFull := parseAddress(tt.raw)
			if gotIP != tt.wantIP {
				t.Errorf("parseAddress(%q) ip = %q, want %q", tt.raw, gotIP, tt.wantIP)
			}
			if gotFull != tt.wantFull {
				t.Errorf("parseAddress(%q) full = %q, want %q", tt.raw, gotFull, tt.wantFull)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ToCaptureSession (pure function)
// ---------------------------------------------------------------------------

func TestToCaptureSession_Completed(t *testing.T) {
	now := time.Now()
	stopped := now.Add(5 * time.Minute)
	c := &models.PacketCapture{
		ID:          uuid.New(),
		Name:        "test-session",
		Interface:   "eth0",
		Filter:      "port 80",
		Status:      models.CaptureStatusCompleted,
		PacketCount: 1234,
		FileSize:    56789,
		FilePath:    "/tmp/test.pcap",
		StartedAt:   now,
		StoppedAt:   &stopped,
	}

	view := ToCaptureSession(c)

	if view.ID != c.ID.String() {
		t.Errorf("ID = %q, want %q", view.ID, c.ID.String())
	}
	if view.Name != "test-session" {
		t.Errorf("Name = %q, want %q", view.Name, "test-session")
	}
	if view.Interface != "eth0" {
		t.Errorf("Interface = %q, want %q", view.Interface, "eth0")
	}
	if view.Filter != "port 80" {
		t.Errorf("Filter = %q, want %q", view.Filter, "port 80")
	}
	if view.Status != "completed" {
		t.Errorf("Status = %q, want %q", view.Status, "completed")
	}
	if view.PacketCount != 1234 {
		t.Errorf("PacketCount = %d, want %d", view.PacketCount, 1234)
	}
	if view.PcapFile != "/tmp/test.pcap" {
		t.Errorf("PcapFile = %q, want %q", view.PcapFile, "/tmp/test.pcap")
	}
	if view.StoppedAt == "" {
		t.Error("StoppedAt should not be empty for stopped capture")
	}
	if view.Duration != "00:05:00" {
		t.Errorf("Duration = %q, want %q", view.Duration, "00:05:00")
	}
}

func TestToCaptureSession_Running(t *testing.T) {
	c := &models.PacketCapture{
		ID:        uuid.New(),
		Name:      "running-session",
		Interface: "lo",
		Status:    models.CaptureStatusRunning,
		StartedAt: time.Now(),
		StoppedAt: nil,
	}

	view := ToCaptureSession(c)

	if view.Status != "running" {
		t.Errorf("Status = %q, want %q", view.Status, "running")
	}
	if view.StoppedAt != "" {
		t.Errorf("StoppedAt = %q, want empty for running capture", view.StoppedAt)
	}
}

func TestToCaptureSession_NoStoppedAt(t *testing.T) {
	c := &models.PacketCapture{
		ID:        uuid.New(),
		Name:      "error-session",
		Status:    models.CaptureStatusError,
		StartedAt: time.Now(),
		StoppedAt: nil,
	}

	view := ToCaptureSession(c)

	if view.StoppedAt != "" {
		t.Errorf("StoppedAt = %q, want empty when StoppedAt is nil", view.StoppedAt)
	}
	// Duration should be 00:00:00 since status is not running and no StoppedAt
	if view.Duration != "00:00:00" {
		t.Errorf("Duration = %q, want %q", view.Duration, "00:00:00")
	}
}
