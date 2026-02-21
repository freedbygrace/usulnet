// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package recording

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ---------------------------------------------------------------------------
// Mock repository
// ---------------------------------------------------------------------------

type mockRecordingRepo struct {
	enabled     bool
	maxDuration int
	enabledErr  error
	updateErr   error

	updatedSessionID uuid.UUID
	updatedPath      string
	updatedSize      int64
}

func (r *mockRecordingRepo) IsRecordingEnabled(_ context.Context, _ uuid.UUID) (bool, int, error) {
	if r.enabledErr != nil {
		return false, 0, r.enabledErr
	}
	return r.enabled, r.maxDuration, nil
}

func (r *mockRecordingRepo) UpdateRecordingMeta(_ context.Context, sessionID uuid.UUID, path string, size int64) error {
	if r.updateErr != nil {
		return r.updateErr
	}
	r.updatedSessionID = sessionID
	r.updatedPath = path
	r.updatedSize = size
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

// ---------------------------------------------------------------------------
// NewService
// ---------------------------------------------------------------------------

func TestNewService(t *testing.T) {
	dir := t.TempDir()
	repo := &mockRecordingRepo{}
	log := testLogger(t)

	svc := NewService(dir, repo, log)
	if svc == nil {
		t.Fatal("NewService returned nil")
	}
	if svc.recordDir != dir {
		t.Errorf("recordDir = %q, want %q", svc.recordDir, dir)
	}
	if svc.repo != repo {
		t.Error("repo not set")
	}
}

func TestNewService_CreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "recordings")
	repo := &mockRecordingRepo{}
	log := testLogger(t)

	svc := NewService(dir, repo, log)
	if svc == nil {
		t.Fatal("NewService returned nil")
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("path is not a directory")
	}
}

// ---------------------------------------------------------------------------
// Available
// ---------------------------------------------------------------------------

func TestAvailable_ValidDir(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, &mockRecordingRepo{}, testLogger(t))

	if !svc.Available() {
		t.Error("Available() = false, want true for valid directory")
	}
}

func TestAvailable_InvalidDir(t *testing.T) {
	svc := &Service{
		recordDir: "/nonexistent/path/that/does/not/exist",
		logger:    testLogger(t).Named("recording"),
	}

	if svc.Available() {
		t.Error("Available() = true, want false for non-existent directory")
	}
}

// ---------------------------------------------------------------------------
// GetRecordingPath
// ---------------------------------------------------------------------------

func TestGetRecordingPath(t *testing.T) {
	dir := "/var/recordings"
	svc := &Service{recordDir: dir}

	sessionID := uuid.New()
	path := svc.GetRecordingPath(sessionID)

	expected := filepath.Join(dir, sessionID.String()+".cast.gz")
	if path != expected {
		t.Errorf("GetRecordingPath = %q, want %q", path, expected)
	}
}

// ---------------------------------------------------------------------------
// StartRecording
// ---------------------------------------------------------------------------

func TestStartRecording_Success(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, &mockRecordingRepo{}, testLogger(t))

	sessionID := uuid.New()
	w, err := svc.StartRecording(sessionID, 120, 40)
	if err != nil {
		t.Fatalf("StartRecording error: %v", err)
	}
	defer w.Close()

	if w == nil {
		t.Fatal("Writer is nil")
	}

	expectedPath := filepath.Join(dir, sessionID.String()+".cast.gz")
	if w.Path() != expectedPath {
		t.Errorf("Path() = %q, want %q", w.Path(), expectedPath)
	}

	// File should exist
	if _, err := os.Stat(expectedPath); err != nil {
		t.Fatalf("recording file not created: %v", err)
	}
}

func TestStartRecording_InvalidDir(t *testing.T) {
	svc := &Service{
		recordDir: "/nonexistent/impossible/path",
		logger:    testLogger(t).Named("recording"),
	}

	_, err := svc.StartRecording(uuid.New(), 80, 24)
	if err == nil {
		t.Fatal("expected error for invalid directory")
	}
}

func TestStartRecording_WritesValidHeader(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, &mockRecordingRepo{}, testLogger(t))

	sessionID := uuid.New()
	w, err := svc.StartRecording(sessionID, 132, 43)
	if err != nil {
		t.Fatalf("StartRecording error: %v", err)
	}

	path, _, err := w.Close()
	if err != nil {
		t.Fatalf("Close error: %v", err)
	}

	// Read and verify header
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open file: %v", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gz.Close()

	dec := json.NewDecoder(gz)
	var header map[string]interface{}
	if err := dec.Decode(&header); err != nil {
		t.Fatalf("decode header: %v", err)
	}

	if v, ok := header["version"]; !ok || v != float64(2) {
		t.Errorf("version = %v, want 2", v)
	}
	if v, ok := header["width"]; !ok || v != float64(132) {
		t.Errorf("width = %v, want 132", v)
	}
	if v, ok := header["height"]; !ok || v != float64(43) {
		t.Errorf("height = %v, want 43", v)
	}
	if _, ok := header["timestamp"]; !ok {
		t.Error("timestamp missing from header")
	}
}

// ---------------------------------------------------------------------------
// Writer — WriteOutput
// ---------------------------------------------------------------------------

func TestWriteOutput_Data(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, &mockRecordingRepo{}, testLogger(t))

	w, err := svc.StartRecording(uuid.New(), 80, 24)
	if err != nil {
		t.Fatalf("StartRecording error: %v", err)
	}

	w.WriteOutput([]byte("hello world"))
	w.WriteOutput([]byte("second line"))

	path, size, err := w.Close()
	if err != nil {
		t.Fatalf("Close error: %v", err)
	}
	if size == 0 {
		t.Error("file size is 0 after writing output")
	}

	// Verify events in the file
	events := readEvents(t, path)
	if len(events) < 2 {
		t.Fatalf("got %d output events, want at least 2", len(events))
	}

	for _, ev := range events {
		arr, ok := ev.([]interface{})
		if !ok {
			t.Fatalf("event is not an array: %T", ev)
		}
		if len(arr) != 3 {
			t.Fatalf("event has %d elements, want 3", len(arr))
		}
		if arr[1] != "o" {
			t.Errorf("event type = %q, want %q", arr[1], "o")
		}
	}
}

func TestWriteOutput_EmptyData(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, &mockRecordingRepo{}, testLogger(t))

	w, err := svc.StartRecording(uuid.New(), 80, 24)
	if err != nil {
		t.Fatalf("StartRecording error: %v", err)
	}

	// Writing empty data should be a no-op
	w.WriteOutput(nil)
	w.WriteOutput([]byte{})

	path, _, err := w.Close()
	if err != nil {
		t.Fatalf("Close error: %v", err)
	}

	events := readEvents(t, path)
	if len(events) != 0 {
		t.Errorf("got %d events, want 0 for empty writes", len(events))
	}
}

func TestWriteOutput_AfterClose(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, &mockRecordingRepo{}, testLogger(t))

	w, err := svc.StartRecording(uuid.New(), 80, 24)
	if err != nil {
		t.Fatalf("StartRecording error: %v", err)
	}

	w.Close()

	// Writing after close should not panic
	w.WriteOutput([]byte("should be ignored"))
}

// ---------------------------------------------------------------------------
// Writer — WriteInput
// ---------------------------------------------------------------------------

func TestWriteInput_Data(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, &mockRecordingRepo{}, testLogger(t))

	w, err := svc.StartRecording(uuid.New(), 80, 24)
	if err != nil {
		t.Fatalf("StartRecording error: %v", err)
	}

	w.WriteInput([]byte("ls -la"))

	path, _, err := w.Close()
	if err != nil {
		t.Fatalf("Close error: %v", err)
	}

	events := readEvents(t, path)
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}

	arr := events[0].([]interface{})
	if arr[1] != "i" {
		t.Errorf("event type = %q, want %q", arr[1], "i")
	}
	if arr[2] != "ls -la" {
		t.Errorf("event data = %q, want %q", arr[2], "ls -la")
	}
}

func TestWriteInput_EmptyData(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, &mockRecordingRepo{}, testLogger(t))

	w, err := svc.StartRecording(uuid.New(), 80, 24)
	if err != nil {
		t.Fatalf("StartRecording error: %v", err)
	}

	w.WriteInput(nil)
	w.WriteInput([]byte{})

	path, _, err := w.Close()
	if err != nil {
		t.Fatalf("Close error: %v", err)
	}

	events := readEvents(t, path)
	if len(events) != 0 {
		t.Errorf("got %d events, want 0", len(events))
	}
}

func TestWriteInput_AfterClose(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, &mockRecordingRepo{}, testLogger(t))

	w, err := svc.StartRecording(uuid.New(), 80, 24)
	if err != nil {
		t.Fatalf("StartRecording error: %v", err)
	}

	w.Close()
	w.WriteInput([]byte("ignored"))
}

// ---------------------------------------------------------------------------
// Writer — WriteResize
// ---------------------------------------------------------------------------

func TestWriteResize(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, &mockRecordingRepo{}, testLogger(t))

	w, err := svc.StartRecording(uuid.New(), 80, 24)
	if err != nil {
		t.Fatalf("StartRecording error: %v", err)
	}

	w.WriteResize(132, 43)

	path, _, err := w.Close()
	if err != nil {
		t.Fatalf("Close error: %v", err)
	}

	events := readEvents(t, path)
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}

	arr := events[0].([]interface{})
	if arr[1] != "r" {
		t.Errorf("event type = %q, want %q", arr[1], "r")
	}
	if arr[2] != "132x43" {
		t.Errorf("event data = %q, want %q", arr[2], "132x43")
	}
}

func TestWriteResize_AfterClose(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, &mockRecordingRepo{}, testLogger(t))

	w, err := svc.StartRecording(uuid.New(), 80, 24)
	if err != nil {
		t.Fatalf("StartRecording error: %v", err)
	}

	w.Close()
	w.WriteResize(100, 50) // should not panic
}

// ---------------------------------------------------------------------------
// Writer — Close
// ---------------------------------------------------------------------------

func TestClose_ReturnsPathAndSize(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, &mockRecordingRepo{}, testLogger(t))

	sessionID := uuid.New()
	w, err := svc.StartRecording(sessionID, 80, 24)
	if err != nil {
		t.Fatalf("StartRecording error: %v", err)
	}

	w.WriteOutput([]byte("some data"))

	path, size, err := w.Close()
	if err != nil {
		t.Fatalf("Close error: %v", err)
	}
	if path == "" {
		t.Error("path is empty")
	}
	if size <= 0 {
		t.Errorf("size = %d, want > 0", size)
	}
}

func TestClose_DoubleClose(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, &mockRecordingRepo{}, testLogger(t))

	w, err := svc.StartRecording(uuid.New(), 80, 24)
	if err != nil {
		t.Fatalf("StartRecording error: %v", err)
	}

	path1, _, err1 := w.Close()
	if err1 != nil {
		t.Fatalf("first Close error: %v", err1)
	}

	path2, size2, err2 := w.Close()
	if err2 != nil {
		t.Fatalf("second Close error: %v", err2)
	}
	if path2 != path1 {
		t.Errorf("second close path = %q, want %q", path2, path1)
	}
	if size2 != 0 {
		t.Errorf("second close size = %d, want 0", size2)
	}
}

// ---------------------------------------------------------------------------
// Writer — Path
// ---------------------------------------------------------------------------

func TestWriterPath(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, &mockRecordingRepo{}, testLogger(t))

	sessionID := uuid.New()
	w, err := svc.StartRecording(sessionID, 80, 24)
	if err != nil {
		t.Fatalf("StartRecording error: %v", err)
	}
	defer w.Close()

	expected := filepath.Join(dir, sessionID.String()+".cast.gz")
	if w.Path() != expected {
		t.Errorf("Path() = %q, want %q", w.Path(), expected)
	}
}

// ---------------------------------------------------------------------------
// Writer — Concurrent writes
// ---------------------------------------------------------------------------

func TestWriter_ConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, &mockRecordingRepo{}, testLogger(t))

	w, err := svc.StartRecording(uuid.New(), 80, 24)
	if err != nil {
		t.Fatalf("StartRecording error: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(3)
		go func(n int) {
			defer wg.Done()
			w.WriteOutput([]byte(fmt.Sprintf("output-%d", n)))
		}(i)
		go func(n int) {
			defer wg.Done()
			w.WriteInput([]byte(fmt.Sprintf("input-%d", n)))
		}(i)
		go func(n int) {
			defer wg.Done()
			w.WriteResize(80+n, 24+n)
		}(i)
	}
	wg.Wait()

	_, _, err = w.Close()
	if err != nil {
		t.Fatalf("Close error after concurrent writes: %v", err)
	}
}

// ---------------------------------------------------------------------------
// DeleteRecording
// ---------------------------------------------------------------------------

func TestDeleteRecording_Success(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, &mockRecordingRepo{}, testLogger(t))

	sessionID := uuid.New()
	w, err := svc.StartRecording(sessionID, 80, 24)
	if err != nil {
		t.Fatalf("StartRecording error: %v", err)
	}
	w.Close()

	err = svc.DeleteRecording(sessionID)
	if err != nil {
		t.Fatalf("DeleteRecording error: %v", err)
	}

	path := svc.GetRecordingPath(sessionID)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("recording file still exists after delete")
	}
}

func TestDeleteRecording_NotExists(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, &mockRecordingRepo{}, testLogger(t))

	// Deleting a non-existent recording should not error
	err := svc.DeleteRecording(uuid.New())
	if err != nil {
		t.Fatalf("DeleteRecording error for non-existent file: %v", err)
	}
}

// ---------------------------------------------------------------------------
// CleanupExpiredRecordings
// ---------------------------------------------------------------------------

func TestCleanupExpiredRecordings_DeletesExisting(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, &mockRecordingRepo{}, testLogger(t))

	// Create some files
	var paths []string
	for i := 0; i < 3; i++ {
		p := filepath.Join(dir, fmt.Sprintf("expired-%d.cast.gz", i))
		if err := os.WriteFile(p, []byte("data"), 0644); err != nil {
			t.Fatalf("write file: %v", err)
		}
		paths = append(paths, p)
	}

	count := svc.CleanupExpiredRecordings(paths)
	if count != 3 {
		t.Errorf("count = %d, want 3", count)
	}

	for _, p := range paths {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("file %s still exists", p)
		}
	}
}

func TestCleanupExpiredRecordings_MixedExistence(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, &mockRecordingRepo{}, testLogger(t))

	existing := filepath.Join(dir, "exists.cast.gz")
	if err := os.WriteFile(existing, []byte("data"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	paths := []string{
		existing,
		filepath.Join(dir, "nonexistent.cast.gz"),
	}

	count := svc.CleanupExpiredRecordings(paths)
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
}

func TestCleanupExpiredRecordings_EmptyList(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, &mockRecordingRepo{}, testLogger(t))

	count := svc.CleanupExpiredRecordings(nil)
	if count != 0 {
		t.Errorf("count = %d, want 0", count)
	}
}

// ---------------------------------------------------------------------------
// Mock repository contract tests
// ---------------------------------------------------------------------------

func TestRepository_IsRecordingEnabled(t *testing.T) {
	repo := &mockRecordingRepo{enabled: true, maxDuration: 3600}
	enabled, dur, err := repo.IsRecordingEnabled(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !enabled {
		t.Error("enabled = false, want true")
	}
	if dur != 3600 {
		t.Errorf("maxDuration = %d, want 3600", dur)
	}
}

func TestRepository_IsRecordingEnabled_Error(t *testing.T) {
	repo := &mockRecordingRepo{enabledErr: fmt.Errorf("db error")}
	_, _, err := repo.IsRecordingEnabled(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRepository_UpdateRecordingMeta(t *testing.T) {
	repo := &mockRecordingRepo{}
	sessionID := uuid.New()
	err := repo.UpdateRecordingMeta(context.Background(), sessionID, "/path/to/file", 12345)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if repo.updatedSessionID != sessionID {
		t.Error("sessionID not recorded")
	}
	if repo.updatedPath != "/path/to/file" {
		t.Errorf("path = %q, want %q", repo.updatedPath, "/path/to/file")
	}
	if repo.updatedSize != 12345 {
		t.Errorf("size = %d, want 12345", repo.updatedSize)
	}
}

func TestRepository_UpdateRecordingMeta_Error(t *testing.T) {
	repo := &mockRecordingRepo{updateErr: fmt.Errorf("db error")}
	err := repo.UpdateRecordingMeta(context.Background(), uuid.New(), "/path", 0)
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// Mixed event types
// ---------------------------------------------------------------------------

func TestWriter_MixedEventTypes(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, &mockRecordingRepo{}, testLogger(t))

	w, err := svc.StartRecording(uuid.New(), 80, 24)
	if err != nil {
		t.Fatalf("StartRecording error: %v", err)
	}

	w.WriteOutput([]byte("$ ls"))
	w.WriteInput([]byte("ls"))
	w.WriteResize(120, 40)
	w.WriteOutput([]byte("file1 file2"))

	path, _, err := w.Close()
	if err != nil {
		t.Fatalf("Close error: %v", err)
	}

	events := readEvents(t, path)
	if len(events) != 4 {
		t.Fatalf("got %d events, want 4", len(events))
	}

	// Verify event types in order
	expectedTypes := []string{"o", "i", "r", "o"}
	for i, ev := range events {
		arr := ev.([]interface{})
		if arr[1] != expectedTypes[i] {
			t.Errorf("event[%d] type = %q, want %q", i, arr[1], expectedTypes[i])
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// readEvents reads all events (excluding the header) from a cast.gz file.
func readEvents(t *testing.T, path string) []interface{} {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open file %s: %v", path, err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gz.Close()

	data, err := io.ReadAll(gz)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 {
		t.Fatal("no lines in recording file")
	}

	// First line is the header, skip it
	var events []interface{}
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		var ev interface{}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("unmarshal event %q: %v", line, err)
		}
		events = append(events, ev)
	}
	return events
}
