// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package recording

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Repository defines the data layer contract for recording configs.
type Repository interface {
	IsRecordingEnabled(ctx context.Context, userID uuid.UUID) (bool, int, error)
	UpdateRecordingMeta(ctx context.Context, sessionID uuid.UUID, path string, size int64) error
}

// Writer handles writing terminal output to an asciicast v2 file.
type Writer struct {
	mu        sync.Mutex
	file      *os.File
	gz        *gzip.Writer
	enc       *json.Encoder
	startTime time.Time
	closed    bool
	path      string
}

// Service manages session recordings.
type Service struct {
	recordDir string
	repo      Repository
	logger    *logger.Logger
}

// NewService creates a recording service.
func NewService(recordDir string, repo Repository, log *logger.Logger) *Service {
	if err := os.MkdirAll(recordDir, 0750); err != nil {
		log.Error("failed to create recording directory", "path", recordDir, "error", err)
	}
	return &Service{
		recordDir: recordDir,
		logger:    log.Named("recording"),
		repo:      repo,
	}
}

// Available returns whether the recording directory is writable.
func (s *Service) Available() bool {
	info, err := os.Stat(s.recordDir)
	return err == nil && info.IsDir()
}

// StartRecording creates a new recording writer for a session.
func (s *Service) StartRecording(sessionID uuid.UUID, cols, rows int) (*Writer, error) {
	filename := fmt.Sprintf("%s.cast.gz", sessionID.String())
	path := filepath.Join(s.recordDir, filename)

	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create recording file: %w", err)
	}

	gz := gzip.NewWriter(f)
	enc := json.NewEncoder(gz)

	// Write asciicast v2 header
	header := map[string]interface{}{
		"version":   2,
		"width":     cols,
		"height":    rows,
		"timestamp": time.Now().Unix(),
		"env": map[string]string{
			"TERM": "xterm-256color",
		},
	}
	if err := enc.Encode(header); err != nil {
		gz.Close()
		f.Close()
		os.Remove(path)
		return nil, fmt.Errorf("write header: %w", err)
	}

	return &Writer{
		file:      f,
		gz:        gz,
		enc:       enc,
		startTime: time.Now(),
		path:      path,
	}, nil
}

// WriteOutput records terminal output data.
func (w *Writer) WriteOutput(data []byte) {
	if len(data) == 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}

	elapsed := time.Since(w.startTime).Seconds()
	// asciicast v2 event: [time, type, data]
	event := []interface{}{elapsed, "o", string(data)}
	_ = w.enc.Encode(event)
}

// WriteInput records terminal input data (optional, for full recording).
func (w *Writer) WriteInput(data []byte) {
	if len(data) == 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}

	elapsed := time.Since(w.startTime).Seconds()
	event := []interface{}{elapsed, "i", string(data)}
	_ = w.enc.Encode(event)
}

// WriteResize records a terminal resize event.
func (w *Writer) WriteResize(cols, rows int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}

	elapsed := time.Since(w.startTime).Seconds()
	event := []interface{}{elapsed, "r", fmt.Sprintf("%dx%d", cols, rows)}
	_ = w.enc.Encode(event)
}

// Close finalizes the recording and returns the file path and size.
func (w *Writer) Close() (string, int64, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return w.path, 0, nil
	}
	w.closed = true

	if err := w.gz.Close(); err != nil {
		w.file.Close()
		return w.path, 0, fmt.Errorf("close gzip: %w", err)
	}
	if err := w.file.Close(); err != nil {
		return w.path, 0, fmt.Errorf("close file: %w", err)
	}

	info, err := os.Stat(w.path)
	if err != nil {
		return w.path, 0, nil
	}
	return w.path, info.Size(), nil
}

// Path returns the file path.
func (w *Writer) Path() string {
	return w.path
}

// GetRecordingPath returns the full path for a session recording.
func (s *Service) GetRecordingPath(sessionID uuid.UUID) string {
	return filepath.Join(s.recordDir, fmt.Sprintf("%s.cast.gz", sessionID.String()))
}

// DeleteRecording removes a recording file from disk.
func (s *Service) DeleteRecording(sessionID uuid.UUID) error {
	path := s.GetRecordingPath(sessionID)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete recording: %w", err)
	}
	return nil
}

// CleanupExpiredRecordings removes recording files that have been cleared from DB.
func (s *Service) CleanupExpiredRecordings(paths []string) int {
	count := 0
	for _, p := range paths {
		if err := os.Remove(p); err == nil {
			count++
		}
	}
	return count
}
