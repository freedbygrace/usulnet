// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package license

import (
	"os"
	"path/filepath"
	"testing"
)

// ============================================================================
// NewStore
// ============================================================================

func TestNewStore(t *testing.T) {
	store := NewStore("/app/data")
	want := filepath.Join("/app/data", "license.jwt")
	if store.Path() != want {
		t.Errorf("Path() = %q, want %q", store.Path(), want)
	}
}

func TestNewStore_TrailingSlash(t *testing.T) {
	store := NewStore("/app/data/")
	// filepath.Join normalizes trailing slashes
	want := filepath.Join("/app/data/", "license.jwt")
	if store.Path() != want {
		t.Errorf("Path() = %q, want %q", store.Path(), want)
	}
}

// ============================================================================
// Save + Load round-trip
// ============================================================================

func TestStore_SaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	testJWT := "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.test.payload"

	// Save
	if err := store.Save(testJWT); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Load
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if got != testJWT {
		t.Errorf("Load() = %q, want %q", got, testJWT)
	}
}

func TestStore_SaveCreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "nested", "deep")
	store := NewStore(nested)

	if err := store.Save("test-jwt"); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Verify directory was created
	info, err := os.Stat(nested)
	if err != nil {
		t.Fatalf("parent dir not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("parent path is not a directory")
	}
}

func TestStore_SaveFilePermissions(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	if err := store.Save("test-jwt"); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	info, err := os.Stat(store.Path())
	if err != nil {
		t.Fatalf("Stat() error: %v", err)
	}

	// File should be 0600 (owner read/write only)
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("file permissions = %o, want 0600", perm)
	}
}

func TestStore_SaveOverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	// Save first JWT
	if err := store.Save("first-jwt"); err != nil {
		t.Fatalf("first Save() error: %v", err)
	}

	// Overwrite with second JWT
	if err := store.Save("second-jwt"); err != nil {
		t.Fatalf("second Save() error: %v", err)
	}

	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if got != "second-jwt" {
		t.Errorf("Load() = %q, want %q", got, "second-jwt")
	}
}

// ============================================================================
// Load
// ============================================================================

func TestStore_LoadNonExistentFile(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	// Load from non-existent file should return empty string, nil error (CE default)
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() non-existent error: %v", err)
	}
	if got != "" {
		t.Errorf("Load() non-existent = %q, want empty", got)
	}
}

func TestStore_LoadTrimsWhitespace(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	// Write file with extra whitespace
	path := store.Path()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatalf("mkdir error: %v", err)
	}
	if err := os.WriteFile(path, []byte("  jwt-with-whitespace  \n\n"), 0600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if got != "jwt-with-whitespace" {
		t.Errorf("Load() = %q, want %q", got, "jwt-with-whitespace")
	}
}

// ============================================================================
// Remove
// ============================================================================

func TestStore_Remove(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	// Save then remove
	if err := store.Save("to-remove"); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	if err := store.Remove(); err != nil {
		t.Fatalf("Remove() error: %v", err)
	}

	// File should be gone
	if _, err := os.Stat(store.Path()); !os.IsNotExist(err) {
		t.Error("file still exists after Remove()")
	}

	// Load should return empty (CE default)
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() after Remove() error: %v", err)
	}
	if got != "" {
		t.Errorf("Load() after Remove() = %q, want empty", got)
	}
}

func TestStore_RemoveNonExistent(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	// Remove non-existent file should not error (idempotent)
	if err := store.Remove(); err != nil {
		t.Errorf("Remove() non-existent error: %v", err)
	}
}

func TestStore_RemoveIdempotent(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	if err := store.Save("test"); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Remove twice should not error
	if err := store.Remove(); err != nil {
		t.Fatalf("first Remove() error: %v", err)
	}
	if err := store.Remove(); err != nil {
		t.Errorf("second Remove() error: %v", err)
	}
}

// ============================================================================
// Path
// ============================================================================

func TestStore_Path(t *testing.T) {
	store := NewStore("/custom/path")
	want := filepath.Join("/custom/path", "license.jwt")
	if store.Path() != want {
		t.Errorf("Path() = %q, want %q", store.Path(), want)
	}
}
