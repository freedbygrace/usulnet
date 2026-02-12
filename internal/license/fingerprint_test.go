// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package license

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ============================================================================
// GenerateInstanceID
// ============================================================================

func TestGenerateInstanceID(t *testing.T) {
	dir := t.TempDir()

	id, err := GenerateInstanceID(dir)
	if err != nil {
		t.Fatalf("GenerateInstanceID() error: %v", err)
	}

	// Should be a 32-char hex string (16 bytes = 32 hex chars)
	if len(id) != 32 {
		t.Errorf("instance ID length = %d, want 32", len(id))
	}

	// Should only contain hex characters
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("instance ID contains non-hex char: %c", c)
			break
		}
	}
}

func TestGenerateInstanceID_Deterministic(t *testing.T) {
	dir := t.TempDir()

	id1, err := GenerateInstanceID(dir)
	if err != nil {
		t.Fatalf("first GenerateInstanceID() error: %v", err)
	}

	id2, err := GenerateInstanceID(dir)
	if err != nil {
		t.Fatalf("second GenerateInstanceID() error: %v", err)
	}

	// Same data directory should produce the same ID (deterministic)
	if id1 != id2 {
		t.Errorf("non-deterministic: id1=%q, id2=%q", id1, id2)
	}
}

func TestGenerateInstanceID_DifferentDirs(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	id1, err := GenerateInstanceID(dir1)
	if err != nil {
		t.Fatalf("GenerateInstanceID(dir1) error: %v", err)
	}

	id2, err := GenerateInstanceID(dir2)
	if err != nil {
		t.Fatalf("GenerateInstanceID(dir2) error: %v", err)
	}

	// Different data directories should produce different IDs (different salt)
	if id1 == id2 {
		t.Error("different dirs produced same instance ID")
	}
}

func TestGenerateInstanceID_CreatesSaltFile(t *testing.T) {
	dir := t.TempDir()

	_, err := GenerateInstanceID(dir)
	if err != nil {
		t.Fatalf("GenerateInstanceID() error: %v", err)
	}

	saltPath := filepath.Join(dir, ".instance-salt")
	info, err := os.Stat(saltPath)
	if err != nil {
		t.Fatalf("salt file not created: %v", err)
	}

	// Salt file should be 0600 (owner read/write only)
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("salt file permissions = %o, want 0600", perm)
	}

	// Salt should be at least 32 bytes of hex (64 chars + newline)
	data, err := os.ReadFile(saltPath)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	salt := strings.TrimSpace(string(data))
	if len(salt) < 64 {
		t.Errorf("salt length = %d, want >= 64 hex chars", len(salt))
	}
}

func TestGenerateInstanceID_PersistsSalt(t *testing.T) {
	dir := t.TempDir()
	saltPath := filepath.Join(dir, ".instance-salt")

	// Generate first ID (creates salt)
	id1, err := GenerateInstanceID(dir)
	if err != nil {
		t.Fatalf("first GenerateInstanceID() error: %v", err)
	}

	// Read salt
	salt1, err := os.ReadFile(saltPath)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	// Generate second ID (reuses salt)
	id2, err := GenerateInstanceID(dir)
	if err != nil {
		t.Fatalf("second GenerateInstanceID() error: %v", err)
	}

	salt2, err := os.ReadFile(saltPath)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	// Salt should not change between calls
	if string(salt1) != string(salt2) {
		t.Error("salt changed between calls")
	}

	// And IDs should match
	if id1 != id2 {
		t.Errorf("IDs differ: %q != %q", id1, id2)
	}
}

func TestGenerateInstanceID_CreatesNestedDir(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "deep", "nested", "path")

	_, err := GenerateInstanceID(nested)
	if err != nil {
		t.Fatalf("GenerateInstanceID() with nested dir error: %v", err)
	}

	// Parent directory should have been created
	if _, err := os.Stat(nested); err != nil {
		t.Errorf("nested directory not created: %v", err)
	}
}

// ============================================================================
// getOrCreateSalt (internal)
// ============================================================================

func TestGetOrCreateSalt_NewSalt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".instance-salt")

	salt, err := getOrCreateSalt(path)
	if err != nil {
		t.Fatalf("getOrCreateSalt() error: %v", err)
	}

	if salt == "" {
		t.Error("salt is empty")
	}

	// Salt should be hex-encoded 32 bytes = 64 chars
	if len(salt) != 64 {
		t.Errorf("salt length = %d, want 64", len(salt))
	}
}

func TestGetOrCreateSalt_ExistingSalt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".instance-salt")

	// Write a known salt
	knownSalt := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	if err := os.WriteFile(path, []byte(knownSalt+"\n"), 0600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	salt, err := getOrCreateSalt(path)
	if err != nil {
		t.Fatalf("getOrCreateSalt() error: %v", err)
	}

	if salt != knownSalt {
		t.Errorf("salt = %q, want %q", salt, knownSalt)
	}
}

func TestGetOrCreateSalt_ShortSaltRegenerates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".instance-salt")

	// Write a short salt (< 32 bytes)
	if err := os.WriteFile(path, []byte("short"), 0600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	salt, err := getOrCreateSalt(path)
	if err != nil {
		t.Fatalf("getOrCreateSalt() error: %v", err)
	}

	// Should generate a new salt since the existing one was too short
	if salt == "short" {
		t.Error("short salt was not regenerated")
	}
	if len(salt) < 64 {
		t.Errorf("regenerated salt too short: %d chars", len(salt))
	}
}
