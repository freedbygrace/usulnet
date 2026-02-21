// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package image

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"testing"

	"github.com/fr4nsys/usulnet/internal/models"
	apperrors "github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ---------------------------------------------------------------------------
// NewService tests
// ---------------------------------------------------------------------------

func TestNewService_NilLogger(t *testing.T) {
	svc := NewService(nil, nil)
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestNewService_WithLogger(t *testing.T) {
	log, _ := logger.NewWithOutput("error", "console", io.Discard)
	svc := NewService(nil, log)
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

// ---------------------------------------------------------------------------
// encodeAuth tests
// ---------------------------------------------------------------------------

func TestEncodeAuth_Nil(t *testing.T) {
	result := encodeAuth(nil)
	if result != "" {
		t.Errorf("encodeAuth(nil) = %q, want empty", result)
	}
}

func TestEncodeAuth_WithCredentials(t *testing.T) {
	auth := &models.RegistryAuthConfig{
		Username:      "user",
		Password:      "pass",
		ServerAddress: "registry.example.com",
	}

	result := encodeAuth(auth)
	if result == "" {
		t.Fatal("encodeAuth() returned empty string")
	}

	// Decode and verify
	decoded, err := base64.URLEncoding.DecodeString(result)
	if err != nil {
		t.Fatalf("base64 decode error: %v", err)
	}

	var parsed struct {
		Username      string `json:"username"`
		Password      string `json:"password"`
		ServerAddress string `json:"serveraddress"`
	}
	if err := json.Unmarshal(decoded, &parsed); err != nil {
		t.Fatalf("json unmarshal error: %v", err)
	}

	if parsed.Username != "user" {
		t.Errorf("Username = %q, want %q", parsed.Username, "user")
	}
	if parsed.Password != "pass" {
		t.Errorf("Password = %q, want %q", parsed.Password, "pass")
	}
	if parsed.ServerAddress != "registry.example.com" {
		t.Errorf("ServerAddress = %q, want %q", parsed.ServerAddress, "registry.example.com")
	}
}

func TestEncodeAuth_EmptyFields(t *testing.T) {
	auth := &models.RegistryAuthConfig{}
	result := encodeAuth(auth)
	if result == "" {
		t.Fatal("encodeAuth() should return non-empty even for empty fields")
	}

	decoded, err := base64.URLEncoding.DecodeString(result)
	if err != nil {
		t.Fatalf("base64 decode error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(decoded, &parsed); err != nil {
		t.Fatalf("json unmarshal error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ValidateReference tests
// ---------------------------------------------------------------------------

func TestValidateReference_Valid(t *testing.T) {
	tests := []string{
		"nginx",
		"nginx:latest",
		"docker.io/library/nginx:1.25",
		"registry.example.com/myapp:v1.0",
		"ghcr.io/user/repo@sha256:abc123",
	}
	for _, ref := range tests {
		if err := ValidateReference(ref); err != nil {
			t.Errorf("ValidateReference(%q) = %v, want nil", ref, err)
		}
	}
}

func TestValidateReference_Empty(t *testing.T) {
	err := ValidateReference("")
	if err == nil {
		t.Fatal("expected error for empty reference")
	}
	if !apperrors.IsValidationError(err) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// createTarWithDockerfile tests
// ---------------------------------------------------------------------------

func TestCreateTarWithDockerfile(t *testing.T) {
	dockerfile := "FROM nginx:latest\nCOPY . /usr/share/nginx/html"

	data, err := createTarWithDockerfile(dockerfile)
	if err != nil {
		t.Fatalf("createTarWithDockerfile() error = %v", err)
	}
	if len(data) == 0 {
		t.Fatal("tar data is empty")
	}

	// Verify it's a valid tar archive with a Dockerfile entry
	reader := tar.NewReader(bytes.NewReader(data))
	header, err := reader.Next()
	if err != nil {
		t.Fatalf("tar.Next() error = %v", err)
	}
	if header.Name != "Dockerfile" {
		t.Errorf("first entry name = %q, want %q", header.Name, "Dockerfile")
	}

	content, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read content error = %v", err)
	}
	if string(content) != dockerfile {
		t.Errorf("content = %q, want %q", string(content), dockerfile)
	}
}

func TestCreateTarWithDockerfile_Empty(t *testing.T) {
	data, err := createTarWithDockerfile("")
	if err != nil {
		t.Fatalf("createTarWithDockerfile(\"\") error = %v", err)
	}
	if len(data) == 0 {
		t.Fatal("tar data is empty")
	}
}

// ---------------------------------------------------------------------------
// tarWriter tests
// ---------------------------------------------------------------------------

func TestTarWriter_WriteAndClose(t *testing.T) {
	var buf bytes.Buffer
	tw := newTarWriter(&buf)

	err := tw.writeFile("test.txt", []byte("hello world"))
	if err != nil {
		t.Fatalf("writeFile() error = %v", err)
	}

	err = tw.close()
	if err != nil {
		t.Fatalf("close() error = %v", err)
	}

	// The tar should have at least header + content + padding + trailer
	if buf.Len() < 512+512+1024 {
		t.Errorf("tar too small: %d bytes", buf.Len())
	}
}

func TestTarWriter_MultipleFiles(t *testing.T) {
	var buf bytes.Buffer
	tw := newTarWriter(&buf)

	tw.writeFile("file1.txt", []byte("content1"))
	tw.writeFile("file2.txt", []byte("content2"))
	tw.close()

	// Verify both files are present
	reader := tar.NewReader(bytes.NewReader(buf.Bytes()))

	h1, err := reader.Next()
	if err != nil {
		t.Fatalf("first entry: %v", err)
	}
	if h1.Name != "file1.txt" {
		t.Errorf("first entry = %q, want %q", h1.Name, "file1.txt")
	}

	h2, err := reader.Next()
	if err != nil {
		t.Fatalf("second entry: %v", err)
	}
	if h2.Name != "file2.txt" {
		t.Errorf("second entry = %q, want %q", h2.Name, "file2.txt")
	}
}

// ---------------------------------------------------------------------------
// BuildOptions and BuildProgress struct tests
// ---------------------------------------------------------------------------

func TestBuildOptions_Defaults(t *testing.T) {
	opts := BuildOptions{}
	if opts.NoCache {
		t.Error("NoCache should default to false")
	}
	if opts.Pull {
		t.Error("Pull should default to false")
	}
	if opts.Dockerfile != "" {
		t.Error("Dockerfile should default to empty")
	}
}

func TestBuildProgress_JSON(t *testing.T) {
	p := BuildProgress{
		Stream:   "Step 1/3 : FROM nginx",
		Status:   "pulling",
		Progress: "50%",
	}

	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var parsed BuildProgress
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if parsed.Stream != p.Stream {
		t.Errorf("Stream = %q, want %q", parsed.Stream, p.Stream)
	}
}

func TestBuildResult_Fields(t *testing.T) {
	r := BuildResult{
		ImageID: "sha256:abc123",
		Tags:    []string{"myapp:latest", "myapp:v1.0"},
	}
	if r.ImageID != "sha256:abc123" {
		t.Errorf("ImageID = %q", r.ImageID)
	}
	if len(r.Tags) != 2 {
		t.Errorf("Tags len = %d, want 2", len(r.Tags))
	}
}
