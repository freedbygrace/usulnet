// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package git

import (
	"testing"

	"github.com/fr4nsys/usulnet/internal/models"
)

// ---------------------------------------------------------------------------
// NewProvider factory tests
// ---------------------------------------------------------------------------

func TestNewProvider_Gitea(t *testing.T) {
	p, err := NewProvider(models.GitProviderGitea, "https://gitea.example.com", "token123")
	if err != nil {
		t.Fatalf("NewProvider(gitea) error = %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestNewProvider_GitHub(t *testing.T) {
	p, err := NewProvider(models.GitProviderGitHub, "https://api.github.com", "token123")
	if err != nil {
		t.Fatalf("NewProvider(github) error = %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestNewProvider_GitLab(t *testing.T) {
	p, err := NewProvider(models.GitProviderGitLab, "https://gitlab.com", "token123")
	if err != nil {
		t.Fatalf("NewProvider(gitlab) error = %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestNewProvider_CaseInsensitive(t *testing.T) {
	tests := []struct {
		input models.GitProviderType
	}{
		{"GITEA"},
		{"Gitea"},
		{"GITHUB"},
		{"GitHub"},
		{"GITLAB"},
		{"GitLab"},
	}

	for _, tt := range tests {
		p, err := NewProvider(tt.input, "https://example.com", "token")
		if err != nil {
			t.Errorf("NewProvider(%q) error = %v", tt.input, err)
		}
		if p == nil {
			t.Errorf("NewProvider(%q) returned nil", tt.input)
		}
	}
}

func TestNewProvider_Unknown(t *testing.T) {
	_, err := NewProvider("bitbucket", "https://example.com", "token")
	if err == nil {
		t.Fatal("expected error for unknown provider type")
	}
}

func TestNewProvider_EmptyType(t *testing.T) {
	_, err := NewProvider("", "https://example.com", "token")
	if err == nil {
		t.Fatal("expected error for empty provider type")
	}
}

// ---------------------------------------------------------------------------
// Option types tests (struct initialization)
// ---------------------------------------------------------------------------

func TestCreateRepoOptions(t *testing.T) {
	opts := CreateRepoOptions{
		Name:        "test-repo",
		Description: "A test repository",
		Private:     true,
		AutoInit:    true,
		Gitignore:   "Go",
		License:     "MIT",
	}
	if opts.Name != "test-repo" {
		t.Errorf("Name = %q", opts.Name)
	}
	if !opts.Private {
		t.Error("Private should be true")
	}
}

func TestListCommitsOptions_Defaults(t *testing.T) {
	opts := ListCommitsOptions{}
	if opts.Page != 0 || opts.PerPage != 0 {
		t.Error("default page/perPage should be 0")
	}
}

func TestMergePROptions(t *testing.T) {
	opts := MergePROptions{
		MergeMethod:   "squash",
		CommitTitle:   "Merge PR #1",
		CommitMessage: "Description",
		Squash:        true,
	}
	if opts.MergeMethod != "squash" {
		t.Errorf("MergeMethod = %q", opts.MergeMethod)
	}
}

func TestLicenseTemplate_JSON(t *testing.T) {
	lt := LicenseTemplate{
		Key:  "mit",
		Name: "MIT License",
		URL:  "https://opensource.org/licenses/MIT",
	}
	if lt.Key != "mit" {
		t.Errorf("Key = %q", lt.Key)
	}
}
