// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package gitea

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestClient creates a Client backed by an httptest.Server.
// The caller registers handlers via the setup callback.
func newTestClient(t *testing.T, setup func(mux *http.ServeMux)) *Client {
	t.Helper()
	mux := http.NewServeMux()
	if setup != nil {
		setup(mux)
	}
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return NewClient(ts.URL, "test-token")
}

// requireAuth is a reusable check that the Authorization header is correct.
func requireAuth(t *testing.T, r *http.Request) bool {
	t.Helper()
	if got := r.Header.Get("Authorization"); got != "token test-token" {
		t.Errorf("Authorization header = %q, want %q", got, "token test-token")
		return false
	}
	return true
}

// writeJSON encodes v as JSON to w. Fails the test on error.
func writeJSON(t *testing.T, w http.ResponseWriter, v interface{}) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatalf("failed to write JSON response: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

func TestNewClient(t *testing.T) {
	c := NewClient("https://gitea.example.com", "my-token")
	if c.baseURL != "https://gitea.example.com" {
		t.Errorf("baseURL = %q, want %q", c.baseURL, "https://gitea.example.com")
	}
	if c.token != "my-token" {
		t.Errorf("token = %q, want %q", c.token, "my-token")
	}
	if c.httpClient.Timeout != 30*time.Second {
		t.Errorf("timeout = %v, want %v", c.httpClient.Timeout, 30*time.Second)
	}
}

func TestNewClient_TrailingSlash(t *testing.T) {
	c := NewClient("https://gitea.example.com///", "tok")
	if c.baseURL != "https://gitea.example.com" {
		t.Errorf("baseURL = %q, want trailing slashes trimmed", c.baseURL)
	}
}

// ---------------------------------------------------------------------------
// Version / User / TestConnection
// ---------------------------------------------------------------------------

func TestClient_GetVersion(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/api/v1/version", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if !requireAuth(t, r) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			writeJSON(t, w, APIVersion{Version: "1.22.0"})
		})
	})

	v, err := c.GetVersion(context.Background())
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}
	if v.Version != "1.22.0" {
		t.Errorf("Version = %q, want %q", v.Version, "1.22.0")
	}
}

func TestClient_GetCurrentUser(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/api/v1/user", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if !requireAuth(t, r) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			writeJSON(t, w, APIUser{
				ID:       42,
				Login:    "admin",
				FullName: "Admin User",
				Email:    "admin@example.com",
				IsAdmin:  true,
			})
		})
	})

	u, err := c.GetCurrentUser(context.Background())
	if err != nil {
		t.Fatalf("GetCurrentUser: %v", err)
	}
	if u.ID != 42 {
		t.Errorf("ID = %d, want 42", u.ID)
	}
	if u.Login != "admin" {
		t.Errorf("Login = %q, want %q", u.Login, "admin")
	}
	if !u.IsAdmin {
		t.Error("expected IsAdmin true")
	}
}

func TestClient_TestConnection(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/api/v1/user", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(t, w, APIUser{ID: 1, Login: "bot"})
		})
	})

	if err := c.TestConnection(context.Background()); err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Repository CRUD
// ---------------------------------------------------------------------------

func TestClient_ListUserRepos(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/api/v1/user/repos", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			// Verify pagination defaults get applied.
			q := r.URL.Query()
			if q.Get("page") != "1" {
				t.Errorf("page = %q, want %q", q.Get("page"), "1")
			}
			if q.Get("limit") != "50" {
				t.Errorf("limit = %q, want %q", q.Get("limit"), "50")
			}
			if q.Get("sort") != "updated" {
				t.Errorf("sort = %q, want %q", q.Get("sort"), "updated")
			}
			writeJSON(t, w, []APIRepository{
				{ID: 1, Name: "repo-a", FullName: "user/repo-a"},
				{ID: 2, Name: "repo-b", FullName: "user/repo-b"},
			})
		})
	})

	repos, err := c.ListUserRepos(context.Background(), 0, 0) // should default to page=1, limit=50
	if err != nil {
		t.Fatalf("ListUserRepos: %v", err)
	}
	if len(repos) != 2 {
		t.Fatalf("got %d repos, want 2", len(repos))
	}
	if repos[0].Name != "repo-a" {
		t.Errorf("repos[0].Name = %q, want %q", repos[0].Name, "repo-a")
	}
}

func TestClient_ListAllRepos(t *testing.T) {
	callCount := 0
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/api/v1/user/repos", func(w http.ResponseWriter, r *http.Request) {
			callCount++
			page := r.URL.Query().Get("page")
			var repos []APIRepository
			switch page {
			case "1":
				// Return exactly 50 to trigger second page.
				for i := int64(0); i < 50; i++ {
					repos = append(repos, APIRepository{ID: i, Name: "repo"})
				}
			case "2":
				// Return fewer than 50 to signal end.
				for i := int64(50); i < 60; i++ {
					repos = append(repos, APIRepository{ID: i, Name: "repo"})
				}
			default:
				t.Errorf("unexpected page %q", page)
			}
			writeJSON(t, w, repos)
		})
	})

	all, err := c.ListAllRepos(context.Background())
	if err != nil {
		t.Fatalf("ListAllRepos: %v", err)
	}
	if len(all) != 60 {
		t.Errorf("got %d repos, want 60", len(all))
	}
	if callCount != 2 {
		t.Errorf("API called %d times, want 2", callCount)
	}
}

func TestClient_GetRepository(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/myorg/myrepo" {
				writeJSON(t, w, APIRepository{
					ID:            99,
					Name:          "myrepo",
					FullName:      "myorg/myrepo",
					DefaultBranch: "main",
					Private:       true,
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
	})

	repo, err := c.GetRepository(context.Background(), "myorg", "myrepo")
	if err != nil {
		t.Fatalf("GetRepository: %v", err)
	}
	if repo.ID != 99 {
		t.Errorf("ID = %d, want 99", repo.ID)
	}
	if repo.DefaultBranch != "main" {
		t.Errorf("DefaultBranch = %q, want %q", repo.DefaultBranch, "main")
	}
	if !repo.Private {
		t.Error("expected Private true")
	}
}

func TestClient_CreateUserRepository(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/api/v1/user/repos", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			var opts CreateRepoOptions
			if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
				t.Errorf("decode body: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if opts.Name != "new-repo" {
				t.Errorf("Name = %q, want %q", opts.Name, "new-repo")
			}
			if !opts.Private {
				t.Error("expected Private true")
			}
			w.WriteHeader(http.StatusCreated)
			writeJSON(t, w, APIRepository{ID: 100, Name: opts.Name, Private: opts.Private})
		})
	})

	repo, err := c.CreateUserRepository(context.Background(), CreateRepoOptions{
		Name:    "new-repo",
		Private: true,
	})
	if err != nil {
		t.Fatalf("CreateUserRepository: %v", err)
	}
	if repo.ID != 100 {
		t.Errorf("ID = %d, want 100", repo.ID)
	}
}

func TestClient_EditRepository(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPatch && r.URL.Path == "/api/v1/repos/user/repo" {
				var opts EditRepoOptions
				if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				desc := ""
				if opts.Description != nil {
					desc = *opts.Description
				}
				writeJSON(t, w, APIRepository{ID: 1, Name: "repo", Description: desc})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
	})

	desc := "updated description"
	repo, err := c.EditRepository(context.Background(), "user", "repo", EditRepoOptions{
		Description: &desc,
	})
	if err != nil {
		t.Fatalf("EditRepository: %v", err)
	}
	if repo.Description != "updated description" {
		t.Errorf("Description = %q, want %q", repo.Description, "updated description")
	}
}

func TestClient_DeleteRepository(t *testing.T) {
	deleted := false
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodDelete && r.URL.Path == "/api/v1/repos/user/repo" {
				deleted = true
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
	})

	if err := c.DeleteRepository(context.Background(), "user", "repo"); err != nil {
		t.Fatalf("DeleteRepository: %v", err)
	}
	if !deleted {
		t.Error("expected DELETE to be called")
	}
}

// ---------------------------------------------------------------------------
// Branch / Tag
// ---------------------------------------------------------------------------

func TestClient_ListBranches(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/user/repo/branches" {
				writeJSON(t, w, []APIBranch{
					{Name: "main", Protected: true},
					{Name: "develop", Protected: false},
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
	})

	branches, err := c.ListBranches(context.Background(), "user", "repo")
	if err != nil {
		t.Fatalf("ListBranches: %v", err)
	}
	if len(branches) != 2 {
		t.Fatalf("got %d branches, want 2", len(branches))
	}
	if branches[0].Name != "main" {
		t.Errorf("branches[0].Name = %q, want %q", branches[0].Name, "main")
	}
	if !branches[0].Protected {
		t.Error("expected main branch to be protected")
	}
}

func TestClient_GetBranch(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/user/repo/branches/main" {
				writeJSON(t, w, APIBranch{
					Name: "main",
					Commit: APICommit{
						ID:      "abc123",
						Message: "initial commit",
					},
					Protected: true,
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
	})

	b, err := c.GetBranch(context.Background(), "user", "repo", "main")
	if err != nil {
		t.Fatalf("GetBranch: %v", err)
	}
	if b.Name != "main" {
		t.Errorf("Name = %q, want %q", b.Name, "main")
	}
	if b.Commit.ID != "abc123" {
		t.Errorf("Commit.ID = %q, want %q", b.Commit.ID, "abc123")
	}
}

func TestClient_CreateBranch(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == "/api/v1/repos/user/repo/branches" {
				var opts CreateBranchOptions
				if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if opts.NewBranchName != "feature-x" {
					t.Errorf("NewBranchName = %q, want %q", opts.NewBranchName, "feature-x")
				}
				w.WriteHeader(http.StatusCreated)
				writeJSON(t, w, APIBranch{Name: opts.NewBranchName})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
	})

	b, err := c.CreateBranch(context.Background(), "user", "repo", CreateBranchOptions{
		NewBranchName: "feature-x",
		OldBranchName: "main",
	})
	if err != nil {
		t.Fatalf("CreateBranch: %v", err)
	}
	if b.Name != "feature-x" {
		t.Errorf("Name = %q, want %q", b.Name, "feature-x")
	}
}

func TestClient_ListTags(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/user/repo/tags" {
				q := r.URL.Query()
				if q.Get("page") != "1" {
					t.Errorf("page = %q, want %q", q.Get("page"), "1")
				}
				if q.Get("limit") != "10" {
					t.Errorf("limit = %q, want %q", q.Get("limit"), "10")
				}
				writeJSON(t, w, []APITag{
					{Name: "v1.0.0", ID: "aaa"},
					{Name: "v1.1.0", ID: "bbb"},
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
	})

	tags, err := c.ListTags(context.Background(), "user", "repo", 1, 10)
	if err != nil {
		t.Fatalf("ListTags: %v", err)
	}
	if len(tags) != 2 {
		t.Fatalf("got %d tags, want 2", len(tags))
	}
	if tags[0].Name != "v1.0.0" {
		t.Errorf("tags[0].Name = %q, want %q", tags[0].Name, "v1.0.0")
	}
}

// ---------------------------------------------------------------------------
// Content / Files
// ---------------------------------------------------------------------------

func TestClient_ListContents(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/user/repo/contents/" {
				if ref := r.URL.Query().Get("ref"); ref != "main" {
					t.Errorf("ref = %q, want %q", ref, "main")
				}
				writeJSON(t, w, []APIContentEntry{
					{Name: "README.md", Path: "README.md", Type: "file", Size: 1024},
					{Name: "src", Path: "src", Type: "dir", Size: 0},
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
	})

	entries, err := c.ListContents(context.Background(), "user", "repo", "", "main")
	if err != nil {
		t.Fatalf("ListContents: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Type != "file" {
		t.Errorf("entries[0].Type = %q, want %q", entries[0].Type, "file")
	}
	if entries[1].Type != "dir" {
		t.Errorf("entries[1].Type = %q, want %q", entries[1].Type, "dir")
	}
}

func TestClient_GetRawFile(t *testing.T) {
	fileContent := "package main\n\nfunc main() {}\n"
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/user/repo/raw/main.go" {
				if ref := r.URL.Query().Get("ref"); ref != "develop" {
					t.Errorf("ref = %q, want %q", ref, "develop")
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(fileContent))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
	})

	data, err := c.GetRawFile(context.Background(), "user", "repo", "main.go", "develop")
	if err != nil {
		t.Fatalf("GetRawFile: %v", err)
	}
	if string(data) != fileContent {
		t.Errorf("content = %q, want %q", string(data), fileContent)
	}
}

func TestClient_UpdateFile(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPut && r.URL.Path == "/api/v1/repos/user/repo/contents/docs/README.md" {
				var opts UpdateFileOptions
				if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if opts.Message != "update readme" {
					t.Errorf("Message = %q, want %q", opts.Message, "update readme")
				}
				if opts.SHA != "oldsha" {
					t.Errorf("SHA = %q, want %q", opts.SHA, "oldsha")
				}
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
	})

	err := c.UpdateFile(context.Background(), "user", "repo", "docs/README.md", UpdateFileOptions{
		Content: "dXBkYXRlZA==", // base64 "updated"
		Message: "update readme",
		SHA:     "oldsha",
		Branch:  "main",
	})
	if err != nil {
		t.Fatalf("UpdateFile: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Commits
// ---------------------------------------------------------------------------

func TestClient_ListCommits(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/user/repo/commits" {
				q := r.URL.Query()
				// With limit=0 the client defaults to 20.
				if q.Get("limit") != "20" {
					t.Errorf("limit = %q, want %q", q.Get("limit"), "20")
				}
				if q.Get("sha") != "main" {
					t.Errorf("sha = %q, want %q", q.Get("sha"), "main")
				}
				writeJSON(t, w, []APICommitListItem{
					{SHA: "abc123", Commit: APICommitDetail{Message: "first"}},
					{SHA: "def456", Commit: APICommitDetail{Message: "second"}},
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
	})

	commits, err := c.ListCommits(context.Background(), "user", "repo", "main", 0)
	if err != nil {
		t.Fatalf("ListCommits: %v", err)
	}
	if len(commits) != 2 {
		t.Fatalf("got %d commits, want 2", len(commits))
	}
	if commits[0].SHA != "abc123" {
		t.Errorf("commits[0].SHA = %q, want %q", commits[0].SHA, "abc123")
	}
}

func TestClient_GetCommit(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/user/repo/git/commits/abc123" {
				writeJSON(t, w, APICommitListItem{
					SHA: "abc123",
					Commit: APICommitDetail{
						Message: "fix: resolve null pointer",
						Author:  &APIIdentity{Name: "dev", Email: "dev@example.com"},
					},
					Files: []APIDiffFile{
						{Filename: "main.go", Status: "modified", Additions: 5, Deletions: 2},
					},
					Stats: &APICommitStats{Total: 7, Additions: 5, Deletions: 2},
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
	})

	commit, err := c.GetCommit(context.Background(), "user", "repo", "abc123")
	if err != nil {
		t.Fatalf("GetCommit: %v", err)
	}
	if commit.SHA != "abc123" {
		t.Errorf("SHA = %q, want %q", commit.SHA, "abc123")
	}
	if commit.Commit.Message != "fix: resolve null pointer" {
		t.Errorf("Message = %q, want %q", commit.Commit.Message, "fix: resolve null pointer")
	}
	if len(commit.Files) != 1 {
		t.Fatalf("got %d files, want 1", len(commit.Files))
	}
	if commit.Stats.Total != 7 {
		t.Errorf("Stats.Total = %d, want 7", commit.Stats.Total)
	}
}

func TestClient_Compare(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/user/repo/compare/main...feature" {
				writeJSON(t, w, APICompare{
					TotalCommits: 3,
					Commits: []APICommitListItem{
						{SHA: "aaa"},
						{SHA: "bbb"},
						{SHA: "ccc"},
					},
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
	})

	cmp, err := c.Compare(context.Background(), "user", "repo", "main...feature")
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if cmp.TotalCommits != 3 {
		t.Errorf("TotalCommits = %d, want 3", cmp.TotalCommits)
	}
	if len(cmp.Commits) != 3 {
		t.Errorf("got %d commits, want 3", len(cmp.Commits))
	}
}

// ---------------------------------------------------------------------------
// Pull Requests
// ---------------------------------------------------------------------------

func TestClient_ListPullRequests(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/user/repo/pulls" {
				q := r.URL.Query()
				if q.Get("state") != "open" {
					t.Errorf("state = %q, want %q", q.Get("state"), "open")
				}
				if q.Get("sort") != "newest" {
					t.Errorf("sort = %q, want %q", q.Get("sort"), "newest")
				}
				if q.Get("labels") != "bug" {
					t.Errorf("labels = %q, want %q", q.Get("labels"), "bug")
				}
				writeJSON(t, w, []APIPullRequest{
					{ID: 1, Number: 10, Title: "Fix bug", State: "open"},
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
	})

	prs, err := c.ListPullRequests(context.Background(), "user", "repo", PRListOptions{
		State:  "open",
		Sort:   "newest",
		Labels: "bug",
	})
	if err != nil {
		t.Fatalf("ListPullRequests: %v", err)
	}
	if len(prs) != 1 {
		t.Fatalf("got %d PRs, want 1", len(prs))
	}
	if prs[0].Title != "Fix bug" {
		t.Errorf("Title = %q, want %q", prs[0].Title, "Fix bug")
	}
}

func TestClient_GetPullRequest(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/user/repo/pulls/42" {
				writeJSON(t, w, APIPullRequest{
					ID:        1,
					Number:    42,
					Title:     "Add feature",
					State:     "open",
					Mergeable: true,
					Head:      APIPRBranch{Ref: "feature", SHA: "headsha"},
					Base:      APIPRBranch{Ref: "main", SHA: "basesha"},
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
	})

	pr, err := c.GetPullRequest(context.Background(), "user", "repo", 42)
	if err != nil {
		t.Fatalf("GetPullRequest: %v", err)
	}
	if pr.Number != 42 {
		t.Errorf("Number = %d, want 42", pr.Number)
	}
	if !pr.Mergeable {
		t.Error("expected Mergeable true")
	}
	if pr.Head.Ref != "feature" {
		t.Errorf("Head.Ref = %q, want %q", pr.Head.Ref, "feature")
	}
}

func TestClient_CreatePullRequest(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == "/api/v1/repos/user/repo/pulls" {
				var opts CreatePullRequestOptions
				if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if opts.Title != "New PR" {
					t.Errorf("Title = %q, want %q", opts.Title, "New PR")
				}
				if opts.Head != "feature" {
					t.Errorf("Head = %q, want %q", opts.Head, "feature")
				}
				if opts.Base != "main" {
					t.Errorf("Base = %q, want %q", opts.Base, "main")
				}
				w.WriteHeader(http.StatusCreated)
				writeJSON(t, w, APIPullRequest{
					ID:     1,
					Number: 99,
					Title:  opts.Title,
					State:  "open",
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
	})

	pr, err := c.CreatePullRequest(context.Background(), "user", "repo", CreatePullRequestOptions{
		Title: "New PR",
		Head:  "feature",
		Base:  "main",
	})
	if err != nil {
		t.Fatalf("CreatePullRequest: %v", err)
	}
	if pr.Number != 99 {
		t.Errorf("Number = %d, want 99", pr.Number)
	}
}

func TestClient_MergePullRequest(t *testing.T) {
	merged := false
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == "/api/v1/repos/user/repo/pulls/5/merge" {
				var opts MergePullRequestOptions
				if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if opts.MergeStyle != "squash" {
					t.Errorf("MergeStyle = %q, want %q", opts.MergeStyle, "squash")
				}
				merged = true
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
	})

	err := c.MergePullRequest(context.Background(), "user", "repo", 5, MergePullRequestOptions{
		MergeStyle:        "squash",
		DeleteBranchAfter: true,
	})
	if err != nil {
		t.Fatalf("MergePullRequest: %v", err)
	}
	if !merged {
		t.Error("expected merge endpoint to be called")
	}
}

// ---------------------------------------------------------------------------
// Issues
// ---------------------------------------------------------------------------

func TestClient_ListIssues(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/user/repo/issues" {
				q := r.URL.Query()
				if q.Get("state") != "open" {
					t.Errorf("state = %q, want %q", q.Get("state"), "open")
				}
				if q.Get("labels") != "bug,urgent" {
					t.Errorf("labels = %q, want %q", q.Get("labels"), "bug,urgent")
				}
				writeJSON(t, w, []APIIssue{
					{ID: 1, Number: 10, Title: "Bug report", State: "open"},
					{ID: 2, Number: 11, Title: "Another bug", State: "open"},
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
	})

	issues, err := c.ListIssues(context.Background(), "user", "repo", IssueListOptions{
		State:  "open",
		Labels: "bug,urgent",
	})
	if err != nil {
		t.Fatalf("ListIssues: %v", err)
	}
	if len(issues) != 2 {
		t.Fatalf("got %d issues, want 2", len(issues))
	}
	if issues[0].Title != "Bug report" {
		t.Errorf("issues[0].Title = %q, want %q", issues[0].Title, "Bug report")
	}
}

func TestClient_CreateIssue(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == "/api/v1/repos/user/repo/issues" {
				var opts CreateIssueOptions
				if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if opts.Title != "New issue" {
					t.Errorf("Title = %q, want %q", opts.Title, "New issue")
				}
				w.WriteHeader(http.StatusCreated)
				writeJSON(t, w, APIIssue{
					ID:     5,
					Number: 12,
					Title:  opts.Title,
					Body:   opts.Body,
					State:  "open",
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
	})

	issue, err := c.CreateIssue(context.Background(), "user", "repo", CreateIssueOptions{
		Title: "New issue",
		Body:  "Something is broken",
	})
	if err != nil {
		t.Fatalf("CreateIssue: %v", err)
	}
	if issue.Number != 12 {
		t.Errorf("Number = %d, want 12", issue.Number)
	}
	if issue.Body != "Something is broken" {
		t.Errorf("Body = %q, want %q", issue.Body, "Something is broken")
	}
}

func TestClient_CreateIssueComment(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == "/api/v1/repos/user/repo/issues/7/comments" {
				var opts CreateCommentOptions
				if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if opts.Body != "LGTM" {
					t.Errorf("Body = %q, want %q", opts.Body, "LGTM")
				}
				w.WriteHeader(http.StatusCreated)
				writeJSON(t, w, APIComment{
					ID:   100,
					Body: opts.Body,
					User: APIUser{Login: "admin"},
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
	})

	comment, err := c.CreateIssueComment(context.Background(), "user", "repo", 7, CreateCommentOptions{
		Body: "LGTM",
	})
	if err != nil {
		t.Fatalf("CreateIssueComment: %v", err)
	}
	if comment.ID != 100 {
		t.Errorf("ID = %d, want 100", comment.ID)
	}
	if comment.Body != "LGTM" {
		t.Errorf("Body = %q, want %q", comment.Body, "LGTM")
	}
}

// ---------------------------------------------------------------------------
// Webhooks
// ---------------------------------------------------------------------------

func TestClient_CreateRepoWebhook(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == "/api/v1/repos/user/repo/hooks" {
				var opts CreateWebhookOptions
				if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if opts.Type != "gitea" {
					t.Errorf("Type = %q, want %q", opts.Type, "gitea")
				}
				if opts.Config.URL != "https://example.com/hook" {
					t.Errorf("Config.URL = %q, want %q", opts.Config.URL, "https://example.com/hook")
				}
				if !opts.Active {
					t.Error("expected Active true")
				}
				w.WriteHeader(http.StatusCreated)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
	})

	err := c.CreateRepoWebhook(context.Background(), "user", "repo", CreateWebhookOptions{
		Type: "gitea",
		Config: WebhookConfig{
			URL:         "https://example.com/hook",
			ContentType: "json",
			Secret:      "s3cr3t",
		},
		Events: []string{"push", "pull_request"},
		Active: true,
	})
	if err != nil {
		t.Fatalf("CreateRepoWebhook: %v", err)
	}
}

func TestClient_ListHooks(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/user/repo/hooks" {
				writeJSON(t, w, []APIHook{
					{
						ID:     1,
						Type:   "gitea",
						Active: true,
						Events: []string{"push"},
						Config: map[string]string{"url": "https://example.com/hook"},
					},
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
	})

	hooks, err := c.ListHooks(context.Background(), "user", "repo")
	if err != nil {
		t.Fatalf("ListHooks: %v", err)
	}
	if len(hooks) != 1 {
		t.Fatalf("got %d hooks, want 1", len(hooks))
	}
	if hooks[0].Type != "gitea" {
		t.Errorf("Type = %q, want %q", hooks[0].Type, "gitea")
	}
	if !hooks[0].Active {
		t.Error("expected hook to be active")
	}
}

// ---------------------------------------------------------------------------
// Releases
// ---------------------------------------------------------------------------

func TestClient_ListReleases(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/user/repo/releases" {
				writeJSON(t, w, []APIRelease{
					{ID: 1, TagName: "v1.0.0", Name: "Release 1.0", IsDraft: false},
					{ID: 2, TagName: "v2.0.0-rc1", Name: "RC1", IsPrerelease: true},
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
	})

	releases, err := c.ListReleases(context.Background(), "user", "repo", 1, 10)
	if err != nil {
		t.Fatalf("ListReleases: %v", err)
	}
	if len(releases) != 2 {
		t.Fatalf("got %d releases, want 2", len(releases))
	}
	if releases[0].TagName != "v1.0.0" {
		t.Errorf("releases[0].TagName = %q, want %q", releases[0].TagName, "v1.0.0")
	}
	if releases[1].IsPrerelease != true {
		t.Error("expected releases[1] to be a prerelease")
	}
}

func TestClient_CreateRelease(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == "/api/v1/repos/user/repo/releases" {
				var opts CreateReleaseOptions
				if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if opts.TagName != "v3.0.0" {
					t.Errorf("TagName = %q, want %q", opts.TagName, "v3.0.0")
				}
				w.WriteHeader(http.StatusCreated)
				writeJSON(t, w, APIRelease{
					ID:      10,
					TagName: opts.TagName,
					Name:    opts.Name,
					Body:    opts.Body,
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
	})

	release, err := c.CreateRelease(context.Background(), "user", "repo", CreateReleaseOptions{
		TagName: "v3.0.0",
		Target:  "main",
		Name:    "Version 3",
		Body:    "Major release",
	})
	if err != nil {
		t.Fatalf("CreateRelease: %v", err)
	}
	if release.ID != 10 {
		t.Errorf("ID = %d, want 10", release.ID)
	}
	if release.TagName != "v3.0.0" {
		t.Errorf("TagName = %q, want %q", release.TagName, "v3.0.0")
	}
}

// ---------------------------------------------------------------------------
// Actions / CI Status
// ---------------------------------------------------------------------------

func TestClient_ListActionRuns(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/user/repo/actions/runs" {
				q := r.URL.Query()
				if q.Get("branch") != "main" {
					t.Errorf("branch = %q, want %q", q.Get("branch"), "main")
				}
				if q.Get("status") != "success" {
					t.Errorf("status = %q, want %q", q.Get("status"), "success")
				}
				// Response is wrapped in {"workflow_runs": [...]}
				writeJSON(t, w, struct {
					Runs []APIActionRun `json:"workflow_runs"`
				}{
					Runs: []APIActionRun{
						{ID: 1, Title: "CI", Status: "success", HeadBranch: "main"},
						{ID: 2, Title: "Deploy", Status: "success", HeadBranch: "main"},
					},
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
	})

	runs, err := c.ListActionRuns(context.Background(), "user", "repo", ActionRunListOptions{
		Branch: "main",
		Status: "success",
		Page:   1,
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("ListActionRuns: %v", err)
	}
	if len(runs) != 2 {
		t.Fatalf("got %d runs, want 2", len(runs))
	}
	if runs[0].Title != "CI" {
		t.Errorf("runs[0].Title = %q, want %q", runs[0].Title, "CI")
	}
}

func TestClient_GetCombinedStatus(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/user/repo/commits/abc123/status" {
				writeJSON(t, w, APICombinedStatus{
					State:      "success",
					SHA:        "abc123",
					TotalCount: 2,
					Statuses: []APICommitStatus{
						{ID: 1, State: "success", Context: "ci/build"},
						{ID: 2, State: "success", Context: "ci/test"},
					},
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
	})

	status, err := c.GetCombinedStatus(context.Background(), "user", "repo", "abc123")
	if err != nil {
		t.Fatalf("GetCombinedStatus: %v", err)
	}
	if status.State != "success" {
		t.Errorf("State = %q, want %q", status.State, "success")
	}
	if status.TotalCount != 2 {
		t.Errorf("TotalCount = %d, want 2", status.TotalCount)
	}
	if len(status.Statuses) != 2 {
		t.Fatalf("got %d statuses, want 2", len(status.Statuses))
	}
}

// ---------------------------------------------------------------------------
// Error Handling
// ---------------------------------------------------------------------------

func TestClient_ErrorResponse(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/api/v1/version", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"message":"token is invalid"}`))
		})
	})

	_, err := c.GetVersion(context.Background())
	if err == nil {
		t.Fatal("expected error for 403 response")
	}
	if !strings.Contains(err.Error(), "API error 403") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "API error 403")
	}
	if !strings.Contains(err.Error(), "token is invalid") {
		t.Errorf("error = %q, want it to contain response body", err.Error())
	}
}

func TestClient_InvalidJSON(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/api/v1/version", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{invalid json`))
		})
	})

	_, err := c.GetVersion(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "decode response") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "decode response")
	}
}

func TestClient_ServerDown(t *testing.T) {
	// Create a server and close it immediately to get a valid but unreachable URL.
	ts := httptest.NewServer(http.NotFoundHandler())
	url := ts.URL
	ts.Close()

	c := NewClient(url, "test-token")
	_, err := c.GetVersion(context.Background())
	if err == nil {
		t.Fatal("expected error when server is down")
	}
	if !strings.Contains(err.Error(), "request failed") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "request failed")
	}
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

func TestClient_ListGitignoreTemplates(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/api/v1/gitignore/templates", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			writeJSON(t, w, []string{"Go", "Python", "Node", "Rust"})
		})
	})

	templates, err := c.ListGitignoreTemplates(context.Background())
	if err != nil {
		t.Fatalf("ListGitignoreTemplates: %v", err)
	}
	if len(templates) != 4 {
		t.Fatalf("got %d templates, want 4", len(templates))
	}
	if templates[0] != "Go" {
		t.Errorf("templates[0] = %q, want %q", templates[0], "Go")
	}
}

// ---------------------------------------------------------------------------
// Additional coverage: auth verification, request body, edge cases
// ---------------------------------------------------------------------------

func TestClient_AuthHeaderOnEveryRequest(t *testing.T) {
	// Verify the auth header is sent on every request type (GET, POST, PATCH, DELETE).
	var methods []string
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "token test-token" {
				t.Errorf("%s %s: missing auth header", r.Method, r.URL.Path)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			methods = append(methods, r.Method)
			switch r.Method {
			case http.MethodGet:
				writeJSON(t, w, APIRepository{ID: 1, Name: "r"})
			case http.MethodPost:
				writeJSON(t, w, APIRepository{ID: 1, Name: "r"})
			case http.MethodPatch:
				writeJSON(t, w, APIRepository{ID: 1, Name: "r"})
			case http.MethodDelete:
				w.WriteHeader(http.StatusNoContent)
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		})
	})

	ctx := context.Background()
	_, _ = c.GetRepository(ctx, "u", "r")               // GET
	_, _ = c.CreateUserRepository(ctx, CreateRepoOptions{Name: "r"}) // POST
	_, _ = c.EditRepository(ctx, "u", "r", EditRepoOptions{})       // PATCH
	_ = c.DeleteRepository(ctx, "u", "r")                           // DELETE

	if len(methods) != 4 {
		t.Fatalf("expected 4 requests, got %d", len(methods))
	}
	want := []string{"GET", "POST", "PATCH", "DELETE"}
	for i, m := range want {
		if methods[i] != m {
			t.Errorf("methods[%d] = %q, want %q", i, methods[i], m)
		}
	}
}

func TestClient_PostSendsContentTypeJSON(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				ct := r.Header.Get("Content-Type")
				if ct != "application/json" {
					t.Errorf("Content-Type = %q, want %q", ct, "application/json")
				}
				// Read and discard body to avoid broken pipe
				io.ReadAll(r.Body)
			}
			writeJSON(t, w, APIIssue{ID: 1})
		})
	})

	_, _ = c.CreateIssue(context.Background(), "u", "r", CreateIssueOptions{Title: "t"})
}

func TestClient_ListUserRepos_ClampsPageAndLimit(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/api/v1/user/repos", func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			// Negative page should become 1, limit >50 should become 50.
			if q.Get("page") != "1" {
				t.Errorf("page = %q, want %q (clamped from -1)", q.Get("page"), "1")
			}
			if q.Get("limit") != "50" {
				t.Errorf("limit = %q, want %q (clamped from 999)", q.Get("limit"), "50")
			}
			writeJSON(t, w, []APIRepository{})
		})
	})

	_, err := c.ListUserRepos(context.Background(), -1, 999)
	if err != nil {
		t.Fatalf("ListUserRepos: %v", err)
	}
}

func TestClient_ListCommits_DefaultLimit(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			if q.Get("limit") != "20" {
				t.Errorf("limit = %q, want %q (default for out-of-range)", q.Get("limit"), "20")
			}
			writeJSON(t, w, []APICommitListItem{})
		})
	})

	// limit=100 is out of range (>50), should default to 20.
	_, err := c.ListCommits(context.Background(), "u", "r", "", 100)
	if err != nil {
		t.Fatalf("ListCommits: %v", err)
	}
}

func TestClient_ListTags_ClampsDefaults(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			if q.Get("page") != "1" {
				t.Errorf("page = %q, want %q", q.Get("page"), "1")
			}
			if q.Get("limit") != "50" {
				t.Errorf("limit = %q, want %q", q.Get("limit"), "50")
			}
			writeJSON(t, w, []APITag{})
		})
	})

	_, err := c.ListTags(context.Background(), "u", "r", 0, 0)
	if err != nil {
		t.Fatalf("ListTags: %v", err)
	}
}

func TestClient_GetRawFile_ErrorResponse(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("file not found"))
		})
	})

	_, err := c.GetRawFile(context.Background(), "u", "r", "missing.txt", "main")
	if err == nil {
		t.Fatal("expected error for 404 on raw file")
	}
	if !strings.Contains(err.Error(), "API error 404") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "API error 404")
	}
}

func TestClient_DeleteRepository_Error(t *testing.T) {
	c := newTestClient(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("internal error"))
		})
	})

	err := c.DeleteRepository(context.Background(), "u", "r")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if !strings.Contains(err.Error(), "API error 500") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "API error 500")
	}
}
