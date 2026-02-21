// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package docker

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// ImageList
// ---------------------------------------------------------------------------

func TestImageList(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/images/json", func(w http.ResponseWriter, r *http.Request) {
		resp := []map[string]interface{}{
			{
				"Id":          "sha256:img1",
				"ParentId":    "",
				"RepoTags":    []string{"nginx:latest"},
				"RepoDigests": []string{},
				"Created":     time.Now().Unix(),
				"Size":        int64(50 * 1024 * 1024),
				"SharedSize":  int64(0),
				"VirtualSize": int64(50 * 1024 * 1024),
				"Labels":      map[string]string{},
				"Containers":  int64(1),
			},
			{
				"Id":          "sha256:img2",
				"ParentId":    "",
				"RepoTags":    []string{"postgres:16"},
				"RepoDigests": []string{},
				"Created":     time.Now().Unix(),
				"Size":        int64(100 * 1024 * 1024),
				"SharedSize":  int64(0),
				"VirtualSize": int64(100 * 1024 * 1024),
				"Labels":      map[string]string{},
				"Containers":  int64(0),
			},
		}
		jsonResponse(w, http.StatusOK, resp)
	})

	images, err := c.ImageList(ctx, ImageListOptions{})
	if err != nil {
		t.Fatalf("ImageList() error: %v", err)
	}
	if len(images) != 2 {
		t.Fatalf("ImageList() len = %d, want 2", len(images))
	}
	if images[0].ID != "sha256:img1" {
		t.Errorf("images[0].ID = %q, want %q", images[0].ID, "sha256:img1")
	}
}

func TestImageList_Closed(t *testing.T) {
	c := newClosedClient(t)
	_, err := c.ImageList(context.Background(), ImageListOptions{})
	if err == nil {
		t.Fatal("ImageList() on closed client should return error")
	}
}

// ---------------------------------------------------------------------------
// ImageGet (inspect)
// ---------------------------------------------------------------------------

func TestImageGet(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/images/sha256:img1/json", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"Id":            "sha256:img1",
			"Parent":        "",
			"RepoTags":      []string{"nginx:latest"},
			"RepoDigests":   []string{"nginx@sha256:digest1"},
			"Created":       "2024-01-15T10:30:00Z",
			"Size":          int64(50 * 1024 * 1024),
			"VirtualSize":   int64(50 * 1024 * 1024),
			"Architecture":  "amd64",
			"Os":            "linux",
			"DockerVersion": "27.0.0",
			"Config": map[string]interface{}{
				"Labels": map[string]string{"version": "1.0"},
			},
			"RootFS": map[string]interface{}{
				"Type":   "layers",
				"Layers": []string{"sha256:layer1"},
			},
		}
		jsonResponse(w, http.StatusOK, resp)
	})

	details, err := c.ImageGet(ctx, "sha256:img1")
	if err != nil {
		t.Fatalf("ImageGet() error: %v", err)
	}
	if details.ID != "sha256:img1" {
		t.Errorf("ID = %q, want %q", details.ID, "sha256:img1")
	}
	if details.Architecture != "amd64" {
		t.Errorf("Architecture = %q, want %q", details.Architecture, "amd64")
	}
}

func TestImageGet_NotFound(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/images/nonexistent/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"No such image: nonexistent"}`))
	})

	_, err := c.ImageGet(ctx, "nonexistent")
	if err == nil {
		t.Fatal("ImageGet() should fail for nonexistent image")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found', got: %v", err)
	}
}

func TestImageGet_Closed(t *testing.T) {
	c := newClosedClient(t)
	_, err := c.ImageGet(context.Background(), "img1")
	if err == nil {
		t.Fatal("ImageGet() on closed client should return error")
	}
}

// ---------------------------------------------------------------------------
// ImageRemove
// ---------------------------------------------------------------------------

func TestImageRemove(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/images/sha256:img1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		resp := []map[string]interface{}{
			{"Untagged": "nginx:latest"},
			{"Deleted": "sha256:img1"},
		}
		jsonResponse(w, http.StatusOK, resp)
	})

	deleted, err := c.ImageRemove(ctx, "sha256:img1", true, true)
	if err != nil {
		t.Fatalf("ImageRemove() error: %v", err)
	}
	if len(deleted) != 2 {
		t.Errorf("deleted len = %d, want 2", len(deleted))
	}
}

func TestImageRemove_NotFound(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/images/gone", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"No such image: gone"}`))
	})

	_, err := c.ImageRemove(ctx, "gone", false, false)
	if err == nil {
		t.Fatal("ImageRemove() should fail for nonexistent image")
	}
}

// ---------------------------------------------------------------------------
// ImageTag
// ---------------------------------------------------------------------------

func TestImageTag(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/images/nginx:latest/tag", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	if err := c.ImageTag(ctx, "nginx:latest", "myregistry/nginx:v1"); err != nil {
		t.Fatalf("ImageTag() error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ImageExists
// ---------------------------------------------------------------------------

func TestImageExists_True(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/images/nginx:latest/json", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"Id":       "sha256:img1",
			"RepoTags": []string{"nginx:latest"},
			"Created":  "2024-01-15T10:30:00Z",
			"Size":     int64(50 * 1024 * 1024),
			"Config":   map[string]interface{}{},
			"RootFS":   map[string]interface{}{"Type": "layers"},
		}
		jsonResponse(w, http.StatusOK, resp)
	})

	exists, err := c.ImageExists(ctx, "nginx:latest")
	if err != nil {
		t.Fatalf("ImageExists() error: %v", err)
	}
	if !exists {
		t.Error("ImageExists() = false, want true")
	}
}

func TestImageExists_False(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/images/gone:latest/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"No such image: gone:latest"}`))
	})

	exists, err := c.ImageExists(ctx, "gone:latest")
	if err != nil {
		t.Fatalf("ImageExists() error: %v", err)
	}
	if exists {
		t.Error("ImageExists() = true, want false")
	}
}

func TestImageExists_Closed(t *testing.T) {
	c := newClosedClient(t)
	_, err := c.ImageExists(context.Background(), "nginx")
	if err == nil {
		t.Fatal("ImageExists() on closed client should return error")
	}
}

// ---------------------------------------------------------------------------
// ImagePrune
// ---------------------------------------------------------------------------

func TestImagePrune(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/images/prune", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"ImagesDeleted": []map[string]interface{}{
				{"Untagged": "old:latest"},
			},
			"SpaceReclaimed": uint64(5000),
		}
		jsonResponse(w, http.StatusOK, resp)
	})

	space, deleted, err := c.ImagePrune(ctx, true, nil)
	if err != nil {
		t.Fatalf("ImagePrune() error: %v", err)
	}
	if space != 5000 {
		t.Errorf("space reclaimed = %d, want 5000", space)
	}
	if len(deleted) != 1 {
		t.Errorf("deleted len = %d, want 1", len(deleted))
	}
}

// ---------------------------------------------------------------------------
// Closed client: all major image operations
// ---------------------------------------------------------------------------

func TestImage_Operations_Closed(t *testing.T) {
	c := newClosedClient(t)
	ctx := context.Background()

	if _, err := c.ImageRemove(ctx, "x", false, false); err == nil {
		t.Error("ImageRemove on closed client should error")
	}
	if err := c.ImageTag(ctx, "x", "y"); err == nil {
		t.Error("ImageTag on closed client should error")
	}
	if _, _, err := c.ImagePrune(ctx, false, nil); err == nil {
		t.Error("ImagePrune on closed client should error")
	}
	if _, err := c.ImageHistory(ctx, "x"); err == nil {
		t.Error("ImageHistory on closed client should error")
	}
	if _, err := c.ImageSave(ctx, []string{"x"}); err == nil {
		t.Error("ImageSave on closed client should error")
	}
	if _, err := c.ImageDigest(ctx, "x"); err == nil {
		t.Error("ImageDigest on closed client should error")
	}
	if _, err := c.ImageSize(ctx, "x"); err == nil {
		t.Error("ImageSize on closed client should error")
	}
}
