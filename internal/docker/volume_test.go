// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package docker

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// VolumeList
// ---------------------------------------------------------------------------

func TestVolumeList(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/volumes", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		resp := map[string]interface{}{
			"Volumes": []map[string]interface{}{
				{
					"Name":       "vol-1",
					"Driver":     "local",
					"Mountpoint": "/var/lib/docker/volumes/vol-1/_data",
					"Labels":     map[string]string{},
					"Scope":      "local",
				},
				{
					"Name":       "vol-2",
					"Driver":     "local",
					"Mountpoint": "/var/lib/docker/volumes/vol-2/_data",
					"Labels":     map[string]string{"backup": "yes"},
					"Scope":      "local",
				},
			},
			"Warnings": []string{},
		}
		jsonResponse(w, http.StatusOK, resp)
	})

	volumes, err := c.VolumeList(ctx, VolumeListOptions{})
	if err != nil {
		t.Fatalf("VolumeList() error: %v", err)
	}
	if len(volumes) != 2 {
		t.Fatalf("VolumeList() len = %d, want 2", len(volumes))
	}
	if volumes[0].Name != "vol-1" {
		t.Errorf("volumes[0].Name = %q, want %q", volumes[0].Name, "vol-1")
	}
}

func TestVolumeList_Closed(t *testing.T) {
	c := newClosedClient(t)
	_, err := c.VolumeList(context.Background(), VolumeListOptions{})
	if err == nil {
		t.Fatal("VolumeList() on closed client should return error")
	}
}

// ---------------------------------------------------------------------------
// VolumeGet (inspect)
// ---------------------------------------------------------------------------

func TestVolumeGet(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/volumes/my-vol", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"Name":       "my-vol",
			"Driver":     "local",
			"Mountpoint": "/var/lib/docker/volumes/my-vol/_data",
			"Labels":     map[string]string{"env": "test"},
			"Scope":      "local",
			"Options":    map[string]string{},
			"CreatedAt":  "2024-01-15T10:30:00Z",
		}
		jsonResponse(w, http.StatusOK, resp)
	})

	vol, err := c.VolumeGet(ctx, "my-vol")
	if err != nil {
		t.Fatalf("VolumeGet() error: %v", err)
	}
	if vol.Name != "my-vol" {
		t.Errorf("Name = %q, want %q", vol.Name, "my-vol")
	}
	if vol.Driver != "local" {
		t.Errorf("Driver = %q, want %q", vol.Driver, "local")
	}
}

func TestVolumeGet_NotFound(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/volumes/gone", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"get gone: no such volume"}`))
	})

	_, err := c.VolumeGet(ctx, "gone")
	if err == nil {
		t.Fatal("VolumeGet() should fail for nonexistent volume")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found', got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// VolumeCreate
// ---------------------------------------------------------------------------

func TestVolumeCreate(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/volumes/create", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		resp := map[string]interface{}{
			"Name":       "new-vol",
			"Driver":     "local",
			"Mountpoint": "/var/lib/docker/volumes/new-vol/_data",
			"Labels":     map[string]string{"created": "true"},
			"Scope":      "local",
		}
		jsonResponse(w, http.StatusCreated, resp)
	})

	vol, err := c.VolumeCreate(ctx, VolumeCreateOptions{
		Name:   "new-vol",
		Labels: map[string]string{"created": "true"},
	})
	if err != nil {
		t.Fatalf("VolumeCreate() error: %v", err)
	}
	if vol.Name != "new-vol" {
		t.Errorf("Name = %q, want %q", vol.Name, "new-vol")
	}
}

func TestVolumeCreate_DefaultDriver(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/volumes/create", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"Name":   "auto-vol",
			"Driver": "local",
			"Scope":  "local",
		}
		jsonResponse(w, http.StatusCreated, resp)
	})

	vol, err := c.VolumeCreate(ctx, VolumeCreateOptions{
		Name: "auto-vol",
		// No driver specified — should default to "local".
	})
	if err != nil {
		t.Fatalf("VolumeCreate() error: %v", err)
	}
	if vol.Driver != "local" {
		t.Errorf("Driver = %q, want %q", vol.Driver, "local")
	}
}

func TestVolumeCreate_Closed(t *testing.T) {
	c := newClosedClient(t)
	_, err := c.VolumeCreate(context.Background(), VolumeCreateOptions{Name: "x"})
	if err == nil {
		t.Fatal("VolumeCreate() on closed client should return error")
	}
}

// ---------------------------------------------------------------------------
// VolumeRemove
// ---------------------------------------------------------------------------

func TestVolumeRemove(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/volumes/my-vol", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			// Also handle GET for other tests.
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	if err := c.VolumeRemove(ctx, "my-vol", false); err != nil {
		t.Fatalf("VolumeRemove() error: %v", err)
	}
}

func TestVolumeRemove_NotFound(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/volumes/gone", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"get gone: no such volume"}`))
	})

	err := c.VolumeRemove(ctx, "gone", false)
	if err == nil {
		t.Fatal("VolumeRemove() should fail for nonexistent volume")
	}
}

// ---------------------------------------------------------------------------
// VolumeExists
// ---------------------------------------------------------------------------

func TestVolumeExists_True(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/volumes/exists-vol", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"Name":   "exists-vol",
			"Driver": "local",
			"Scope":  "local",
		}
		jsonResponse(w, http.StatusOK, resp)
	})

	exists, err := c.VolumeExists(ctx, "exists-vol")
	if err != nil {
		t.Fatalf("VolumeExists() error: %v", err)
	}
	if !exists {
		t.Error("VolumeExists() = false, want true")
	}
}

func TestVolumeExists_False(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/volumes/nope", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"get nope: no such volume"}`))
	})

	exists, err := c.VolumeExists(ctx, "nope")
	if err != nil {
		t.Fatalf("VolumeExists() error: %v", err)
	}
	if exists {
		t.Error("VolumeExists() = true, want false")
	}
}

// ---------------------------------------------------------------------------
// VolumePrune
// ---------------------------------------------------------------------------

func TestVolumePrune(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/volumes/prune", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"VolumesDeleted": []string{"old-vol"},
			"SpaceReclaimed": uint64(2048),
		}
		jsonResponse(w, http.StatusOK, resp)
	})

	space, deleted, err := c.VolumePrune(ctx, nil)
	if err != nil {
		t.Fatalf("VolumePrune() error: %v", err)
	}
	if space != 2048 {
		t.Errorf("space reclaimed = %d, want 2048", space)
	}
	if len(deleted) != 1 {
		t.Errorf("deleted len = %d, want 1", len(deleted))
	}
}

// ---------------------------------------------------------------------------
// Closed client: volume operations
// ---------------------------------------------------------------------------

func TestVolume_Operations_Closed(t *testing.T) {
	c := newClosedClient(t)
	ctx := context.Background()

	if _, err := c.VolumeGet(ctx, "x"); err == nil {
		t.Error("VolumeGet on closed client should error")
	}
	if err := c.VolumeRemove(ctx, "x", false); err == nil {
		t.Error("VolumeRemove on closed client should error")
	}
	if _, err := c.VolumeExists(ctx, "x"); err == nil {
		t.Error("VolumeExists on closed client should error")
	}
	if _, _, err := c.VolumePrune(ctx, nil); err == nil {
		t.Error("VolumePrune on closed client should error")
	}
	if _, err := c.VolumeSize(ctx, "x"); err == nil {
		t.Error("VolumeSize on closed client should error")
	}
}
