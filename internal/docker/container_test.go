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
// ContainerList
// ---------------------------------------------------------------------------

func TestContainerList(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		resp := []map[string]interface{}{
			{
				"Id":      "container-1",
				"Names":   []string{"/web"},
				"Image":   "nginx:latest",
				"ImageID": "sha256:img1",
				"Command": "nginx",
				"State":   "running",
				"Status":  "Up 5 minutes",
				"Created": time.Now().Unix(),
			},
			{
				"Id":      "container-2",
				"Names":   []string{"/db"},
				"Image":   "postgres:16",
				"ImageID": "sha256:img2",
				"Command": "postgres",
				"State":   "running",
				"Status":  "Up 10 minutes",
				"Created": time.Now().Unix(),
			},
		}
		jsonResponse(w, http.StatusOK, resp)
	})

	containers, err := c.ContainerList(ctx, ContainerListOptions{All: true})
	if err != nil {
		t.Fatalf("ContainerList() error: %v", err)
	}
	if len(containers) != 2 {
		t.Fatalf("ContainerList() len = %d, want 2", len(containers))
	}
	if containers[0].ID != "container-1" {
		t.Errorf("containers[0].ID = %q, want %q", containers[0].ID, "container-1")
	}
	if containers[0].Name != "web" {
		t.Errorf("containers[0].Name = %q, want %q", containers[0].Name, "web")
	}
}

func TestContainerList_Closed(t *testing.T) {
	c := newClosedClient(t)
	ctx := context.Background()

	_, err := c.ContainerList(ctx, ContainerListOptions{})
	if err == nil {
		t.Fatal("ContainerList() on closed client should return error")
	}
}

// ---------------------------------------------------------------------------
// ContainerGet (inspect)
// ---------------------------------------------------------------------------

func TestContainerGet(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/containers/abc123/json", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"Id":      "abc123",
			"Created": "2024-01-15T10:30:00.000000000Z",
			"Name":    "/my-container",
			"Image":   "sha256:img1",
			"State": map[string]interface{}{
				"Status":     "running",
				"StartedAt":  "2024-01-15T10:30:01.000000000Z",
				"FinishedAt": "0001-01-01T00:00:00Z",
			},
			"Config": map[string]interface{}{
				"Image":  "nginx:latest",
				"Labels": map[string]string{},
			},
			"HostConfig": map[string]interface{}{
				"NetworkMode": "bridge",
				"RestartPolicy": map[string]interface{}{
					"Name":              "",
					"MaximumRetryCount": 0,
				},
				"LogConfig": map[string]interface{}{
					"Type":   "json-file",
					"Config": map[string]string{},
				},
			},
			"NetworkSettings": map[string]interface{}{
				"Networks": map[string]interface{}{},
				"Ports":    map[string]interface{}{},
			},
			"Mounts":       []interface{}{},
			"Path":         "/entrypoint.sh",
			"Args":         []string{},
			"Driver":       "overlay2",
			"MountLabel":   "",
			"ProcessLabel": "",
			"LogPath":      "",
			"RestartCount": 0,
		}
		jsonResponse(w, http.StatusOK, resp)
	})

	details, err := c.ContainerGet(ctx, "abc123")
	if err != nil {
		t.Fatalf("ContainerGet() error: %v", err)
	}
	if details.ID != "abc123" {
		t.Errorf("ID = %q, want %q", details.ID, "abc123")
	}
	if details.Name != "my-container" {
		t.Errorf("Name = %q, want %q", details.Name, "my-container")
	}
}

func TestContainerGet_NotFound(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/containers/nonexistent/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"No such container: nonexistent"}`))
	})

	_, err := c.ContainerGet(ctx, "nonexistent")
	if err == nil {
		t.Fatal("ContainerGet() should fail for nonexistent container")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found', got: %v", err)
	}
}

func TestContainerGet_Closed(t *testing.T) {
	c := newClosedClient(t)
	ctx := context.Background()

	_, err := c.ContainerGet(ctx, "abc123")
	if err == nil {
		t.Fatal("ContainerGet() on closed client should return error")
	}
}

// ---------------------------------------------------------------------------
// ContainerStart
// ---------------------------------------------------------------------------

func TestContainerStart(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/containers/abc123/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	if err := c.ContainerStart(ctx, "abc123"); err != nil {
		t.Fatalf("ContainerStart() error: %v", err)
	}
}

func TestContainerStart_NotFound(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/containers/gone/start", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"No such container: gone"}`))
	})

	err := c.ContainerStart(ctx, "gone")
	if err == nil {
		t.Fatal("ContainerStart() should fail for nonexistent container")
	}
}

func TestContainerStart_Closed(t *testing.T) {
	c := newClosedClient(t)
	if err := c.ContainerStart(context.Background(), "abc123"); err == nil {
		t.Fatal("ContainerStart() on closed client should return error")
	}
}

// ---------------------------------------------------------------------------
// ContainerStop
// ---------------------------------------------------------------------------

func TestContainerStop(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/containers/abc123/stop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	if err := c.ContainerStop(ctx, "abc123", nil); err != nil {
		t.Fatalf("ContainerStop() error: %v", err)
	}

	// With timeout.
	timeout := 10
	if err := c.ContainerStop(ctx, "abc123", &timeout); err != nil {
		t.Fatalf("ContainerStop(timeout=10) error: %v", err)
	}
}

func TestContainerStop_NotFound(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/containers/gone/stop", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"No such container: gone"}`))
	})

	err := c.ContainerStop(ctx, "gone", nil)
	if err == nil {
		t.Fatal("ContainerStop() should fail for nonexistent container")
	}
}

// ---------------------------------------------------------------------------
// ContainerRestart
// ---------------------------------------------------------------------------

func TestContainerRestart(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/containers/abc123/restart", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	if err := c.ContainerRestart(ctx, "abc123", nil); err != nil {
		t.Fatalf("ContainerRestart() error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ContainerKill
// ---------------------------------------------------------------------------

func TestContainerKill(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/containers/abc123/kill", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	if err := c.ContainerKill(ctx, "abc123", "SIGTERM"); err != nil {
		t.Fatalf("ContainerKill() error: %v", err)
	}

	// Empty signal defaults to SIGKILL.
	if err := c.ContainerKill(ctx, "abc123", ""); err != nil {
		t.Fatalf("ContainerKill(empty signal) error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ContainerPause / Unpause
// ---------------------------------------------------------------------------

func TestContainerPause(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/containers/abc123/pause", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	if err := c.ContainerPause(ctx, "abc123"); err != nil {
		t.Fatalf("ContainerPause() error: %v", err)
	}
}

func TestContainerUnpause(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/containers/abc123/unpause", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	if err := c.ContainerUnpause(ctx, "abc123"); err != nil {
		t.Fatalf("ContainerUnpause() error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ContainerRename
// ---------------------------------------------------------------------------

func TestContainerRename(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/containers/abc123/rename", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	if err := c.ContainerRename(ctx, "abc123", "new-name"); err != nil {
		t.Fatalf("ContainerRename() error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ContainerRemove
// ---------------------------------------------------------------------------

func TestContainerRemove(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/containers/abc123", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	if err := c.ContainerRemove(ctx, "abc123", true, false); err != nil {
		t.Fatalf("ContainerRemove() error: %v", err)
	}
}

func TestContainerRemove_NotFound(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/containers/gone", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"No such container: gone"}`))
	})

	err := c.ContainerRemove(ctx, "gone", false, false)
	if err == nil {
		t.Fatal("ContainerRemove() should fail for nonexistent container")
	}
}

// ---------------------------------------------------------------------------
// ContainerPrune
// ---------------------------------------------------------------------------

func TestContainerPrune(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/containers/prune", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"ContainersDeleted": []string{"c1", "c2"},
			"SpaceReclaimed":    uint64(1024),
		}
		jsonResponse(w, http.StatusOK, resp)
	})

	space, deleted, err := c.ContainerPrune(ctx, nil)
	if err != nil {
		t.Fatalf("ContainerPrune() error: %v", err)
	}
	if space != 1024 {
		t.Errorf("space reclaimed = %d, want 1024", space)
	}
	if len(deleted) != 2 {
		t.Errorf("deleted len = %d, want 2", len(deleted))
	}
}

// ---------------------------------------------------------------------------
// ContainerCreate
// ---------------------------------------------------------------------------

func TestContainerCreate(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/containers/create", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		resp := map[string]interface{}{
			"Id":       "new-container-id",
			"Warnings": []string{},
		}
		jsonResponse(w, http.StatusCreated, resp)
	})

	id, err := c.ContainerCreate(ctx, ContainerCreateOptions{
		Name:  "test-container",
		Image: "nginx:latest",
		Env:   []string{"FOO=bar"},
	})
	if err != nil {
		t.Fatalf("ContainerCreate() error: %v", err)
	}
	if id != "new-container-id" {
		t.Errorf("ContainerCreate() id = %q, want %q", id, "new-container-id")
	}
}

func TestContainerCreate_Closed(t *testing.T) {
	c := newClosedClient(t)
	_, err := c.ContainerCreate(context.Background(), ContainerCreateOptions{
		Name:  "test",
		Image: "nginx",
	})
	if err == nil {
		t.Fatal("ContainerCreate() on closed client should return error")
	}
}

// ---------------------------------------------------------------------------
// Closed client: all major operations
// ---------------------------------------------------------------------------

func TestContainer_Operations_Closed(t *testing.T) {
	c := newClosedClient(t)
	ctx := context.Background()

	// Each should return an error on a closed client.
	if err := c.ContainerStop(ctx, "x", nil); err == nil {
		t.Error("ContainerStop on closed client should error")
	}
	if err := c.ContainerRestart(ctx, "x", nil); err == nil {
		t.Error("ContainerRestart on closed client should error")
	}
	if err := c.ContainerKill(ctx, "x", "SIGKILL"); err == nil {
		t.Error("ContainerKill on closed client should error")
	}
	if err := c.ContainerPause(ctx, "x"); err == nil {
		t.Error("ContainerPause on closed client should error")
	}
	if err := c.ContainerUnpause(ctx, "x"); err == nil {
		t.Error("ContainerUnpause on closed client should error")
	}
	if err := c.ContainerRename(ctx, "x", "y"); err == nil {
		t.Error("ContainerRename on closed client should error")
	}
	if err := c.ContainerRemove(ctx, "x", false, false); err == nil {
		t.Error("ContainerRemove on closed client should error")
	}
	if err := c.ContainerUpdate(ctx, "x", Resources{}); err == nil {
		t.Error("ContainerUpdate on closed client should error")
	}
	if _, _, err := c.ContainerPrune(ctx, nil); err == nil {
		t.Error("ContainerPrune on closed client should error")
	}
	if _, err := c.ContainerTop(ctx, "x", ""); err == nil {
		t.Error("ContainerTop on closed client should error")
	}
	if _, err := c.ContainerDiff(ctx, "x"); err == nil {
		t.Error("ContainerDiff on closed client should error")
	}
	if _, err := c.ContainerExport(ctx, "x"); err == nil {
		t.Error("ContainerExport on closed client should error")
	}
	if _, err := c.ContainerCommit(ctx, "x", CommitOptions{}); err == nil {
		t.Error("ContainerCommit on closed client should error")
	}
	if _, err := c.ContainerWait(ctx, "x"); err == nil {
		t.Error("ContainerWait on closed client should error")
	}
	if _, err := c.ContainerLogs(ctx, "x", LogOptions{Stdout: true}); err == nil {
		t.Error("ContainerLogs on closed client should error")
	}
}
