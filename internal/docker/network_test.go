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
// NetworkList
// ---------------------------------------------------------------------------

func TestNetworkList(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/networks", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		resp := []map[string]interface{}{
			{
				"Id":     "net-1",
				"Name":   "bridge",
				"Driver": "bridge",
				"Scope":  "local",
			},
			{
				"Id":     "net-2",
				"Name":   "my-network",
				"Driver": "bridge",
				"Scope":  "local",
			},
		}
		jsonResponse(w, http.StatusOK, resp)
	})

	networks, err := c.NetworkList(ctx, NetworkListOptions{})
	if err != nil {
		t.Fatalf("NetworkList() error: %v", err)
	}
	if len(networks) != 2 {
		t.Fatalf("NetworkList() len = %d, want 2", len(networks))
	}
	if networks[0].Name != "bridge" {
		t.Errorf("networks[0].Name = %q, want %q", networks[0].Name, "bridge")
	}
}

func TestNetworkList_Closed(t *testing.T) {
	c := newClosedClient(t)
	_, err := c.NetworkList(context.Background(), NetworkListOptions{})
	if err == nil {
		t.Fatal("NetworkList() on closed client should return error")
	}
}

// ---------------------------------------------------------------------------
// NetworkGet (inspect)
// ---------------------------------------------------------------------------

func TestNetworkGet(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/networks/net-1", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"Id":         "net-1",
			"Name":       "my-network",
			"Driver":     "bridge",
			"Scope":      "local",
			"Internal":   false,
			"Attachable": true,
			"IPAM": map[string]interface{}{
				"Driver": "default",
				"Config": []map[string]interface{}{
					{"Subnet": "172.18.0.0/16", "Gateway": "172.18.0.1"},
				},
			},
			"Containers": map[string]interface{}{},
			"Options":    map[string]string{},
			"Labels":     map[string]string{},
		}
		jsonResponse(w, http.StatusOK, resp)
	})

	net, err := c.NetworkGet(ctx, "net-1")
	if err != nil {
		t.Fatalf("NetworkGet() error: %v", err)
	}
	if net.Name != "my-network" {
		t.Errorf("Name = %q, want %q", net.Name, "my-network")
	}
	if net.Driver != "bridge" {
		t.Errorf("Driver = %q, want %q", net.Driver, "bridge")
	}
}

func TestNetworkGet_NotFound(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/networks/gone", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"network gone not found"}`))
	})

	_, err := c.NetworkGet(ctx, "gone")
	if err == nil {
		t.Fatal("NetworkGet() should fail for nonexistent network")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found', got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// NetworkRemove
// ---------------------------------------------------------------------------

func TestNetworkRemove(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/networks/net-1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			// Handle GET for inspect tests too.
			resp := map[string]interface{}{
				"Id":         "net-1",
				"Name":       "my-network",
				"Driver":     "bridge",
				"Scope":      "local",
				"IPAM":       map[string]interface{}{"Config": []interface{}{}},
				"Containers": map[string]interface{}{},
			}
			jsonResponse(w, http.StatusOK, resp)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	if err := c.NetworkRemove(ctx, "net-1"); err != nil {
		t.Fatalf("NetworkRemove() error: %v", err)
	}
}

func TestNetworkRemove_NotFound(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/networks/gone", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"network gone not found"}`))
	})

	err := c.NetworkRemove(ctx, "gone")
	if err == nil {
		t.Fatal("NetworkRemove() should fail for nonexistent network")
	}
}

// ---------------------------------------------------------------------------
// NetworkExists
// ---------------------------------------------------------------------------

func TestNetworkExists_True(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/networks/net-exists", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"Id":         "net-exists",
			"Name":       "exists-net",
			"Driver":     "bridge",
			"Scope":      "local",
			"IPAM":       map[string]interface{}{"Config": []interface{}{}},
			"Containers": map[string]interface{}{},
		}
		jsonResponse(w, http.StatusOK, resp)
	})

	exists, err := c.NetworkExists(ctx, "net-exists")
	if err != nil {
		t.Fatalf("NetworkExists() error: %v", err)
	}
	if !exists {
		t.Error("NetworkExists() = false, want true")
	}
}

func TestNetworkExists_False(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/networks/nope", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"network nope not found"}`))
	})

	exists, err := c.NetworkExists(ctx, "nope")
	if err != nil {
		t.Fatalf("NetworkExists() error: %v", err)
	}
	if exists {
		t.Error("NetworkExists() = true, want false")
	}
}

// ---------------------------------------------------------------------------
// NetworkPrune
// ---------------------------------------------------------------------------

func TestNetworkPrune(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/networks/prune", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"NetworksDeleted": []string{"old-net-1", "old-net-2"},
		}
		jsonResponse(w, http.StatusOK, resp)
	})

	deleted, err := c.NetworkPrune(ctx, nil)
	if err != nil {
		t.Fatalf("NetworkPrune() error: %v", err)
	}
	if len(deleted) != 2 {
		t.Errorf("deleted len = %d, want 2", len(deleted))
	}
}

// ---------------------------------------------------------------------------
// NetworkConnect
// ---------------------------------------------------------------------------

func TestNetworkConnect(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/networks/net-1/connect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	err := c.NetworkConnect(ctx, "net-1", NetworkConnectOptions{
		ContainerID: "container-1",
		Aliases:     []string{"web"},
	})
	if err != nil {
		t.Fatalf("NetworkConnect() error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// NetworkDisconnect
// ---------------------------------------------------------------------------

func TestNetworkDisconnect(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/networks/net-1/disconnect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	err := c.NetworkDisconnect(ctx, "net-1", "container-1", false)
	if err != nil {
		t.Fatalf("NetworkDisconnect() error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Closed client: network operations
// ---------------------------------------------------------------------------

func TestNetwork_Operations_Closed(t *testing.T) {
	c := newClosedClient(t)
	ctx := context.Background()

	if _, err := c.NetworkGet(ctx, "x"); err == nil {
		t.Error("NetworkGet on closed client should error")
	}
	if _, err := c.NetworkCreate(ctx, NetworkCreateOptions{Name: "x"}); err == nil {
		t.Error("NetworkCreate on closed client should error")
	}
	if err := c.NetworkRemove(ctx, "x"); err == nil {
		t.Error("NetworkRemove on closed client should error")
	}
	if err := c.NetworkConnect(ctx, "x", NetworkConnectOptions{ContainerID: "y"}); err == nil {
		t.Error("NetworkConnect on closed client should error")
	}
	if err := c.NetworkDisconnect(ctx, "x", "y", false); err == nil {
		t.Error("NetworkDisconnect on closed client should error")
	}
	if _, err := c.NetworkExists(ctx, "x"); err == nil {
		t.Error("NetworkExists on closed client should error")
	}
	if _, err := c.NetworkPrune(ctx, nil); err == nil {
		t.Error("NetworkPrune on closed client should error")
	}
}
