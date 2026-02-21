// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package inventory

import (
	"testing"
	"time"

	"github.com/fr4nsys/usulnet/internal/gateway/protocol"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// CollectorConfig Tests
// ============================================================================

func TestCollectorConfigDefaults(t *testing.T) {
	cfg := CollectorConfig{}

	if cfg.AgentID != "" {
		t.Errorf("expected empty AgentID, got %q", cfg.AgentID)
	}
	if cfg.HostID != "" {
		t.Errorf("expected empty HostID, got %q", cfg.HostID)
	}
	if cfg.CacheTTL != 0 {
		t.Errorf("expected zero CacheTTL, got %v", cfg.CacheTTL)
	}
}

func TestCollectorConfigCustom(t *testing.T) {
	cfg := CollectorConfig{
		AgentID:  "agent-001",
		HostID:   "host-001",
		CacheTTL: 1 * time.Minute,
	}

	if cfg.AgentID != "agent-001" {
		t.Errorf("expected AgentID 'agent-001', got %q", cfg.AgentID)
	}
	if cfg.HostID != "host-001" {
		t.Errorf("expected HostID 'host-001', got %q", cfg.HostID)
	}
	if cfg.CacheTTL != 1*time.Minute {
		t.Errorf("expected CacheTTL 1m, got %v", cfg.CacheTTL)
	}
}

// ============================================================================
// NewCollector Tests
// ============================================================================

func TestNewCollectorDefaultCacheTTL(t *testing.T) {
	log := logger.Nop()
	cfg := CollectorConfig{
		AgentID: "a1",
		HostID:  "h1",
	}

	c := NewCollector(nil, cfg, log)

	if c == nil {
		t.Fatal("expected non-nil Collector")
	}
	if c.cacheTTL != 30*time.Second {
		t.Errorf("expected default CacheTTL 30s, got %v", c.cacheTTL)
	}
	if c.agentID != "a1" {
		t.Errorf("expected agentID 'a1', got %q", c.agentID)
	}
	if c.hostID != "h1" {
		t.Errorf("expected hostID 'h1', got %q", c.hostID)
	}
}

func TestNewCollectorCustomCacheTTL(t *testing.T) {
	log := logger.Nop()
	cfg := CollectorConfig{
		AgentID:  "a2",
		HostID:   "h2",
		CacheTTL: 2 * time.Minute,
	}

	c := NewCollector(nil, cfg, log)

	if c.cacheTTL != 2*time.Minute {
		t.Errorf("expected CacheTTL 2m, got %v", c.cacheTTL)
	}
}

func TestNewCollectorZeroCacheTTLGetsDefault(t *testing.T) {
	log := logger.Nop()
	cfg := CollectorConfig{CacheTTL: 0}

	c := NewCollector(nil, cfg, log)

	if c.cacheTTL != 30*time.Second {
		t.Errorf("expected default 30s for zero CacheTTL, got %v", c.cacheTTL)
	}
}

func TestNewCollectorDockerClientStored(t *testing.T) {
	log := logger.Nop()
	cfg := CollectorConfig{}

	// Passing nil docker client: the constructor stores it but doesn't use it
	c := NewCollector(nil, cfg, log)

	if c.docker != nil {
		t.Error("expected nil docker client when nil was passed")
	}
}

// ============================================================================
// GetCached Tests (no docker dependency)
// ============================================================================

func TestGetCachedEmpty(t *testing.T) {
	log := logger.Nop()
	cfg := CollectorConfig{CacheTTL: 1 * time.Minute}
	c := NewCollector(nil, cfg, log)

	inv, ok := c.GetCached()
	if ok {
		t.Error("expected ok=false when no inventory cached")
	}
	if inv != nil {
		t.Error("expected nil inventory when not cached")
	}
}

func TestGetCachedValid(t *testing.T) {
	log := logger.Nop()
	cfg := CollectorConfig{CacheTTL: 1 * time.Minute}
	c := NewCollector(nil, cfg, log)

	// Manually set cache
	inv := &protocol.Inventory{AgentID: "test"}
	c.lastInventory = inv
	c.lastCollected = time.Now()

	cached, ok := c.GetCached()
	if !ok {
		t.Error("expected ok=true for valid cache")
	}
	if cached == nil {
		t.Fatal("expected non-nil cached inventory")
	}
	if cached.AgentID != "test" {
		t.Errorf("expected AgentID 'test', got %q", cached.AgentID)
	}
}

func TestGetCachedExpired(t *testing.T) {
	log := logger.Nop()
	cfg := CollectorConfig{CacheTTL: 1 * time.Millisecond}
	c := NewCollector(nil, cfg, log)

	c.lastInventory = &protocol.Inventory{AgentID: "old"}
	c.lastCollected = time.Now().Add(-1 * time.Second) // Well past the 1ms TTL

	inv, ok := c.GetCached()
	if ok {
		t.Error("expected ok=false for expired cache")
	}
	if inv != nil {
		t.Error("expected nil inventory for expired cache")
	}
}

// ============================================================================
// InventoryDiff Tests
// ============================================================================

func TestDiffNoChanges(t *testing.T) {
	old := &protocol.Inventory{
		Containers: []protocol.ContainerInfo{
			{ID: "c1", State: "running"},
		},
		Images:   []protocol.ImageInfo{{ID: "i1"}},
		Volumes:  []protocol.VolumeInfo{{Name: "v1"}},
		Networks: []protocol.NetworkInfo{{ID: "n1"}},
	}

	diff := Diff(old, old)

	if diff.HasChanges() {
		t.Error("expected no changes for identical inventories")
	}
}

func TestDiffAddedResources(t *testing.T) {
	old := &protocol.Inventory{}
	newInv := &protocol.Inventory{
		Containers: []protocol.ContainerInfo{{ID: "c1", State: "running"}},
		Images:     []protocol.ImageInfo{{ID: "i1"}},
		Volumes:    []protocol.VolumeInfo{{Name: "v1"}},
		Networks:   []protocol.NetworkInfo{{ID: "n1"}},
	}

	diff := Diff(old, newInv)

	if !diff.HasChanges() {
		t.Error("expected changes")
	}
	if len(diff.AddedContainers) != 1 || diff.AddedContainers[0] != "c1" {
		t.Errorf("expected added container c1, got %v", diff.AddedContainers)
	}
	if len(diff.AddedImages) != 1 || diff.AddedImages[0] != "i1" {
		t.Errorf("expected added image i1, got %v", diff.AddedImages)
	}
	if len(diff.AddedVolumes) != 1 || diff.AddedVolumes[0] != "v1" {
		t.Errorf("expected added volume v1, got %v", diff.AddedVolumes)
	}
	if len(diff.AddedNetworks) != 1 || diff.AddedNetworks[0] != "n1" {
		t.Errorf("expected added network n1, got %v", diff.AddedNetworks)
	}
}

func TestDiffRemovedResources(t *testing.T) {
	old := &protocol.Inventory{
		Containers: []protocol.ContainerInfo{{ID: "c1", State: "running"}},
		Images:     []protocol.ImageInfo{{ID: "i1"}},
		Volumes:    []protocol.VolumeInfo{{Name: "v1"}},
		Networks:   []protocol.NetworkInfo{{ID: "n1"}},
	}
	newInv := &protocol.Inventory{}

	diff := Diff(old, newInv)

	if !diff.HasChanges() {
		t.Error("expected changes")
	}
	if len(diff.RemovedContainers) != 1 || diff.RemovedContainers[0] != "c1" {
		t.Errorf("expected removed container c1, got %v", diff.RemovedContainers)
	}
	if len(diff.RemovedImages) != 1 || diff.RemovedImages[0] != "i1" {
		t.Errorf("expected removed image i1, got %v", diff.RemovedImages)
	}
	if len(diff.RemovedVolumes) != 1 || diff.RemovedVolumes[0] != "v1" {
		t.Errorf("expected removed volume v1, got %v", diff.RemovedVolumes)
	}
	if len(diff.RemovedNetworks) != 1 || diff.RemovedNetworks[0] != "n1" {
		t.Errorf("expected removed network n1, got %v", diff.RemovedNetworks)
	}
}

func TestDiffChangedContainerState(t *testing.T) {
	old := &protocol.Inventory{
		Containers: []protocol.ContainerInfo{
			{ID: "c1", State: "running"},
		},
	}
	newInv := &protocol.Inventory{
		Containers: []protocol.ContainerInfo{
			{ID: "c1", State: "exited"},
		},
	}

	diff := Diff(old, newInv)

	if !diff.HasChanges() {
		t.Error("expected changes for state change")
	}
	if len(diff.ChangedContainers) != 1 || diff.ChangedContainers[0] != "c1" {
		t.Errorf("expected changed container c1, got %v", diff.ChangedContainers)
	}
	if len(diff.AddedContainers) != 0 {
		t.Errorf("expected no added containers, got %v", diff.AddedContainers)
	}
	if len(diff.RemovedContainers) != 0 {
		t.Errorf("expected no removed containers, got %v", diff.RemovedContainers)
	}
}

func TestDiffMixedChanges(t *testing.T) {
	old := &protocol.Inventory{
		Containers: []protocol.ContainerInfo{
			{ID: "c1", State: "running"},
			{ID: "c2", State: "running"},
		},
		Images: []protocol.ImageInfo{
			{ID: "i1"},
			{ID: "i2"},
		},
	}
	newInv := &protocol.Inventory{
		Containers: []protocol.ContainerInfo{
			{ID: "c1", State: "exited"}, // Changed
			{ID: "c3", State: "running"}, // Added
		},
		Images: []protocol.ImageInfo{
			{ID: "i2"}, // i1 removed
			{ID: "i3"}, // i3 added
		},
	}

	diff := Diff(old, newInv)

	if !diff.HasChanges() {
		t.Error("expected changes")
	}
	if len(diff.ChangedContainers) != 1 {
		t.Errorf("expected 1 changed container, got %d", len(diff.ChangedContainers))
	}
	if len(diff.AddedContainers) != 1 {
		t.Errorf("expected 1 added container, got %d", len(diff.AddedContainers))
	}
	if len(diff.RemovedContainers) != 1 {
		t.Errorf("expected 1 removed container, got %d", len(diff.RemovedContainers))
	}
	if len(diff.AddedImages) != 1 {
		t.Errorf("expected 1 added image, got %d", len(diff.AddedImages))
	}
	if len(diff.RemovedImages) != 1 {
		t.Errorf("expected 1 removed image, got %d", len(diff.RemovedImages))
	}
}

func TestInventoryDiffHasChanges(t *testing.T) {
	// Empty diff
	d := &InventoryDiff{}
	if d.HasChanges() {
		t.Error("expected no changes for empty diff")
	}

	// Each field individually triggers HasChanges
	fields := []struct {
		name string
		set  func(d *InventoryDiff)
	}{
		{"AddedContainers", func(d *InventoryDiff) { d.AddedContainers = []string{"c1"} }},
		{"RemovedContainers", func(d *InventoryDiff) { d.RemovedContainers = []string{"c1"} }},
		{"ChangedContainers", func(d *InventoryDiff) { d.ChangedContainers = []string{"c1"} }},
		{"AddedImages", func(d *InventoryDiff) { d.AddedImages = []string{"i1"} }},
		{"RemovedImages", func(d *InventoryDiff) { d.RemovedImages = []string{"i1"} }},
		{"AddedVolumes", func(d *InventoryDiff) { d.AddedVolumes = []string{"v1"} }},
		{"RemovedVolumes", func(d *InventoryDiff) { d.RemovedVolumes = []string{"v1"} }},
		{"AddedNetworks", func(d *InventoryDiff) { d.AddedNetworks = []string{"n1"} }},
		{"RemovedNetworks", func(d *InventoryDiff) { d.RemovedNetworks = []string{"n1"} }},
	}

	for _, f := range fields {
		t.Run(f.name, func(t *testing.T) {
			diff := &InventoryDiff{}
			f.set(diff)
			if !diff.HasChanges() {
				t.Errorf("expected HasChanges true when %s is set", f.name)
			}
		})
	}
}

func TestDiffBothEmpty(t *testing.T) {
	old := &protocol.Inventory{}
	newInv := &protocol.Inventory{}

	diff := Diff(old, newInv)

	if diff.HasChanges() {
		t.Error("expected no changes for two empty inventories")
	}
}
