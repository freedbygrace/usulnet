// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package docker

import (
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	dockerevents "github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/go-connections/nat"
)

// ---------------------------------------------------------------------------
// ContainerFromSummary
// ---------------------------------------------------------------------------

func TestContainerFromSummary(t *testing.T) {
	created := time.Now().Unix()
	summary := types.Container{
		ID:      "abc123",
		Names:   []string{"/my-container"},
		Image:   "nginx:latest",
		ImageID: "sha256:abc123",
		Command: "/entrypoint.sh",
		Status:  "Up 5 minutes",
		State:   "running",
		Created: created,
		Labels:  map[string]string{"env": "prod"},
		Ports: []types.Port{
			{PrivatePort: 80, PublicPort: 8080, Type: "tcp", IP: "0.0.0.0"},
		},
		Mounts: []types.MountPoint{
			{
				Type:        mount.TypeVolume,
				Name:        "data",
				Source:      "/var/lib/docker/volumes/data/_data",
				Destination: "/data",
				Mode:        "rw",
				RW:          true,
			},
		},
		SizeRw:     1024,
		SizeRootFs: 4096,
	}

	c := ContainerFromSummary(summary)

	if c.ID != "abc123" {
		t.Errorf("ID = %q, want %q", c.ID, "abc123")
	}
	if c.Name != "my-container" {
		t.Errorf("Name = %q, want %q (leading / should be stripped)", c.Name, "my-container")
	}
	if c.Image != "nginx:latest" {
		t.Errorf("Image = %q, want %q", c.Image, "nginx:latest")
	}
	if c.State != "running" {
		t.Errorf("State = %q, want %q", c.State, "running")
	}
	if c.Created.Unix() != created {
		t.Errorf("Created = %v, want %v", c.Created.Unix(), created)
	}
	if len(c.Ports) != 1 {
		t.Fatalf("Ports len = %d, want 1", len(c.Ports))
	}
	if c.Ports[0].PublicPort != 8080 {
		t.Errorf("Ports[0].PublicPort = %d, want 8080", c.Ports[0].PublicPort)
	}
	if len(c.Mounts) != 1 {
		t.Fatalf("Mounts len = %d, want 1", len(c.Mounts))
	}
	if c.Mounts[0].Name != "data" {
		t.Errorf("Mounts[0].Name = %q, want %q", c.Mounts[0].Name, "data")
	}
	if c.SizeRw != 1024 {
		t.Errorf("SizeRw = %d, want 1024", c.SizeRw)
	}
}

func TestContainerFromSummary_NoNames(t *testing.T) {
	summary := types.Container{
		ID:    "abc123",
		Names: []string{},
	}
	c := ContainerFromSummary(summary)
	if c.Name != "" {
		t.Errorf("Name should be empty when no names, got %q", c.Name)
	}
}

func TestContainerFromSummary_WithNetworkSettings(t *testing.T) {
	summary := types.Container{
		ID:    "abc123",
		Names: []string{"/test"},
		NetworkSettings: &types.SummaryNetworkSettings{
			Networks: map[string]*network.EndpointSettings{
				"bridge": {
					NetworkID:  "net-123",
					EndpointID: "ep-456",
					IPAddress:  "172.17.0.2",
					Gateway:    "172.17.0.1",
				},
			},
		},
	}

	c := ContainerFromSummary(summary)
	if len(c.Networks) != 1 {
		t.Fatalf("Networks len = %d, want 1", len(c.Networks))
	}
	if c.Networks[0].IPAddress != "172.17.0.2" {
		t.Errorf("Networks[0].IPAddress = %q, want %q", c.Networks[0].IPAddress, "172.17.0.2")
	}
	if c.Networks[0].NetworkName != "bridge" {
		t.Errorf("Networks[0].NetworkName = %q, want %q", c.Networks[0].NetworkName, "bridge")
	}
}

// ---------------------------------------------------------------------------
// ContainerFromInspect
// ---------------------------------------------------------------------------

func TestContainerFromInspect(t *testing.T) {
	createdStr := "2024-01-15T10:30:00.000000000Z"
	startedStr := "2024-01-15T10:30:01.000000000Z"
	finishedStr := "0001-01-01T00:00:00Z"

	inspect := types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:      "abc123",
			Created: createdStr,
			Name:    "/my-container",
			Image:   "sha256:img123",
			State: &types.ContainerState{
				Status:     "running",
				StartedAt:  startedStr,
				FinishedAt: finishedStr,
			},
			Driver:       "overlay2",
			MountLabel:   "label1",
			ProcessLabel: "proc1",
			LogPath:      "/var/log/container.log",
			Path:         "/entrypoint.sh",
			Args:         []string{"--flag"},
			RestartCount: 2,
			HostConfig: &container.HostConfig{
				Binds:       []string{"/host:/container"},
				NetworkMode: "bridge",
				RestartPolicy: container.RestartPolicy{
					Name:              "always",
					MaximumRetryCount: 5,
				},
				Resources: container.Resources{
					Memory:    536870912,
					CPUShares: 512,
				},
				LogConfig: container.LogConfig{
					Type:   "json-file",
					Config: map[string]string{"max-size": "10m"},
				},
			},
		},
		Config: &container.Config{
			Hostname: "abc123",
			Image:    "nginx:latest",
			Env:      []string{"KEY=value"},
			Cmd:      []string{"nginx", "-g", "daemon off;"},
			Labels:   map[string]string{"app": "web"},
			Tty:      true,
		},
		NetworkSettings: &types.NetworkSettings{
			Networks: map[string]*network.EndpointSettings{
				"bridge": {
					NetworkID: "net-1",
					IPAddress: "172.17.0.2",
				},
			},
			NetworkSettingsBase: types.NetworkSettingsBase{
				Ports: nat.PortMap{
					"80/tcp": []nat.PortBinding{
						{HostIP: "0.0.0.0", HostPort: "8080"},
					},
					"443/tcp": nil, // exposed but not published
				},
			},
		},
		Mounts: []types.MountPoint{
			{
				Type:        mount.TypeBind,
				Source:      "/host",
				Destination: "/container",
				RW:          true,
			},
		},
	}

	d := ContainerFromInspect(inspect)

	if d.ID != "abc123" {
		t.Errorf("ID = %q, want %q", d.ID, "abc123")
	}
	if d.Name != "my-container" {
		t.Errorf("Name = %q, want %q", d.Name, "my-container")
	}
	if d.State != "running" {
		t.Errorf("State = %q, want %q", d.State, "running")
	}
	if d.Driver != "overlay2" {
		t.Errorf("Driver = %q, want %q", d.Driver, "overlay2")
	}
	if d.Config == nil {
		t.Fatal("Config is nil")
	}
	if d.Config.Tty != true {
		t.Error("Config.Tty should be true")
	}
	if d.HostConfig == nil {
		t.Fatal("HostConfig is nil")
	}
	if d.HostConfig.Resources.Memory != 536870912 {
		t.Errorf("Memory = %d, want 536870912", d.HostConfig.Resources.Memory)
	}
	if len(d.Networks) != 1 {
		t.Fatalf("Networks len = %d, want 1", len(d.Networks))
	}
	if len(d.Mounts) != 1 {
		t.Fatalf("Mounts len = %d, want 1", len(d.Mounts))
	}
	// Port check: should have both 80/tcp (published) and 443/tcp (exposed-only).
	if len(d.Ports) != 2 {
		t.Fatalf("Ports len = %d, want 2", len(d.Ports))
	}
}

// ---------------------------------------------------------------------------
// ImageFromSummary
// ---------------------------------------------------------------------------

func TestImageFromSummary(t *testing.T) {
	created := time.Now().Unix()
	summary := image.Summary{
		ID:          "sha256:abc123",
		ParentID:    "sha256:parent",
		RepoTags:    []string{"nginx:latest"},
		RepoDigests: []string{"nginx@sha256:digest123"},
		Created:     created,
		Size:        100 * 1024 * 1024,
		SharedSize:  50 * 1024 * 1024,
		VirtualSize: 150 * 1024 * 1024,
		Labels:      map[string]string{"maintainer": "test"},
		Containers:  3,
	}

	img := ImageFromSummary(summary)

	if img.ID != "sha256:abc123" {
		t.Errorf("ID = %q, want %q", img.ID, "sha256:abc123")
	}
	if len(img.RepoTags) != 1 || img.RepoTags[0] != "nginx:latest" {
		t.Errorf("RepoTags = %v, want [nginx:latest]", img.RepoTags)
	}
	if img.Size != 100*1024*1024 {
		t.Errorf("Size = %d, want %d", img.Size, 100*1024*1024)
	}
	if img.Containers != 3 {
		t.Errorf("Containers = %d, want 3", img.Containers)
	}
}

// ---------------------------------------------------------------------------
// ImageFromInspect
// ---------------------------------------------------------------------------

func TestImageFromInspect(t *testing.T) {
	inspect := types.ImageInspect{
		ID:            "sha256:abc123",
		Parent:        "sha256:parent",
		RepoTags:      []string{"nginx:latest"},
		RepoDigests:   []string{"nginx@sha256:digest123"},
		Created:       "2024-01-15T10:30:00Z",
		Size:          100 * 1024 * 1024,
		VirtualSize:   150 * 1024 * 1024,
		Architecture:  "amd64",
		Author:        "test-author",
		Comment:       "test comment",
		DockerVersion: "27.0.0",
		Os:            "linux",
		// Config is intentionally nil here; the Labels path is tested
		// by verifying that ImageFromInspect handles nil Config gracefully.
		RootFS: types.RootFS{
			Type:   "layers",
			Layers: []string{"sha256:layer1", "sha256:layer2"},
		},
	}

	d := ImageFromInspect(inspect)

	if d.ID != "sha256:abc123" {
		t.Errorf("ID = %q, want %q", d.ID, "sha256:abc123")
	}
	if d.Architecture != "amd64" {
		t.Errorf("Architecture = %q, want %q", d.Architecture, "amd64")
	}
	if d.OS != "linux" {
		t.Errorf("OS = %q, want %q", d.OS, "linux")
	}
	// Config is nil, so Labels should also be nil.
	if d.Labels != nil {
		t.Errorf("Labels should be nil when Config is nil, got %v", d.Labels)
	}
	if d.RootFS.Type != "layers" {
		t.Errorf("RootFS.Type = %q, want %q", d.RootFS.Type, "layers")
	}
	if len(d.RootFS.Layers) != 2 {
		t.Errorf("RootFS.Layers len = %d, want 2", len(d.RootFS.Layers))
	}
}

// ---------------------------------------------------------------------------
// VolumeFromDocker
// ---------------------------------------------------------------------------

func TestVolumeFromDocker(t *testing.T) {
	vol := volume.Volume{
		Name:       "my-volume",
		Driver:     "local",
		Mountpoint: "/var/lib/docker/volumes/my-volume/_data",
		Labels:     map[string]string{"backup": "true"},
		Scope:      "local",
		Options:    map[string]string{"type": "nfs"},
		CreatedAt:  "2024-01-15T10:30:00Z",
		UsageData: &volume.UsageData{
			Size:     1024,
			RefCount: 2,
		},
	}

	v := VolumeFromDocker(vol)

	if v.Name != "my-volume" {
		t.Errorf("Name = %q, want %q", v.Name, "my-volume")
	}
	if v.Driver != "local" {
		t.Errorf("Driver = %q, want %q", v.Driver, "local")
	}
	if v.Labels["backup"] != "true" {
		t.Errorf("Labels[backup] = %q, want %q", v.Labels["backup"], "true")
	}
	if v.UsageData == nil {
		t.Fatal("UsageData is nil")
	}
	if v.UsageData.Size != 1024 {
		t.Errorf("UsageData.Size = %d, want 1024", v.UsageData.Size)
	}
	if v.CreatedAt.IsZero() {
		t.Error("CreatedAt should be parsed")
	}
}

func TestVolumeFromDocker_NoUsageData(t *testing.T) {
	vol := volume.Volume{
		Name:   "empty-vol",
		Driver: "local",
	}

	v := VolumeFromDocker(vol)
	if v.UsageData != nil {
		t.Error("UsageData should be nil")
	}
}

// ---------------------------------------------------------------------------
// NetworkFromDocker
// ---------------------------------------------------------------------------

func TestNetworkFromDocker(t *testing.T) {
	created := time.Now()
	inspect := network.Inspect{
		ID:         "net-abc123",
		Name:       "my-network",
		Driver:     "bridge",
		Scope:      "local",
		EnableIPv6: false,
		Internal:   true,
		Attachable: true,
		Ingress:    false,
		ConfigOnly: false,
		Created:    created,
		Options:    map[string]string{"com.docker.network.bridge.name": "br-abc"},
		Labels:     map[string]string{"env": "prod"},
		IPAM: network.IPAM{
			Driver: "default",
			Config: []network.IPAMConfig{
				{
					Subnet:  "172.20.0.0/16",
					Gateway: "172.20.0.1",
				},
			},
		},
		Containers: map[string]network.EndpointResource{
			"cid-1": {
				Name:        "container-1",
				EndpointID:  "ep-1",
				MacAddress:  "02:42:ac:14:00:02",
				IPv4Address: "172.20.0.2/16",
			},
		},
	}

	n := NetworkFromDocker(inspect)

	if n.ID != "net-abc123" {
		t.Errorf("ID = %q, want %q", n.ID, "net-abc123")
	}
	if n.Name != "my-network" {
		t.Errorf("Name = %q, want %q", n.Name, "my-network")
	}
	if n.Driver != "bridge" {
		t.Errorf("Driver = %q, want %q", n.Driver, "bridge")
	}
	if !n.Internal {
		t.Error("Internal should be true")
	}
	if !n.Attachable {
		t.Error("Attachable should be true")
	}
	if n.IPAM.Driver != "default" {
		t.Errorf("IPAM.Driver = %q, want %q", n.IPAM.Driver, "default")
	}
	if len(n.IPAM.Config) != 1 {
		t.Fatalf("IPAM.Config len = %d, want 1", len(n.IPAM.Config))
	}
	if n.IPAM.Config[0].Subnet != "172.20.0.0/16" {
		t.Errorf("IPAM.Config[0].Subnet = %q, want %q", n.IPAM.Config[0].Subnet, "172.20.0.0/16")
	}
	if len(n.Containers) != 1 {
		t.Fatalf("Containers len = %d, want 1", len(n.Containers))
	}
	if nc, ok := n.Containers["cid-1"]; !ok {
		t.Error("missing container cid-1")
	} else if nc.Name != "container-1" {
		t.Errorf("Containers[cid-1].Name = %q, want %q", nc.Name, "container-1")
	}
}

func TestNetworkFromResource_IsAlias(t *testing.T) {
	inspect := network.Inspect{
		ID:   "net-1",
		Name: "test",
	}
	a := NetworkFromDocker(inspect)
	b := NetworkFromResource(inspect)
	if a.ID != b.ID || a.Name != b.Name {
		t.Error("NetworkFromResource should delegate to NetworkFromDocker")
	}
}

// ---------------------------------------------------------------------------
// Stats calculations
// ---------------------------------------------------------------------------

func TestCalculateCPUPercent(t *testing.T) {
	stats := &container.StatsResponse{
		CPUStats: container.CPUStats{
			CPUUsage: container.CPUUsage{
				TotalUsage: 200_000_000,
			},
			SystemUsage: 1_000_000_000,
			OnlineCPUs:  4,
		},
		PreCPUStats: container.CPUStats{
			CPUUsage: container.CPUUsage{
				TotalUsage: 100_000_000,
			},
			SystemUsage: 800_000_000,
		},
	}

	pct := CalculateCPUPercent(stats)
	// CPU delta = 100M, system delta = 200M, 4 CPUs => (100M/200M)*4*100 = 200%
	if pct < 199.9 || pct > 200.1 {
		t.Errorf("CalculateCPUPercent() = %.2f, want ~200.0", pct)
	}
}

func TestCalculateCPUPercent_ZeroDelta(t *testing.T) {
	stats := &container.StatsResponse{
		CPUStats: container.CPUStats{
			CPUUsage:    container.CPUUsage{TotalUsage: 100},
			SystemUsage: 100,
		},
		PreCPUStats: container.CPUStats{
			CPUUsage:    container.CPUUsage{TotalUsage: 100},
			SystemUsage: 100,
		},
	}
	pct := CalculateCPUPercent(stats)
	if pct != 0.0 {
		t.Errorf("CalculateCPUPercent() = %.2f, want 0.0 for zero delta", pct)
	}
}

func TestCalculateMemoryPercent(t *testing.T) {
	stats := &container.StatsResponse{
		MemoryStats: container.MemoryStats{
			Usage: 512 * 1024 * 1024,
			Limit: 1024 * 1024 * 1024,
		},
	}
	pct := CalculateMemoryPercent(stats)
	if pct < 49.9 || pct > 50.1 {
		t.Errorf("CalculateMemoryPercent() = %.2f, want ~50.0", pct)
	}
}

func TestCalculateMemoryPercent_ZeroLimit(t *testing.T) {
	stats := &container.StatsResponse{
		MemoryStats: container.MemoryStats{
			Usage: 100,
			Limit: 0,
		},
	}
	pct := CalculateMemoryPercent(stats)
	if pct != 0.0 {
		t.Errorf("CalculateMemoryPercent() = %.2f, want 0.0 for zero limit", pct)
	}
}

func TestStatsFromResponse(t *testing.T) {
	stats := &container.StatsResponse{
		CPUStats: container.CPUStats{
			CPUUsage:    container.CPUUsage{TotalUsage: 200},
			SystemUsage: 1000,
			OnlineCPUs:  2,
		},
		PreCPUStats: container.CPUStats{
			CPUUsage:    container.CPUUsage{TotalUsage: 100},
			SystemUsage: 800,
		},
		MemoryStats: container.MemoryStats{
			Usage: 256 * 1024 * 1024,
			Limit: 1024 * 1024 * 1024,
		},
		Networks: map[string]container.NetworkStats{
			"eth0": {RxBytes: 1000, TxBytes: 2000},
			"eth1": {RxBytes: 500, TxBytes: 300},
		},
		BlkioStats: container.BlkioStats{
			IoServiceBytesRecursive: []container.BlkioStatEntry{
				{Op: "Read", Value: 4096},
				{Op: "Write", Value: 8192},
				{Op: "read", Value: 100},
				{Op: "write", Value: 200},
			},
		},
		PidsStats: container.PidsStats{
			Current: 42,
		},
	}

	cs := StatsFromResponse("cid-1", stats)

	if cs.ID != "cid-1" {
		t.Errorf("ID = %q, want %q", cs.ID, "cid-1")
	}
	if cs.NetworkRx != 1500 {
		t.Errorf("NetworkRx = %d, want 1500", cs.NetworkRx)
	}
	if cs.NetworkTx != 2300 {
		t.Errorf("NetworkTx = %d, want 2300", cs.NetworkTx)
	}
	if cs.BlockRead != 4196 {
		t.Errorf("BlockRead = %d, want 4196", cs.BlockRead)
	}
	if cs.BlockWrite != 8392 {
		t.Errorf("BlockWrite = %d, want 8392", cs.BlockWrite)
	}
	if cs.PIDs != 42 {
		t.Errorf("PIDs = %d, want 42", cs.PIDs)
	}
}

// ---------------------------------------------------------------------------
// AggregateStats
// ---------------------------------------------------------------------------

func TestAggregateStats(t *testing.T) {
	stats := map[string]*ContainerStats{
		"a": {CPUPercent: 10, MemoryUsage: 100, MemoryLimit: 1000, NetworkRx: 50, NetworkTx: 60, PIDs: 5},
		"b": {CPUPercent: 20, MemoryUsage: 200, MemoryLimit: 2000, NetworkRx: 70, NetworkTx: 80, PIDs: 10},
		"c": nil, // Should be safely skipped.
	}

	agg := AggregateStats(stats)

	if agg.ContainerCount != 3 {
		t.Errorf("ContainerCount = %d, want 3", agg.ContainerCount)
	}
	if agg.TotalCPUPercent != 30 {
		t.Errorf("TotalCPUPercent = %.2f, want 30", agg.TotalCPUPercent)
	}
	if agg.TotalMemoryUsage != 300 {
		t.Errorf("TotalMemoryUsage = %d, want 300", agg.TotalMemoryUsage)
	}
	if agg.TotalNetworkRx != 120 {
		t.Errorf("TotalNetworkRx = %d, want 120", agg.TotalNetworkRx)
	}
	if agg.TotalPIDs != 15 {
		t.Errorf("TotalPIDs = %d, want 15", agg.TotalPIDs)
	}
}

// ---------------------------------------------------------------------------
// parseLogLine
// ---------------------------------------------------------------------------

func TestParseLogLine_WithTimestamp(t *testing.T) {
	line := "2024-01-15T10:30:00.123456789Z Hello, World!"
	ll := parseLogLine(line, "stdout", true)

	if ll.Stream != "stdout" {
		t.Errorf("Stream = %q, want %q", ll.Stream, "stdout")
	}
	if ll.Message != "Hello, World!" {
		t.Errorf("Message = %q, want %q", ll.Message, "Hello, World!")
	}
	if ll.Timestamp.Year() != 2024 {
		t.Errorf("Timestamp year = %d, want 2024", ll.Timestamp.Year())
	}
}

func TestParseLogLine_NoTimestamp(t *testing.T) {
	line := "just a message"
	ll := parseLogLine(line, "stderr", false)

	if ll.Stream != "stderr" {
		t.Errorf("Stream = %q, want %q", ll.Stream, "stderr")
	}
	if ll.Message != "just a message" {
		t.Errorf("Message = %q, want %q", ll.Message, "just a message")
	}
}

func TestParseLogLine_ShortLine(t *testing.T) {
	line := "short"
	ll := parseLogLine(line, "stdout", true)
	if ll.Message != "short" {
		t.Errorf("Message = %q, want %q", ll.Message, "short")
	}
}

// ---------------------------------------------------------------------------
// convertDockerEvent
// ---------------------------------------------------------------------------

func TestConvertDockerEvent_WithTimeNano(t *testing.T) {
	now := time.Now()
	msg := dockerevents.Message{
		Type:   "container",
		Action: "start",
		Actor: dockerevents.Actor{
			ID: "abc123def456",
			Attributes: map[string]string{
				"name": "my-container",
			},
		},
		TimeNano: now.UnixNano(),
	}

	e := convertDockerEvent(msg)

	if e.Type != "container" {
		t.Errorf("Type = %q, want %q", e.Type, "container")
	}
	if e.Action != "start" {
		t.Errorf("Action = %q, want %q", e.Action, "start")
	}
	if e.ActorID != "abc123def456" {
		t.Errorf("ActorID = %q, want %q", e.ActorID, "abc123def456")
	}
	if e.ActorName != "my-container" {
		t.Errorf("ActorName = %q, want %q", e.ActorName, "my-container")
	}
	if e.Time.IsZero() {
		t.Error("Time should not be zero")
	}
}

func TestConvertDockerEvent_WithTimeOnly(t *testing.T) {
	msg := dockerevents.Message{
		Type:   "image",
		Action: "pull",
		Actor: dockerevents.Actor{
			ID: "sha256:abc123def456789",
		},
		Time: time.Now().Unix(),
	}

	e := convertDockerEvent(msg)

	if e.Type != "image" {
		t.Errorf("Type = %q, want %q", e.Type, "image")
	}
	// Name should be truncated ID when no name attribute.
	if e.ActorName != "sha256:abc12" {
		t.Errorf("ActorName = %q, want truncated to 12 chars", e.ActorName)
	}
}

func TestConvertDockerEvent_NoTime(t *testing.T) {
	msg := dockerevents.Message{
		Type:   "network",
		Action: "create",
		Actor: dockerevents.Actor{
			ID: "net-short",
		},
	}

	e := convertDockerEvent(msg)

	// With no TimeNano or Time, should use time.Now().
	if e.Time.IsZero() {
		t.Error("Time should be set even with no timestamp fields")
	}
	// Short ID should not be truncated.
	if e.ActorName != "net-short" {
		t.Errorf("ActorName = %q, want %q", e.ActorName, "net-short")
	}
}
