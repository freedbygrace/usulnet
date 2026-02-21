// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package executor

import (
	"testing"
	"time"

	"github.com/fr4nsys/usulnet/internal/gateway/protocol"
)

// ============================================================================
// Container Options Tests
// ============================================================================

func TestContainerListOptionsFromParams(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		p := protocol.CommandParams{}
		opts := containerListOptionsFromParams(p)

		if opts.All {
			t.Error("expected All to be false")
		}
		if opts.Limit != 0 {
			t.Errorf("expected Limit 0, got %d", opts.Limit)
		}
	})

	t.Run("all and limit", func(t *testing.T) {
		p := protocol.CommandParams{All: true, Limit: 10}
		opts := containerListOptionsFromParams(p)

		if !opts.All {
			t.Error("expected All to be true")
		}
		if opts.Limit != 10 {
			t.Errorf("expected Limit 10, got %d", opts.Limit)
		}
	})

	t.Run("with filters", func(t *testing.T) {
		p := protocol.CommandParams{
			Filters: map[string][]string{
				"status": {"running"},
				"label":  {"env=prod", "app=web"},
			},
		}
		opts := containerListOptionsFromParams(p)

		if !opts.Filters.Contains("status") {
			t.Error("expected filters to contain 'status'")
		}
		if !opts.Filters.ExactMatch("status", "running") {
			t.Error("expected status filter to match 'running'")
		}
		if !opts.Filters.Contains("label") {
			t.Error("expected filters to contain 'label'")
		}
	})

	t.Run("empty filters not set", func(t *testing.T) {
		p := protocol.CommandParams{Filters: map[string][]string{}}
		opts := containerListOptionsFromParams(p)

		if opts.Filters.Len() != 0 {
			t.Errorf("expected no filters, got %d", opts.Filters.Len())
		}
	})
}

func TestContainerStartOptionsFromParams(t *testing.T) {
	p := protocol.CommandParams{}
	opts := containerStartOptionsFromParams(p)

	// containerStartOptionsFromParams always returns empty StartOptions
	if opts.CheckpointID != "" {
		t.Errorf("expected empty CheckpointID, got %q", opts.CheckpointID)
	}
	if opts.CheckpointDir != "" {
		t.Errorf("expected empty CheckpointDir, got %q", opts.CheckpointDir)
	}
}

func TestContainerStopOptionsFromParams(t *testing.T) {
	t.Run("no timeout no signal", func(t *testing.T) {
		p := protocol.CommandParams{}
		opts := containerStopOptionsFromParams(p)

		if opts.Timeout != nil {
			t.Errorf("expected nil timeout, got %v", *opts.Timeout)
		}
		if opts.Signal != "" {
			t.Errorf("expected empty signal, got %q", opts.Signal)
		}
	})

	t.Run("with timeout", func(t *testing.T) {
		timeout := 30
		p := protocol.CommandParams{StopTimeout: &timeout}
		opts := containerStopOptionsFromParams(p)

		if opts.Timeout == nil {
			t.Fatal("expected non-nil timeout")
		}
		if *opts.Timeout != 30 {
			t.Errorf("expected timeout 30, got %d", *opts.Timeout)
		}
	})

	t.Run("timeout is a copy", func(t *testing.T) {
		timeout := 15
		p := protocol.CommandParams{StopTimeout: &timeout}
		opts := containerStopOptionsFromParams(p)

		// Mutating the original should not affect the result
		timeout = 99
		if *opts.Timeout != 15 {
			t.Errorf("expected timeout 15 (independent copy), got %d", *opts.Timeout)
		}
	})

	t.Run("with signal", func(t *testing.T) {
		p := protocol.CommandParams{Signal: "SIGTERM"}
		opts := containerStopOptionsFromParams(p)

		if opts.Signal != "SIGTERM" {
			t.Errorf("expected signal SIGTERM, got %q", opts.Signal)
		}
	})

	t.Run("with both", func(t *testing.T) {
		timeout := 5
		p := protocol.CommandParams{StopTimeout: &timeout, Signal: "SIGINT"}
		opts := containerStopOptionsFromParams(p)

		if *opts.Timeout != 5 {
			t.Errorf("expected timeout 5, got %d", *opts.Timeout)
		}
		if opts.Signal != "SIGINT" {
			t.Errorf("expected signal SIGINT, got %q", opts.Signal)
		}
	})
}

func TestContainerRemoveOptionsFromParams(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		p := protocol.CommandParams{}
		opts := containerRemoveOptionsFromParams(p)

		if opts.RemoveVolumes {
			t.Error("expected RemoveVolumes false")
		}
		if opts.Force {
			t.Error("expected Force false")
		}
	})

	t.Run("force and remove volumes", func(t *testing.T) {
		p := protocol.CommandParams{Force: true, RemoveVolumes: true}
		opts := containerRemoveOptionsFromParams(p)

		if !opts.RemoveVolumes {
			t.Error("expected RemoveVolumes true")
		}
		if !opts.Force {
			t.Error("expected Force true")
		}
	})
}

func TestContainerLogsOptionsFromParams(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		p := protocol.CommandParams{}
		opts := containerLogsOptionsFromParams(p)

		if !opts.ShowStdout {
			t.Error("expected ShowStdout true")
		}
		if !opts.ShowStderr {
			t.Error("expected ShowStderr true")
		}
		if opts.Follow {
			t.Error("expected Follow false")
		}
		if opts.Timestamps {
			t.Error("expected Timestamps false")
		}
		if opts.Details {
			t.Error("expected Details false")
		}
		if opts.Tail != "1000" {
			t.Errorf("expected default Tail '1000', got %q", opts.Tail)
		}
		if opts.Since != "" {
			t.Errorf("expected empty Since, got %q", opts.Since)
		}
		if opts.Until != "" {
			t.Errorf("expected empty Until, got %q", opts.Until)
		}
	})

	t.Run("custom tail", func(t *testing.T) {
		p := protocol.CommandParams{Tail: "500"}
		opts := containerLogsOptionsFromParams(p)

		if opts.Tail != "500" {
			t.Errorf("expected Tail '500', got %q", opts.Tail)
		}
	})

	t.Run("all options set", func(t *testing.T) {
		p := protocol.CommandParams{
			Follow:     true,
			Timestamps: true,
			Details:    true,
			Tail:       "all",
			Since:      "2024-01-01T00:00:00Z",
			Until:      "2024-12-31T23:59:59Z",
		}
		opts := containerLogsOptionsFromParams(p)

		if !opts.Follow {
			t.Error("expected Follow true")
		}
		if !opts.Timestamps {
			t.Error("expected Timestamps true")
		}
		if !opts.Details {
			t.Error("expected Details true")
		}
		if opts.Tail != "all" {
			t.Errorf("expected Tail 'all', got %q", opts.Tail)
		}
		if opts.Since != "2024-01-01T00:00:00Z" {
			t.Errorf("expected Since set, got %q", opts.Since)
		}
		if opts.Until != "2024-12-31T23:59:59Z" {
			t.Errorf("expected Until set, got %q", opts.Until)
		}
	})
}

func TestContainerExecConfigFromParams(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		p := protocol.CommandParams{}
		opts := containerExecConfigFromParams(p)

		if opts.Cmd != nil {
			t.Errorf("expected nil Cmd, got %v", opts.Cmd)
		}
		if opts.Tty {
			t.Error("expected Tty false")
		}
		if opts.Privileged {
			t.Error("expected Privileged false")
		}
	})

	t.Run("full options", func(t *testing.T) {
		p := protocol.CommandParams{
			Cmd:          []string{"sh", "-c", "echo hello"},
			Env:          []string{"FOO=bar"},
			WorkingDir:   "/app",
			User:         "root",
			Tty:          true,
			AttachStdin:  true,
			AttachStdout: true,
			AttachStderr: true,
			Privileged:   true,
		}
		opts := containerExecConfigFromParams(p)

		if len(opts.Cmd) != 3 || opts.Cmd[0] != "sh" || opts.Cmd[1] != "-c" || opts.Cmd[2] != "echo hello" {
			t.Errorf("unexpected Cmd: %v", opts.Cmd)
		}
		if len(opts.Env) != 1 || opts.Env[0] != "FOO=bar" {
			t.Errorf("unexpected Env: %v", opts.Env)
		}
		if opts.WorkingDir != "/app" {
			t.Errorf("expected WorkingDir /app, got %q", opts.WorkingDir)
		}
		if opts.User != "root" {
			t.Errorf("expected User root, got %q", opts.User)
		}
		if !opts.Tty {
			t.Error("expected Tty true")
		}
		if !opts.AttachStdin {
			t.Error("expected AttachStdin true")
		}
		if !opts.AttachStdout {
			t.Error("expected AttachStdout true")
		}
		if !opts.AttachStderr {
			t.Error("expected AttachStderr true")
		}
		if !opts.Privileged {
			t.Error("expected Privileged true")
		}
	})
}

// ============================================================================
// Image Options Tests
// ============================================================================

func TestImageListOptionsFromParams(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		p := protocol.CommandParams{}
		opts := imageListOptionsFromParams(p)

		if opts.All {
			t.Error("expected All false")
		}
	})

	t.Run("all with filters", func(t *testing.T) {
		p := protocol.CommandParams{
			All:     true,
			Filters: map[string][]string{"reference": {"alpine:*"}},
		}
		opts := imageListOptionsFromParams(p)

		if !opts.All {
			t.Error("expected All true")
		}
		if !opts.Filters.Contains("reference") {
			t.Error("expected filters to contain 'reference'")
		}
	})
}

func TestImagePullOptionsFromParams(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		p := protocol.CommandParams{}
		opts := imagePullOptionsFromParams(p)

		if opts.Platform != "" {
			t.Errorf("expected empty Platform, got %q", opts.Platform)
		}
		if opts.RegistryAuth != "" {
			t.Errorf("expected empty RegistryAuth, got %q", opts.RegistryAuth)
		}
	})

	t.Run("with platform", func(t *testing.T) {
		p := protocol.CommandParams{Platform: "linux/arm64"}
		opts := imagePullOptionsFromParams(p)

		if opts.Platform != "linux/arm64" {
			t.Errorf("expected platform linux/arm64, got %q", opts.Platform)
		}
	})

	t.Run("with registry auth", func(t *testing.T) {
		p := protocol.CommandParams{RegistryAuth: "eyJ1c2VybmFtZSI6ImZvbyJ9"}
		opts := imagePullOptionsFromParams(p)

		if opts.RegistryAuth != "eyJ1c2VybmFtZSI6ImZvbyJ9" {
			t.Errorf("expected RegistryAuth set, got %q", opts.RegistryAuth)
		}
	})
}

func TestImageRemoveOptionsFromParams(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		p := protocol.CommandParams{}
		opts := imageRemoveOptionsFromParams(p)

		if opts.Force {
			t.Error("expected Force false")
		}
		if !opts.PruneChildren {
			t.Error("expected PruneChildren always true")
		}
	})

	t.Run("force", func(t *testing.T) {
		p := protocol.CommandParams{Force: true}
		opts := imageRemoveOptionsFromParams(p)

		if !opts.Force {
			t.Error("expected Force true")
		}
		if !opts.PruneChildren {
			t.Error("expected PruneChildren always true")
		}
	})
}

func TestImagePruneFiltersFromParams(t *testing.T) {
	t.Run("dangling only", func(t *testing.T) {
		p := protocol.CommandParams{PruneAll: false}
		f := imagePruneFiltersFromParams(p)

		if !f.ExactMatch("dangling", "true") {
			t.Error("expected dangling=true when PruneAll is false")
		}
	})

	t.Run("prune all", func(t *testing.T) {
		p := protocol.CommandParams{PruneAll: true}
		f := imagePruneFiltersFromParams(p)

		if !f.ExactMatch("dangling", "false") {
			t.Error("expected dangling=false when PruneAll is true")
		}
	})

	t.Run("with prune filters", func(t *testing.T) {
		p := protocol.CommandParams{
			PruneAll: false,
			PruneFilters: map[string][]string{
				"until":  {"24h"},
				"label":  {"env=staging"},
			},
		}
		f := imagePruneFiltersFromParams(p)

		if !f.ExactMatch("dangling", "true") {
			t.Error("expected dangling=true")
		}
		if !f.Contains("until") {
			t.Error("expected until filter present")
		}
		if !f.Contains("label") {
			t.Error("expected label filter present")
		}
	})
}

// ============================================================================
// Volume Options Tests
// ============================================================================

func TestVolumeListOptionsFromParams(t *testing.T) {
	t.Run("no filters", func(t *testing.T) {
		p := protocol.CommandParams{}
		opts := volumeListOptionsFromParams(p)

		if opts.Filters.Len() != 0 {
			t.Errorf("expected no filters, got %d", opts.Filters.Len())
		}
	})

	t.Run("with filters", func(t *testing.T) {
		p := protocol.CommandParams{
			Filters: map[string][]string{"driver": {"local"}},
		}
		opts := volumeListOptionsFromParams(p)

		if !opts.Filters.Contains("driver") {
			t.Error("expected driver filter present")
		}
	})
}

func TestVolumeCreateOptionsFromParams(t *testing.T) {
	t.Run("name only", func(t *testing.T) {
		p := protocol.CommandParams{VolumeName: "mydata"}
		opts := volumeCreateOptionsFromParams(p)

		if opts.Name != "mydata" {
			t.Errorf("expected Name 'mydata', got %q", opts.Name)
		}
		if opts.Driver != "" {
			t.Errorf("expected empty Driver, got %q", opts.Driver)
		}
	})

	t.Run("with driver and opts", func(t *testing.T) {
		p := protocol.CommandParams{
			VolumeName: "nfs-vol",
			Driver:     "nfs",
			DriverOpts: map[string]string{"server": "10.0.0.1", "share": "/data"},
		}
		opts := volumeCreateOptionsFromParams(p)

		if opts.Name != "nfs-vol" {
			t.Errorf("expected Name 'nfs-vol', got %q", opts.Name)
		}
		if opts.Driver != "nfs" {
			t.Errorf("expected Driver 'nfs', got %q", opts.Driver)
		}
		if opts.DriverOpts["server"] != "10.0.0.1" {
			t.Errorf("expected server opt, got %v", opts.DriverOpts)
		}
		if opts.DriverOpts["share"] != "/data" {
			t.Errorf("expected share opt, got %v", opts.DriverOpts)
		}
	})

	t.Run("empty driver opts not set", func(t *testing.T) {
		p := protocol.CommandParams{VolumeName: "vol", DriverOpts: map[string]string{}}
		opts := volumeCreateOptionsFromParams(p)

		if opts.DriverOpts != nil {
			t.Errorf("expected nil DriverOpts for empty map, got %v", opts.DriverOpts)
		}
	})
}

func TestVolumePruneFiltersFromParams(t *testing.T) {
	t.Run("no filters", func(t *testing.T) {
		p := protocol.CommandParams{}
		f := volumePruneFiltersFromParams(p)

		if f.Len() != 0 {
			t.Errorf("expected no filters, got %d", f.Len())
		}
	})

	t.Run("with prune filters", func(t *testing.T) {
		p := protocol.CommandParams{
			PruneFilters: map[string][]string{
				"label": {"cleanup=true"},
			},
		}
		f := volumePruneFiltersFromParams(p)

		if !f.Contains("label") {
			t.Error("expected label filter present")
		}
	})
}

// ============================================================================
// Network Options Tests
// ============================================================================

func TestNetworkListOptionsFromParams(t *testing.T) {
	t.Run("no filters", func(t *testing.T) {
		p := protocol.CommandParams{}
		opts := networkListOptionsFromParams(p)

		if opts.Filters.Len() != 0 {
			t.Errorf("expected no filters, got %d", opts.Filters.Len())
		}
	})

	t.Run("with filters", func(t *testing.T) {
		p := protocol.CommandParams{
			Filters: map[string][]string{"scope": {"local"}},
		}
		opts := networkListOptionsFromParams(p)

		if !opts.Filters.Contains("scope") {
			t.Error("expected scope filter present")
		}
	})
}

func TestNetworkInspectOptionsFromParams(t *testing.T) {
	t.Run("not verbose", func(t *testing.T) {
		p := protocol.CommandParams{Details: false}
		opts := networkInspectOptionsFromParams(p)

		if opts.Verbose {
			t.Error("expected Verbose false")
		}
	})

	t.Run("verbose", func(t *testing.T) {
		p := protocol.CommandParams{Details: true}
		opts := networkInspectOptionsFromParams(p)

		if !opts.Verbose {
			t.Error("expected Verbose true")
		}
	})
}

func TestNetworkCreateOptionsFromParams(t *testing.T) {
	t.Run("default driver", func(t *testing.T) {
		p := protocol.CommandParams{}
		opts := networkCreateOptionsFromParams(p)

		if opts.Driver != "bridge" {
			t.Errorf("expected default driver 'bridge', got %q", opts.Driver)
		}
		if opts.IPAM != nil {
			t.Error("expected nil IPAM without subnet")
		}
	})

	t.Run("custom driver", func(t *testing.T) {
		p := protocol.CommandParams{Driver: "overlay"}
		opts := networkCreateOptionsFromParams(p)

		if opts.Driver != "overlay" {
			t.Errorf("expected driver 'overlay', got %q", opts.Driver)
		}
	})

	t.Run("internal and attachable", func(t *testing.T) {
		p := protocol.CommandParams{Internal: true, Attachable: true}
		opts := networkCreateOptionsFromParams(p)

		if !opts.Internal {
			t.Error("expected Internal true")
		}
		if !opts.Attachable {
			t.Error("expected Attachable true")
		}
	})

	t.Run("with subnet and gateway", func(t *testing.T) {
		p := protocol.CommandParams{
			Subnet:  "10.0.0.0/24",
			Gateway: "10.0.0.1",
		}
		opts := networkCreateOptionsFromParams(p)

		if opts.IPAM == nil {
			t.Fatal("expected non-nil IPAM with subnet")
		}
		if opts.IPAM.Driver != "default" {
			t.Errorf("expected IPAM driver 'default', got %q", opts.IPAM.Driver)
		}
		if len(opts.IPAM.Config) != 1 {
			t.Fatalf("expected 1 IPAM config, got %d", len(opts.IPAM.Config))
		}
		if opts.IPAM.Config[0].Subnet != "10.0.0.0/24" {
			t.Errorf("expected subnet 10.0.0.0/24, got %q", opts.IPAM.Config[0].Subnet)
		}
		if opts.IPAM.Config[0].Gateway != "10.0.0.1" {
			t.Errorf("expected gateway 10.0.0.1, got %q", opts.IPAM.Config[0].Gateway)
		}
	})

	t.Run("subnet without gateway", func(t *testing.T) {
		p := protocol.CommandParams{Subnet: "172.20.0.0/16"}
		opts := networkCreateOptionsFromParams(p)

		if opts.IPAM == nil {
			t.Fatal("expected non-nil IPAM")
		}
		if opts.IPAM.Config[0].Gateway != "" {
			t.Errorf("expected empty gateway, got %q", opts.IPAM.Config[0].Gateway)
		}
	})
}

func TestNetworkConnectOptionsFromParams(t *testing.T) {
	t.Run("empty params", func(t *testing.T) {
		p := protocol.CommandParams{}
		settings := networkConnectOptionsFromParams(p)

		if settings == nil {
			t.Fatal("expected non-nil settings")
		}
		if settings.IPAMConfig != nil {
			t.Error("expected nil IPAMConfig without IPAddress")
		}
		if settings.Aliases != nil {
			t.Error("expected nil Aliases without aliases")
		}
	})

	t.Run("with ip address", func(t *testing.T) {
		p := protocol.CommandParams{IPAddress: "10.0.0.42"}
		settings := networkConnectOptionsFromParams(p)

		if settings.IPAMConfig == nil {
			t.Fatal("expected non-nil IPAMConfig")
		}
		if settings.IPAMConfig.IPv4Address != "10.0.0.42" {
			t.Errorf("expected IPv4Address 10.0.0.42, got %q", settings.IPAMConfig.IPv4Address)
		}
	})

	t.Run("with aliases", func(t *testing.T) {
		p := protocol.CommandParams{Aliases: []string{"web", "frontend"}}
		settings := networkConnectOptionsFromParams(p)

		if len(settings.Aliases) != 2 {
			t.Fatalf("expected 2 aliases, got %d", len(settings.Aliases))
		}
		if settings.Aliases[0] != "web" || settings.Aliases[1] != "frontend" {
			t.Errorf("unexpected aliases: %v", settings.Aliases)
		}
	})

	t.Run("with both", func(t *testing.T) {
		p := protocol.CommandParams{
			IPAddress: "10.0.0.99",
			Aliases:   []string{"api"},
		}
		settings := networkConnectOptionsFromParams(p)

		if settings.IPAMConfig == nil {
			t.Fatal("expected non-nil IPAMConfig")
		}
		if settings.IPAMConfig.IPv4Address != "10.0.0.99" {
			t.Errorf("expected IPv4Address 10.0.0.99, got %q", settings.IPAMConfig.IPv4Address)
		}
		if len(settings.Aliases) != 1 || settings.Aliases[0] != "api" {
			t.Errorf("unexpected aliases: %v", settings.Aliases)
		}
	})
}

// ============================================================================
// System Options Tests
// ============================================================================

func TestDiskUsageOptionsFromParams(t *testing.T) {
	p := protocol.CommandParams{All: true, Limit: 5}
	opts := diskUsageOptionsFromParams(p)

	// diskUsageOptionsFromParams always returns empty options
	_ = opts
}

// ============================================================================
// Filter Helpers Tests
// ============================================================================

func TestFiltersFromMap(t *testing.T) {
	t.Run("nil map", func(t *testing.T) {
		f := filtersFromMap(nil)
		if f.Len() != 0 {
			t.Errorf("expected 0 filters from nil map, got %d", f.Len())
		}
	})

	t.Run("empty map", func(t *testing.T) {
		f := filtersFromMap(map[string][]string{})
		if f.Len() != 0 {
			t.Errorf("expected 0 filters from empty map, got %d", f.Len())
		}
	})

	t.Run("single key single value", func(t *testing.T) {
		f := filtersFromMap(map[string][]string{"status": {"running"}})

		if !f.Contains("status") {
			t.Error("expected 'status' key in filters")
		}
		if !f.ExactMatch("status", "running") {
			t.Error("expected status=running match")
		}
	})

	t.Run("single key multiple values", func(t *testing.T) {
		f := filtersFromMap(map[string][]string{
			"label": {"env=prod", "tier=frontend"},
		})

		if !f.Contains("label") {
			t.Error("expected 'label' key in filters")
		}
	})

	t.Run("multiple keys", func(t *testing.T) {
		m := map[string][]string{
			"status": {"running"},
			"name":   {"web"},
			"label":  {"app=nginx"},
		}
		f := filtersFromMap(m)

		if !f.Contains("status") {
			t.Error("expected 'status' key")
		}
		if !f.Contains("name") {
			t.Error("expected 'name' key")
		}
		if !f.Contains("label") {
			t.Error("expected 'label' key")
		}
	})
}

// ============================================================================
// Time Helper Tests
// ============================================================================

func TestDurationPtr(t *testing.T) {
	d := 5 * time.Second
	ptr := durationPtr(d)

	if ptr == nil {
		t.Fatal("expected non-nil pointer")
	}
	if *ptr != 5*time.Second {
		t.Errorf("expected 5s, got %v", *ptr)
	}

	// Verify it returns a new pointer each time
	ptr2 := durationPtr(d)
	if ptr == ptr2 {
		t.Error("expected different pointer addresses")
	}
}

func TestIntPtr(t *testing.T) {
	ptr := intPtr(42)
	if ptr == nil {
		t.Fatal("expected non-nil pointer")
	}
	if *ptr != 42 {
		t.Errorf("expected 42, got %d", *ptr)
	}

	ptr2 := intPtr(42)
	if ptr == ptr2 {
		t.Error("expected different pointer addresses")
	}

	// Test zero value
	ptrZero := intPtr(0)
	if *ptrZero != 0 {
		t.Errorf("expected 0, got %d", *ptrZero)
	}

	// Test negative
	ptrNeg := intPtr(-1)
	if *ptrNeg != -1 {
		t.Errorf("expected -1, got %d", *ptrNeg)
	}
}
