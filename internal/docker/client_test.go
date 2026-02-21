// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Client accessor tests
// ---------------------------------------------------------------------------

func TestClient_Accessors(t *testing.T) {
	c, _ := newTestClient(t)

	if got := c.Host(); got == "" {
		t.Error("Host() returned empty string")
	}
	if got := c.APIVersion(); got != "1.45" {
		t.Errorf("APIVersion() = %q, want %q", got, "1.45")
	}
	if got := c.Timeout(); got != DefaultTimeout {
		t.Errorf("Timeout() = %v, want %v", got, DefaultTimeout)
	}
	if c.Raw() == nil {
		t.Error("Raw() returned nil")
	}
	if c.IsClosed() {
		t.Error("IsClosed() returned true for open client")
	}
}

func TestClient_Close(t *testing.T) {
	c, _ := newTestClient(t)

	if err := c.Close(); err != nil {
		t.Fatalf("first Close() error: %v", err)
	}
	if !c.IsClosed() {
		t.Error("IsClosed() returned false after Close()")
	}
	// Second close should be a no-op.
	if err := c.Close(); err != nil {
		t.Fatalf("second Close() error: %v", err)
	}
}

func TestClient_Ping(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := context.Background()

	if err := c.Ping(ctx); err != nil {
		t.Fatalf("Ping() error: %v", err)
	}
}

func TestClient_Ping_Closed(t *testing.T) {
	c := newClosedClient(t)
	ctx := context.Background()

	err := c.Ping(ctx)
	if err == nil {
		t.Fatal("Ping() on closed client should return error")
	}
}

func TestClient_Info(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	// The Docker SDK sends GET /info with optional version prefix.
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"ID":                "test-id",
			"Name":              "test-host",
			"ServerVersion":     "27.0.0",
			"OperatingSystem":   "Linux",
			"OSType":            "linux",
			"Architecture":      "x86_64",
			"KernelVersion":     "6.1.0",
			"Containers":        5,
			"ContainersRunning": 3,
			"ContainersPaused":  0,
			"ContainersStopped": 2,
			"Images":            10,
			"MemTotal":          int64(8589934592),
			"NCPU":              4,
			"DockerRootDir":     "/var/lib/docker",
			"Driver":            "overlay2",
			"LoggingDriver":     "json-file",
			"CgroupDriver":      "cgroupfs",
			"CgroupVersion":     "2",
			"DefaultRuntime":    "runc",
			"SecurityOptions":   []string{"seccomp"},
			"Runtimes":          map[string]interface{}{"runc": map[string]interface{}{}},
			"Swarm": map[string]interface{}{
				"ControlAvailable": false,
			},
		}
		jsonResponse(w, http.StatusOK, resp)
	})

	info, err := c.Info(ctx)
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}
	if info.ID != "test-id" {
		t.Errorf("Info().ID = %q, want %q", info.ID, "test-id")
	}
	if info.Name != "test-host" {
		t.Errorf("Info().Name = %q, want %q", info.Name, "test-host")
	}
	if info.Containers != 5 {
		t.Errorf("Info().Containers = %d, want %d", info.Containers, 5)
	}
	if info.NCPU != 4 {
		t.Errorf("Info().NCPU = %d, want %d", info.NCPU, 4)
	}
}

func TestClient_Info_Closed(t *testing.T) {
	c := newClosedClient(t)
	ctx := context.Background()

	_, err := c.Info(ctx)
	if err == nil {
		t.Fatal("Info() on closed client should return error")
	}
}

func TestClient_ServerVersion(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"Version":    "27.0.0",
			"ApiVersion": "1.45",
			"Os":         "linux",
			"Arch":       "amd64",
		}
		jsonResponse(w, http.StatusOK, resp)
	})

	ver, err := c.ServerVersion(ctx)
	if err != nil {
		t.Fatalf("ServerVersion() error: %v", err)
	}
	if ver != "27.0.0" {
		t.Errorf("ServerVersion() = %q, want %q", ver, "27.0.0")
	}
}

func TestClient_BuildCachePrune(t *testing.T) {
	c, mux := newTestClient(t)
	ctx := context.Background()

	mux.HandleFunc("/build/prune", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		resp := map[string]interface{}{
			"SpaceReclaimed": 12345678,
		}
		jsonResponse(w, http.StatusOK, resp)
	})

	freed, err := c.BuildCachePrune(ctx, true)
	if err != nil {
		t.Fatalf("BuildCachePrune() error: %v", err)
	}
	if freed != 12345678 {
		t.Errorf("BuildCachePrune() = %d, want %d", freed, 12345678)
	}
}

func TestClient_BuildCachePrune_Closed(t *testing.T) {
	c := newClosedClient(t)
	ctx := context.Background()

	_, err := c.BuildCachePrune(ctx, false)
	if err == nil {
		t.Fatal("BuildCachePrune() on closed client should return error")
	}
}

// ---------------------------------------------------------------------------
// NewClient error paths
// ---------------------------------------------------------------------------

func TestNewClient_DaemonUnavailable(t *testing.T) {
	ctx := context.Background()

	// Point at a non-existent socket. The ping should fail fast.
	_, err := NewClient(ctx, ClientOptions{
		Host:    "unix:///tmp/usulnet_nonexistent_docker.sock",
		Timeout: 1 * time.Second,
	})
	if err == nil {
		t.Fatal("NewClient() should fail when daemon is unreachable")
	}
}

// ---------------------------------------------------------------------------
// Socket path helpers
// ---------------------------------------------------------------------------

func TestSetLocalSocketPath(t *testing.T) {
	original := localSocketPath
	t.Cleanup(func() { localSocketPath = original })

	SetLocalSocketPath("/custom/docker.sock")
	if got := LocalSocketPath(); got != "/custom/docker.sock" {
		t.Errorf("LocalSocketPath() = %q, want %q", got, "/custom/docker.sock")
	}

	// Empty string should not change the path.
	SetLocalSocketPath("")
	if got := LocalSocketPath(); got != "/custom/docker.sock" {
		t.Errorf("LocalSocketPath() = %q after empty set, want %q", got, "/custom/docker.sock")
	}
}

func TestIsUnixSocket(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"unix:///var/run/docker.sock", true},
		{"tcp://localhost:2375", false},
		{"http://localhost:2375", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isUnixSocket(tt.host); got != tt.want {
			t.Errorf("isUnixSocket(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// ClientPool
// ---------------------------------------------------------------------------

func TestClientPool_BasicOperations(t *testing.T) {
	pool := NewClientPool()

	if pool.Size() != 0 {
		t.Errorf("new pool size = %d, want 0", pool.Size())
	}

	// Create and set a client.
	c, _ := newTestClient(t)
	pool.Set("host-1", c)

	if pool.Size() != 1 {
		t.Errorf("pool size after Set = %d, want 1", pool.Size())
	}

	got, ok := pool.Get("host-1")
	if !ok || got != c {
		t.Error("Get(host-1) failed to return the client")
	}

	_, ok = pool.Get("nonexistent")
	if ok {
		t.Error("Get(nonexistent) should return false")
	}

	hosts := pool.Hosts()
	if len(hosts) != 1 {
		t.Errorf("Hosts() len = %d, want 1", len(hosts))
	}
}

func TestClientPool_HostIDs(t *testing.T) {
	pool := NewClientPool()
	c1, _ := newTestClient(t)
	c2, _ := newTestClient(t)
	pool.Set("a", c1)
	pool.Set("b", c2)

	ids := pool.HostIDs()
	if len(ids) != 2 {
		t.Errorf("HostIDs() len = %d, want 2", len(ids))
	}
}

func TestClientPool_Remove(t *testing.T) {
	pool := NewClientPool()
	c, _ := newTestClient(t)
	pool.Set("host-1", c)
	pool.Remove("host-1")

	if pool.Size() != 0 {
		t.Errorf("pool size after Remove = %d, want 0", pool.Size())
	}

	// Removing again should not panic.
	pool.Remove("host-1")
}

func TestClientPool_SetReplaces(t *testing.T) {
	pool := NewClientPool()

	c1, _ := newTestClient(t)
	c2, _ := newTestClient(t)

	pool.Set("host-1", c1)
	pool.Set("host-1", c2)

	got, ok := pool.Get("host-1")
	if !ok || got != c2 {
		t.Error("Set should replace existing client")
	}

	// The old client should have been closed.
	if !c1.IsClosed() {
		t.Error("old client should be closed after replacement")
	}
}

func TestClientPool_CloseAll(t *testing.T) {
	pool := NewClientPool()

	c1, _ := newTestClient(t)
	c2, _ := newTestClient(t)
	pool.Set("a", c1)
	pool.Set("b", c2)

	pool.CloseAll()

	if pool.Size() != 0 {
		t.Errorf("pool size after CloseAll = %d, want 0", pool.Size())
	}
}

func TestClientPool_HealthCheck(t *testing.T) {
	pool := NewClientPool()
	c, _ := newTestClient(t)
	pool.Set("host-1", c)

	ctx := context.Background()
	results := pool.HealthCheck(ctx)

	if len(results) != 1 {
		t.Fatalf("HealthCheck() returned %d results, want 1", len(results))
	}
	if results["host-1"] != nil {
		t.Errorf("HealthCheck() host-1 error: %v", results["host-1"])
	}
}

// ---------------------------------------------------------------------------
// TLS config builder
// ---------------------------------------------------------------------------

func TestBuildTLSConfig_InsecureSkipVerify(t *testing.T) {
	cfg, err := buildTLSConfig(&TLSConfig{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("buildTLSConfig() error: %v", err)
	}
	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true")
	}
}

func TestBuildTLSConfig_InvalidCACert(t *testing.T) {
	_, err := buildTLSConfig(&TLSConfig{
		CACert: []byte("not-a-real-cert"),
	})
	if err == nil {
		t.Fatal("buildTLSConfig() should fail with invalid CA cert")
	}
}

func TestBuildTLSConfig_InvalidClientCert(t *testing.T) {
	_, err := buildTLSConfig(&TLSConfig{
		ClientCert: []byte("not-a-cert"),
		ClientKey:  []byte("not-a-key"),
	})
	if err == nil {
		t.Fatal("buildTLSConfig() should fail with invalid client cert/key")
	}
}

// ---------------------------------------------------------------------------
// EncodeRegistryAuth
// ---------------------------------------------------------------------------

func TestEncodeRegistryAuth(t *testing.T) {
	auth := RegistryAuth{
		Username: "user",
		Password: "pass",
	}
	encoded, err := EncodeRegistryAuth(auth)
	if err != nil {
		t.Fatalf("EncodeRegistryAuth() error: %v", err)
	}
	if encoded == "" {
		t.Error("EncodeRegistryAuth() returned empty string")
	}
}

// ---------------------------------------------------------------------------
// DefaultLogOptions
// ---------------------------------------------------------------------------

func TestDefaultLogOptions(t *testing.T) {
	opts := DefaultLogOptions()
	if opts.Tail != "100" {
		t.Errorf("Tail = %q, want %q", opts.Tail, "100")
	}
	if !opts.Stdout {
		t.Error("Stdout should be true")
	}
	if !opts.Stderr {
		t.Error("Stderr should be true")
	}
	if !opts.Timestamps {
		t.Error("Timestamps should be true")
	}
	if opts.Follow {
		t.Error("Follow should be false")
	}
}

// ---------------------------------------------------------------------------
// IsDefaultNetwork
// ---------------------------------------------------------------------------

func TestIsDefaultNetwork(t *testing.T) {
	for _, name := range []string{"bridge", "host", "none"} {
		if !IsDefaultNetwork(name) {
			t.Errorf("IsDefaultNetwork(%q) = false, want true", name)
		}
	}
	if IsDefaultNetwork("my-custom-net") {
		t.Error("IsDefaultNetwork(my-custom-net) = true, want false")
	}
}

// ---------------------------------------------------------------------------
// FormatDetectedSocket
// ---------------------------------------------------------------------------

func TestFormatDetectedSocket(t *testing.T) {
	got := FormatDetectedSocket(DefaultLocalSocketPath)
	if got == "" {
		t.Error("FormatDetectedSocket returned empty for default path")
	}

	got = FormatDetectedSocket("/custom/path.sock")
	if got == "" {
		t.Error("FormatDetectedSocket returned empty for custom path")
	}
}

// ---------------------------------------------------------------------------
// parseUnixSocket
// ---------------------------------------------------------------------------

func TestParseUnixSocket(t *testing.T) {
	path, ok := parseUnixSocket("unix:///var/run/docker.sock")
	if !ok || path != "/var/run/docker.sock" {
		t.Errorf("parseUnixSocket(unix://...) = (%q, %v), want (/var/run/docker.sock, true)", path, ok)
	}

	_, ok = parseUnixSocket("tcp://localhost:2375")
	if ok {
		t.Error("parseUnixSocket(tcp://...) should return false")
	}
}

// ---------------------------------------------------------------------------
// DefaultExecOptions
// ---------------------------------------------------------------------------

func TestDefaultExecOptions(t *testing.T) {
	opts := DefaultExecOptions()
	if opts.Tty {
		t.Error("Tty should be false")
	}
	if opts.AttachStdin {
		t.Error("AttachStdin should be false")
	}
	if opts.Detach {
		t.Error("Detach should be false")
	}
}

// ---------------------------------------------------------------------------
// ComposeFile parsing
// ---------------------------------------------------------------------------

func TestParseComposeFile(t *testing.T) {
	data := []byte(`
services:
  web:
    image: nginx:latest
    ports:
      - "80:80"
  db:
    image: postgres:16
`)
	compose, err := ParseComposeFile(data)
	if err != nil {
		t.Fatalf("ParseComposeFile() error: %v", err)
	}
	if len(compose.Services) != 2 {
		t.Errorf("got %d services, want 2", len(compose.Services))
	}
	if compose.Services["web"].Image != "nginx:latest" {
		t.Errorf("web image = %q, want %q", compose.Services["web"].Image, "nginx:latest")
	}
}

func TestParseComposeFile_NoServices(t *testing.T) {
	data := []byte(`version: "3"`)
	_, err := ParseComposeFile(data)
	if err == nil {
		t.Fatal("ParseComposeFile() should fail when no services defined")
	}
}

func TestParseComposeFile_InvalidYAML(t *testing.T) {
	data := []byte(`{{invalid yaml`)
	_, err := ParseComposeFile(data)
	if err == nil {
		t.Fatal("ParseComposeFile() should fail with invalid YAML")
	}
}

func TestComposeFile_Validate(t *testing.T) {
	compose := &ComposeFile{
		Services: map[string]ComposeService{
			"web": {}, // No image or build
		},
	}
	if err := compose.Validate(); err == nil {
		t.Fatal("Validate() should fail when service has no image or build")
	}

	compose.Services["web"] = ComposeService{Image: "nginx:latest"}
	if err := compose.Validate(); err != nil {
		t.Fatalf("Validate() should pass with image set: %v", err)
	}
}

func TestComposeFile_GetServiceNames(t *testing.T) {
	compose := &ComposeFile{
		Services: map[string]ComposeService{
			"web": {Image: "nginx"},
			"db":  {Image: "postgres"},
		},
	}
	names := compose.GetServiceNames()
	if len(names) != 2 {
		t.Errorf("GetServiceNames() len = %d, want 2", len(names))
	}
}

func TestMergeComposeFiles(t *testing.T) {
	base := &ComposeFile{
		Version: "3",
		Services: map[string]ComposeService{
			"web": {Image: "nginx:1.0", Restart: "always"},
		},
		Networks: map[string]ComposeNetwork{},
		Volumes:  map[string]ComposeVolume{},
	}
	override := &ComposeFile{
		Services: map[string]ComposeService{
			"web": {Image: "nginx:2.0"}, // Override image
			"db":  {Image: "postgres"},   // New service
		},
		Networks: map[string]ComposeNetwork{},
		Volumes:  map[string]ComposeVolume{},
	}

	result := MergeComposeFiles(base, override)
	if result.Services["web"].Image != "nginx:2.0" {
		t.Errorf("merged web image = %q, want %q", result.Services["web"].Image, "nginx:2.0")
	}
	// Restart should be preserved from base since override didn't set it
	if result.Services["web"].Restart != "always" {
		t.Errorf("merged web restart = %q, want %q", result.Services["web"].Restart, "always")
	}
	if _, ok := result.Services["db"]; !ok {
		t.Error("merged result should include db service from override")
	}
}

// jsonMustMarshal is a test helper that marshals v or fails the test.
func jsonMustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}
