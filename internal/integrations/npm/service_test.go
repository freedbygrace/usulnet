// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package npm

import (
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"go.uber.org/zap"

	"github.com/fr4nsys/usulnet/internal/models"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestService() *Service {
	return NewService(nil, nil, nil, nil, zap.NewNop())
}

// makeInspectResponse builds a container.InspectResponse with the given
// id, name, labels, and exposed ports. Pass nil for exposedPorts if none.
func makeInspectResponse(id, name string, labels map[string]string, exposedPorts nat.PortSet) *container.InspectResponse {
	return &container.InspectResponse{
		ContainerJSONBase: &container.ContainerJSONBase{
			ID:   id,
			Name: name,
		},
		Config: &container.Config{
			Labels:       labels,
			ExposedPorts: exposedPorts,
		},
	}
}

// ---------------------------------------------------------------------------
// Tests: nullableStr
// ---------------------------------------------------------------------------

func TestNullableStr_Empty(t *testing.T) {
	got := nullableStr("")
	if got != nil {
		t.Errorf("nullableStr(\"\") = %v, want nil", got)
	}
}

func TestNullableStr_NonEmpty(t *testing.T) {
	got := nullableStr("hello")
	if got == nil {
		t.Fatal("nullableStr(\"hello\") = nil, want non-nil")
	}
	if *got != "hello" {
		t.Errorf("nullableStr(\"hello\") = %q, want \"hello\"", *got)
	}
}

func TestNullableStr_Whitespace(t *testing.T) {
	got := nullableStr(" ")
	if got == nil {
		t.Fatal("nullableStr(\" \") = nil, want non-nil (only empty string returns nil)")
	}
	if *got != " " {
		t.Errorf("nullableStr(\" \") = %q, want \" \"", *got)
	}
}

func TestNullableStr_LongString(t *testing.T) {
	s := "a-long-user-id-that-might-be-a-uuid-like-value"
	got := nullableStr(s)
	if got == nil {
		t.Fatal("expected non-nil for non-empty string")
	}
	if *got != s {
		t.Errorf("got %q, want %q", *got, s)
	}
}

// ---------------------------------------------------------------------------
// Tests: NewService
// ---------------------------------------------------------------------------

func TestNewService(t *testing.T) {
	svc := newTestService()
	if svc == nil {
		t.Fatal("NewService returned nil")
	}
	if svc.clients == nil {
		t.Error("expected non-nil clients map")
	}
	if svc.logger == nil {
		t.Error("expected non-nil logger")
	}
}

// ---------------------------------------------------------------------------
// Tests: Type aliases
// ---------------------------------------------------------------------------

func TestConnectionCreateIsAlias(t *testing.T) {
	// ConnectionCreate should be usable as models.NPMConnectionCreate.
	var c ConnectionCreate
	c.HostID = "host-1"
	c.BaseURL = "http://npm:81"
	c.AdminEmail = "admin@example.com"
	c.AdminPassword = "secret"

	var m models.NPMConnectionCreate = c
	if m.HostID != "host-1" {
		t.Errorf("HostID = %q, want \"host-1\"", m.HostID)
	}
}

func TestConnectionUpdateIsAlias(t *testing.T) {
	url := "http://npm:81"
	var c ConnectionUpdate
	c.BaseURL = &url

	var m models.NPMConnectionUpdate = c
	if m.BaseURL == nil || *m.BaseURL != url {
		t.Errorf("BaseURL = %v, want %q", m.BaseURL, url)
	}
}

// ---------------------------------------------------------------------------
// Tests: ExtractProxyConfig
// ---------------------------------------------------------------------------

func TestExtractProxyConfig_NoDomain(t *testing.T) {
	svc := newTestService()
	info := makeInspectResponse("abc123", "/myapp", map[string]string{}, nil)

	got := svc.ExtractProxyConfig(info)
	if got != nil {
		t.Errorf("expected nil when no domain label, got %+v", got)
	}
}

func TestExtractProxyConfig_EmptyDomain(t *testing.T) {
	svc := newTestService()
	labels := map[string]string{
		models.LabelProxyDomain: "",
	}
	info := makeInspectResponse("abc123", "/myapp", labels, nil)

	got := svc.ExtractProxyConfig(info)
	if got != nil {
		t.Errorf("expected nil when domain label is empty string, got %+v", got)
	}
}

func TestExtractProxyConfig_DomainOnly(t *testing.T) {
	svc := newTestService()
	labels := map[string]string{
		models.LabelProxyDomain: "example.com",
	}
	exposed := nat.PortSet{
		nat.Port("8080/tcp"): struct{}{},
	}
	info := makeInspectResponse("abc123", "/myapp", labels, exposed)

	got := svc.ExtractProxyConfig(info)
	if got == nil {
		t.Fatal("expected non-nil config")
	}

	if got.ContainerID != "abc123" {
		t.Errorf("ContainerID = %q, want \"abc123\"", got.ContainerID)
	}
	if got.ContainerName != "myapp" {
		t.Errorf("ContainerName = %q, want \"myapp\" (should strip / prefix)", got.ContainerName)
	}
	if got.Domain != "example.com" {
		t.Errorf("Domain = %q, want \"example.com\"", got.Domain)
	}
	if got.Scheme != "http" {
		t.Errorf("Scheme = %q, want \"http\" (default)", got.Scheme)
	}
	if got.Port != 8080 {
		t.Errorf("Port = %d, want 8080 (from exposed ports)", got.Port)
	}
	if !got.SSL {
		t.Error("SSL = false, want true (default)")
	}
	if !got.SSLForced {
		t.Error("SSLForced = false, want true (default)")
	}
	if got.Websocket {
		t.Error("Websocket = true, want false (default)")
	}
	if !got.BlockExploits {
		t.Error("BlockExploits = false, want true (default)")
	}
}

func TestExtractProxyConfig_AllLabels(t *testing.T) {
	svc := newTestService()
	labels := map[string]string{
		models.LabelProxyDomain:       "app.example.com",
		models.LabelProxyPort:         "3000",
		models.LabelProxyScheme:       "https",
		models.LabelProxySSL:          "true",
		models.LabelProxySSLForced:    "true",
		models.LabelProxyWebsocket:    "true",
		models.LabelProxyBlockExploit: "true",
	}
	info := makeInspectResponse("def456", "/webapp", labels, nil)

	got := svc.ExtractProxyConfig(info)
	if got == nil {
		t.Fatal("expected non-nil config")
	}

	if got.Domain != "app.example.com" {
		t.Errorf("Domain = %q, want \"app.example.com\"", got.Domain)
	}
	if got.Port != 3000 {
		t.Errorf("Port = %d, want 3000", got.Port)
	}
	if got.Scheme != "https" {
		t.Errorf("Scheme = %q, want \"https\"", got.Scheme)
	}
	if !got.SSL {
		t.Error("SSL = false, want true")
	}
	if !got.SSLForced {
		t.Error("SSLForced = false, want true")
	}
	if !got.Websocket {
		t.Error("Websocket = false, want true")
	}
	if !got.BlockExploits {
		t.Error("BlockExploits = false, want true")
	}
}

func TestExtractProxyConfig_PortFromExposedPorts(t *testing.T) {
	svc := newTestService()
	labels := map[string]string{
		models.LabelProxyDomain: "example.com",
	}
	exposed := nat.PortSet{
		nat.Port("9090/tcp"): struct{}{},
	}
	info := makeInspectResponse("id1", "/svc", labels, exposed)

	got := svc.ExtractProxyConfig(info)
	if got == nil {
		t.Fatal("expected non-nil config")
	}
	if got.Port != 9090 {
		t.Errorf("Port = %d, want 9090 (from exposed ports)", got.Port)
	}
}

func TestExtractProxyConfig_PortFromLabel(t *testing.T) {
	svc := newTestService()
	labels := map[string]string{
		models.LabelProxyDomain: "example.com",
		models.LabelProxyPort:   "4000",
	}
	// Exposed port is different; label should take priority.
	exposed := nat.PortSet{
		nat.Port("8080/tcp"): struct{}{},
	}
	info := makeInspectResponse("id2", "/svc", labels, exposed)

	got := svc.ExtractProxyConfig(info)
	if got == nil {
		t.Fatal("expected non-nil config")
	}
	if got.Port != 4000 {
		t.Errorf("Port = %d, want 4000 (label overrides exposed port)", got.Port)
	}
}

func TestExtractProxyConfig_InvalidPortLabel(t *testing.T) {
	svc := newTestService()
	labels := map[string]string{
		models.LabelProxyDomain: "example.com",
		models.LabelProxyPort:   "not-a-number",
	}
	info := makeInspectResponse("id3", "/svc", labels, nil)

	got := svc.ExtractProxyConfig(info)
	if got == nil {
		t.Fatal("expected non-nil config")
	}
	// Invalid port label should result in 0 (strconv.Atoi fails, no fallback to exposed ports).
	if got.Port != 0 {
		t.Errorf("Port = %d, want 0 (invalid port label, no fallback)", got.Port)
	}
}

func TestExtractProxyConfig_CustomScheme(t *testing.T) {
	svc := newTestService()
	labels := map[string]string{
		models.LabelProxyDomain: "example.com",
		models.LabelProxyScheme: "https",
	}
	info := makeInspectResponse("id4", "/svc", labels, nil)

	got := svc.ExtractProxyConfig(info)
	if got == nil {
		t.Fatal("expected non-nil config")
	}
	if got.Scheme != "https" {
		t.Errorf("Scheme = %q, want \"https\"", got.Scheme)
	}
}

func TestExtractProxyConfig_SSLFalse(t *testing.T) {
	svc := newTestService()
	labels := map[string]string{
		models.LabelProxyDomain: "example.com",
		models.LabelProxySSL:    "false",
	}
	info := makeInspectResponse("id5", "/svc", labels, nil)

	got := svc.ExtractProxyConfig(info)
	if got == nil {
		t.Fatal("expected non-nil config")
	}
	if got.SSL {
		t.Error("SSL = true, want false (label explicitly set to \"false\")")
	}
}

func TestExtractProxyConfig_SSLWithOne(t *testing.T) {
	svc := newTestService()
	labels := map[string]string{
		models.LabelProxyDomain: "example.com",
		models.LabelProxySSL:    "1",
	}
	info := makeInspectResponse("id6", "/svc", labels, nil)

	got := svc.ExtractProxyConfig(info)
	if got == nil {
		t.Fatal("expected non-nil config")
	}
	if !got.SSL {
		t.Error("SSL = false, want true (label \"1\" should be treated as true)")
	}
}

func TestExtractProxyConfig_SSLForcedFalse(t *testing.T) {
	svc := newTestService()
	labels := map[string]string{
		models.LabelProxyDomain:    "example.com",
		models.LabelProxySSLForced: "false",
	}
	info := makeInspectResponse("id7", "/svc", labels, nil)

	got := svc.ExtractProxyConfig(info)
	if got == nil {
		t.Fatal("expected non-nil config")
	}
	if got.SSLForced {
		t.Error("SSLForced = true, want false (label explicitly set to \"false\")")
	}
}

func TestExtractProxyConfig_WebsocketEnabled(t *testing.T) {
	svc := newTestService()
	labels := map[string]string{
		models.LabelProxyDomain:    "example.com",
		models.LabelProxyWebsocket: "true",
	}
	info := makeInspectResponse("id8", "/svc", labels, nil)

	got := svc.ExtractProxyConfig(info)
	if got == nil {
		t.Fatal("expected non-nil config")
	}
	if !got.Websocket {
		t.Error("Websocket = false, want true")
	}
}

func TestExtractProxyConfig_BlockExploitsFalse(t *testing.T) {
	svc := newTestService()
	labels := map[string]string{
		models.LabelProxyDomain:       "example.com",
		models.LabelProxyBlockExploit: "0",
	}
	info := makeInspectResponse("id9", "/svc", labels, nil)

	got := svc.ExtractProxyConfig(info)
	if got == nil {
		t.Fatal("expected non-nil config")
	}
	if got.BlockExploits {
		t.Error("BlockExploits = true, want false (label \"0\" is neither \"true\" nor \"1\")")
	}
}

func TestExtractProxyConfig_ContainerNamePrefix(t *testing.T) {
	svc := newTestService()
	labels := map[string]string{
		models.LabelProxyDomain: "example.com",
	}
	info := makeInspectResponse("id10", "/my-container", labels, nil)

	got := svc.ExtractProxyConfig(info)
	if got == nil {
		t.Fatal("expected non-nil config")
	}
	if got.ContainerName != "my-container" {
		t.Errorf("ContainerName = %q, want \"my-container\" (should strip \"/\" prefix)", got.ContainerName)
	}
}

func TestExtractProxyConfig_ContainerNameNoPrefix(t *testing.T) {
	svc := newTestService()
	labels := map[string]string{
		models.LabelProxyDomain: "example.com",
	}
	// Name without "/" prefix (edge case).
	info := makeInspectResponse("id11", "noslash", labels, nil)

	got := svc.ExtractProxyConfig(info)
	if got == nil {
		t.Fatal("expected non-nil config")
	}
	if got.ContainerName != "noslash" {
		t.Errorf("ContainerName = %q, want \"noslash\"", got.ContainerName)
	}
}

func TestExtractProxyConfig_NoExposedPorts(t *testing.T) {
	svc := newTestService()
	labels := map[string]string{
		models.LabelProxyDomain: "example.com",
	}
	// No port label and no exposed ports.
	info := makeInspectResponse("id12", "/svc", labels, nil)

	got := svc.ExtractProxyConfig(info)
	if got == nil {
		t.Fatal("expected non-nil config")
	}
	if got.Port != 0 {
		t.Errorf("Port = %d, want 0 (no port label, no exposed ports)", got.Port)
	}
}
