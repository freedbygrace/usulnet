// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package ldap

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// ============================================================================
// DefaultConfig Tests
// ============================================================================

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Port != 389 {
		t.Fatalf("expected port 389, got %d", cfg.Port)
	}
	if cfg.UsernameAttr != "sAMAccountName" {
		t.Fatalf("expected sAMAccountName, got %s", cfg.UsernameAttr)
	}
	if cfg.EmailAttr != "mail" {
		t.Fatalf("expected mail, got %s", cfg.EmailAttr)
	}
	if cfg.UserFilter != "(objectClass=user)" {
		t.Fatalf("expected (objectClass=user), got %s", cfg.UserFilter)
	}
	if cfg.GroupFilter != "(objectClass=group)" {
		t.Fatalf("expected (objectClass=group), got %s", cfg.GroupFilter)
	}
	if cfg.GroupAttr != "member" {
		t.Fatalf("expected member, got %s", cfg.GroupAttr)
	}
	if cfg.DefaultRole != models.RoleViewer {
		t.Fatalf("expected viewer, got %s", cfg.DefaultRole)
	}
	if cfg.Timeout != 10*time.Second {
		t.Fatalf("expected 10s timeout, got %v", cfg.Timeout)
	}
}

// ============================================================================
// Client Constructor and In-Memory Method Tests
// ============================================================================

func newTestClient() *Client {
	cfg := Config{
		ID:            uuid.New(),
		Name:          "TestLDAP",
		Host:          "ldap.example.com",
		Port:          389,
		BaseDN:        "dc=example,dc=com",
		BindDN:        "cn=admin,dc=example,dc=com",
		BindPassword:  "secret",
		UserFilter:    "(objectClass=user)",
		UsernameAttr:  "sAMAccountName",
		EmailAttr:     "mail",
		GroupFilter:   "(objectClass=group)",
		GroupAttr:     "member",
		AdminGroup:    "admins",
		OperatorGroup: "operators",
		DefaultRole:   models.RoleViewer,
		Enabled:       true,
		Timeout:       10 * time.Second,
	}

	return NewClient(cfg, nil, nil)
}

func TestNewClient(t *testing.T) {
	c := newTestClient()
	if c == nil {
		t.Fatal("client should not be nil")
	}
}

func TestNewClient_NilLogger(t *testing.T) {
	c := NewClient(DefaultConfig(), nil, nil)
	if c == nil {
		t.Fatal("should handle nil logger")
	}
}

func TestNewClient_ZeroTimeout(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Timeout = 0

	c := NewClient(cfg, nil, nil)
	if c.config.Timeout != 10*time.Second {
		t.Fatalf("expected default 10s timeout for zero, got %v", c.config.Timeout)
	}
}

func TestClient_GetName(t *testing.T) {
	c := newTestClient()
	if c.GetName() != "TestLDAP" {
		t.Fatalf("expected TestLDAP, got %s", c.GetName())
	}
}

func TestClient_IsEnabled(t *testing.T) {
	c := newTestClient()
	if !c.IsEnabled() {
		t.Fatal("expected enabled")
	}
}

func TestClient_IsEnabled_Disabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false
	c := NewClient(cfg, nil, nil)

	if c.IsEnabled() {
		t.Fatal("expected disabled")
	}
}

func TestClient_GetID(t *testing.T) {
	c := newTestClient()
	if c.GetID() == uuid.Nil {
		t.Fatal("expected non-nil UUID")
	}
}

func TestClient_GetConfig(t *testing.T) {
	c := newTestClient()
	cfg := c.GetConfig()

	if cfg.Name != "TestLDAP" {
		t.Fatalf("expected name TestLDAP, got %s", cfg.Name)
	}
	if cfg.Host != "ldap.example.com" {
		t.Fatalf("expected host ldap.example.com, got %s", cfg.Host)
	}
	if cfg.BindPassword != "********" {
		t.Fatalf("expected masked password, got %s", cfg.BindPassword)
	}
}

func TestClient_GetConfig_MasksPassword(t *testing.T) {
	c := newTestClient()
	cfg := c.GetConfig()

	// Password must always be masked
	if cfg.BindPassword != "********" {
		t.Fatalf("bind password must be masked, got %s", cfg.BindPassword)
	}

	// Original config must not be modified
	if c.config.BindPassword == "********" {
		t.Fatal("original config password should not be masked")
	}
}

func TestClient_UpdateConfig(t *testing.T) {
	c := newTestClient()

	newCfg := DefaultConfig()
	newCfg.Name = "UpdatedLDAP"
	newCfg.Host = "new-ldap.example.com"
	newCfg.Port = 636
	newCfg.Enabled = false

	c.UpdateConfig(newCfg)

	if c.GetName() != "UpdatedLDAP" {
		t.Fatalf("expected UpdatedLDAP, got %s", c.GetName())
	}
	if c.IsEnabled() {
		t.Fatal("expected disabled after update")
	}
	if c.config.Host != "new-ldap.example.com" {
		t.Fatalf("expected new host, got %s", c.config.Host)
	}
	if c.config.Port != 636 {
		t.Fatalf("expected port 636, got %d", c.config.Port)
	}
}

// ============================================================================
// determineRole Tests
// ============================================================================

func TestClient_DetermineRole_Admin(t *testing.T) {
	c := newTestClient()

	role := c.determineRole([]string{"users", "admins"})
	if role != models.RoleAdmin {
		t.Fatalf("expected admin, got %s", role)
	}
}

func TestClient_DetermineRole_Operator(t *testing.T) {
	c := newTestClient()

	role := c.determineRole([]string{"users", "operators"})
	if role != models.RoleOperator {
		t.Fatalf("expected operator, got %s", role)
	}
}

func TestClient_DetermineRole_Default(t *testing.T) {
	c := newTestClient()

	role := c.determineRole([]string{"users", "developers"})
	if role != models.RoleViewer {
		t.Fatalf("expected viewer, got %s", role)
	}
}

func TestClient_DetermineRole_CaseInsensitive(t *testing.T) {
	c := newTestClient()

	role := c.determineRole([]string{"ADMINS"})
	if role != models.RoleAdmin {
		t.Fatalf("expected admin (case-insensitive), got %s", role)
	}
}

func TestClient_DetermineRole_AdminPriority(t *testing.T) {
	c := newTestClient()

	role := c.determineRole([]string{"operators", "admins"})
	if role != models.RoleAdmin {
		t.Fatalf("expected admin priority over operator, got %s", role)
	}
}

func TestClient_DetermineRole_EmptyGroups(t *testing.T) {
	c := newTestClient()

	role := c.determineRole(nil)
	if role != models.RoleViewer {
		t.Fatalf("expected default role for nil groups, got %s", role)
	}
}

func TestClient_DetermineRole_NoAdminGroupConfigured(t *testing.T) {
	c := newTestClient()
	c.config.AdminGroup = ""

	role := c.determineRole([]string{"admins"})
	// Without admin group configured, should not match
	if role == models.RoleAdmin {
		t.Fatal("should not assign admin when admin group is not configured")
	}
}

func TestClient_DetermineRole_NoOperatorGroupConfigured(t *testing.T) {
	c := newTestClient()
	c.config.OperatorGroup = ""
	c.config.AdminGroup = "" // Clear both

	role := c.determineRole([]string{"operators"})
	if role != models.RoleViewer {
		t.Fatalf("expected viewer when no groups configured, got %s", role)
	}
}

// ============================================================================
// Authenticate (disabled check only — no real LDAP server)
// ============================================================================

func TestClient_Authenticate_Disabled(t *testing.T) {
	c := newTestClient()
	c.config.Enabled = false

	_, err := c.Authenticate(context.Background(), "user", "pass")
	if err == nil {
		t.Fatal("expected error for disabled provider")
	}
}

func TestClient_SearchUsers_Disabled(t *testing.T) {
	c := newTestClient()
	c.config.Enabled = false

	_, err := c.SearchUsers(context.Background())
	if err == nil {
		t.Fatal("expected error for disabled provider")
	}
}

func TestClient_SearchGroups_Disabled(t *testing.T) {
	c := newTestClient()
	c.config.Enabled = false

	_, err := c.SearchGroups(context.Background())
	if err == nil {
		t.Fatal("expected error for disabled provider")
	}
}

// ============================================================================
// DefaultSyncConfig Tests
// ============================================================================

func TestDefaultSyncConfig(t *testing.T) {
	cfg := DefaultSyncConfig()

	if cfg.Interval != 6*time.Hour {
		t.Fatalf("expected 6h interval, got %v", cfg.Interval)
	}
	if cfg.BatchSize != 100 {
		t.Fatalf("expected batch size 100, got %d", cfg.BatchSize)
	}
	if cfg.DisableUsers {
		t.Fatal("expected disable_users=false")
	}
	if !cfg.UpdateRoles {
		t.Fatal("expected update_roles=true")
	}
	if cfg.DryRun {
		t.Fatal("expected dry_run=false")
	}
}

// ============================================================================
// SyncService In-Memory Tests
// ============================================================================

func TestSyncService_NewSyncService(t *testing.T) {
	s := NewSyncService(nil, nil, DefaultSyncConfig(), nil)
	if s == nil {
		t.Fatal("sync service should not be nil")
	}
}

func TestSyncService_IsRunning(t *testing.T) {
	s := NewSyncService(nil, nil, DefaultSyncConfig(), nil)
	if s.IsRunning() {
		t.Fatal("should not be running initially")
	}
}

func TestSyncService_GetLastResult_Nil(t *testing.T) {
	s := NewSyncService(nil, nil, DefaultSyncConfig(), nil)
	if s.GetLastResult() != nil {
		t.Fatal("last result should be nil initially")
	}
}

func TestSyncService_AddClient(t *testing.T) {
	s := NewSyncService(nil, nil, DefaultSyncConfig(), nil)
	c := newTestClient()

	s.AddClient(c)

	if len(s.clients) != 1 {
		t.Fatalf("expected 1 client, got %d", len(s.clients))
	}
	if s.clients[0].GetName() != "TestLDAP" {
		t.Fatalf("expected TestLDAP, got %s", s.clients[0].GetName())
	}
}

func TestSyncService_RemoveClient(t *testing.T) {
	c1 := newTestClient()
	c1.config.Name = "Client1"
	c2 := newTestClient()
	c2.config.Name = "Client2"

	s := NewSyncService([]*Client{c1, c2}, nil, DefaultSyncConfig(), nil)

	if len(s.clients) != 2 {
		t.Fatalf("expected 2 clients, got %d", len(s.clients))
	}

	s.RemoveClient("Client1")

	if len(s.clients) != 1 {
		t.Fatalf("expected 1 client after removal, got %d", len(s.clients))
	}
	if s.clients[0].GetName() != "Client2" {
		t.Fatalf("expected Client2 to remain, got %s", s.clients[0].GetName())
	}
}

func TestSyncService_RemoveClient_NotFound(t *testing.T) {
	c := newTestClient()
	s := NewSyncService([]*Client{c}, nil, DefaultSyncConfig(), nil)

	s.RemoveClient("nonexistent")

	if len(s.clients) != 1 {
		t.Fatalf("expected client count unchanged, got %d", len(s.clients))
	}
}

func TestSyncService_UpdateConfig(t *testing.T) {
	s := NewSyncService(nil, nil, DefaultSyncConfig(), nil)

	newCfg := SyncConfig{
		Interval:     1 * time.Hour,
		BatchSize:    50,
		DisableUsers: true,
		UpdateRoles:  false,
		DryRun:       true,
	}

	s.UpdateConfig(newCfg)

	if s.config.Interval != 1*time.Hour {
		t.Fatalf("expected 1h interval, got %v", s.config.Interval)
	}
	if s.config.BatchSize != 50 {
		t.Fatalf("expected batch 50, got %d", s.config.BatchSize)
	}
	if !s.config.DisableUsers {
		t.Fatal("expected disable_users=true")
	}
	if s.config.UpdateRoles {
		t.Fatal("expected update_roles=false")
	}
	if !s.config.DryRun {
		t.Fatal("expected dry_run=true")
	}
}

func TestSyncService_SyncAll_NoClients(t *testing.T) {
	s := NewSyncService(nil, nil, DefaultSyncConfig(), nil)
	results := s.SyncAll(context.Background())

	if len(results) != 0 {
		t.Fatalf("expected no results with no clients, got %d", len(results))
	}
}

func TestSyncService_SyncAll_DisabledClients(t *testing.T) {
	c := newTestClient()
	c.config.Enabled = false

	s := NewSyncService([]*Client{c}, nil, DefaultSyncConfig(), nil)
	results := s.SyncAll(context.Background())

	// Disabled clients are skipped
	if len(results) != 0 {
		t.Fatalf("expected 0 results for disabled client, got %d", len(results))
	}
}

func TestSyncService_SyncProvider_NotFound(t *testing.T) {
	s := NewSyncService(nil, nil, DefaultSyncConfig(), nil)

	_, err := s.SyncProvider(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent provider")
	}
}

// ============================================================================
// SyncResult Tests
// ============================================================================

func TestSyncResult_Struct(t *testing.T) {
	now := time.Now().UTC()
	result := &SyncResult{
		StartedAt:     now,
		CompletedAt:   now.Add(5 * time.Second),
		Duration:      5 * time.Second,
		Provider:      "test-provider",
		UsersFound:    100,
		UsersCreated:  10,
		UsersUpdated:  5,
		UsersDisabled: 2,
		UsersSkipped:  83,
		Errors:        []string{"error1"},
	}

	if result.Provider != "test-provider" {
		t.Fatalf("expected test-provider, got %s", result.Provider)
	}
	if result.UsersFound != 100 {
		t.Fatalf("expected 100, got %d", result.UsersFound)
	}
	if result.UsersCreated+result.UsersUpdated+result.UsersDisabled+result.UsersSkipped != 100 {
		t.Fatal("user counts don't add up")
	}
	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(result.Errors))
	}
}

// ============================================================================
// ProviderFromModel Tests
// ============================================================================

func TestProviderFromModel(t *testing.T) {
	id := uuid.New()
	model := &models.LDAPConfig{
		ID:            id,
		Name:          "Corp LDAP",
		Host:          "ldap.corp.local",
		Port:          636,
		UseTLS:        true,
		StartTLS:      false,
		SkipTLSVerify: false,
		BindDN:        "cn=reader,dc=corp,dc=local",
		BindPassword:  "encrypted-pass",
		BaseDN:        "dc=corp,dc=local",
		UserFilter:    "(objectClass=person)",
		UsernameAttr:  "uid",
		EmailAttr:     "mail",
		GroupFilter:   "(objectClass=groupOfNames)",
		GroupAttr:     "member",
		AdminGroup:    "cn=admins",
		OperatorGroup: "cn=operators",
		DefaultRole:   models.RoleViewer,
		IsEnabled:     true,
	}

	client := ProviderFromModel(model, nil, nil)
	if client == nil {
		t.Fatal("client should not be nil")
	}
	if client.GetName() != "Corp LDAP" {
		t.Fatalf("expected Corp LDAP, got %s", client.GetName())
	}
	if client.GetID() != id {
		t.Fatalf("expected ID %s, got %s", id, client.GetID())
	}
	if !client.IsEnabled() {
		t.Fatal("expected enabled")
	}

	// Verify config mapping
	cfg := client.GetConfig()
	if cfg.Host != "ldap.corp.local" {
		t.Fatalf("expected host ldap.corp.local, got %s", cfg.Host)
	}
	if cfg.Port != 636 {
		t.Fatalf("expected port 636, got %d", cfg.Port)
	}
	if !cfg.UseTLS {
		t.Fatal("expected UseTLS=true")
	}
	if cfg.UserFilter != "(objectClass=person)" {
		t.Fatalf("expected person filter, got %s", cfg.UserFilter)
	}
	if cfg.UsernameAttr != "uid" {
		t.Fatalf("expected uid, got %s", cfg.UsernameAttr)
	}
}

// ============================================================================
// User Struct Tests
// ============================================================================

func TestUser_Struct(t *testing.T) {
	u := User{
		Username: "jdoe",
		Email:    "jdoe@corp.local",
		DN:       "cn=jdoe,ou=users,dc=corp,dc=local",
		Groups:   []string{"admins", "developers"},
		Role:     models.RoleAdmin,
	}

	if u.Username != "jdoe" {
		t.Fatalf("expected jdoe, got %s", u.Username)
	}
	if u.DN == "" {
		t.Fatal("DN should not be empty")
	}
	if len(u.Groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(u.Groups))
	}
}
