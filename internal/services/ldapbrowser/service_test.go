// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package ldapbrowser

import (
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	apperrors "github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ---------------------------------------------------------------------------
// Mock repository
// ---------------------------------------------------------------------------

type mockConnRepo struct {
	conns     map[uuid.UUID]*models.LDAPConnection
	createErr error
	updateErr error
	deleteErr error
	statuses  map[uuid.UUID]models.LDAPConnectionStatus
}

func newMockConnRepo() *mockConnRepo {
	return &mockConnRepo{
		conns:    make(map[uuid.UUID]*models.LDAPConnection),
		statuses: make(map[uuid.UUID]models.LDAPConnectionStatus),
	}
}

func (r *mockConnRepo) Create(_ context.Context, conn *models.LDAPConnection) error {
	if r.createErr != nil {
		return r.createErr
	}
	if conn.ID == uuid.Nil {
		conn.ID = uuid.New()
	}
	r.conns[conn.ID] = conn
	return nil
}

func (r *mockConnRepo) GetByID(_ context.Context, id uuid.UUID) (*models.LDAPConnection, error) {
	if c, ok := r.conns[id]; ok {
		return c, nil
	}
	return nil, apperrors.NotFound("LDAP connection")
}

func (r *mockConnRepo) ListByUser(_ context.Context, userID uuid.UUID) ([]*models.LDAPConnection, error) {
	var result []*models.LDAPConnection
	for _, c := range r.conns {
		if c.UserID == userID {
			result = append(result, c)
		}
	}
	return result, nil
}

func (r *mockConnRepo) Update(_ context.Context, id uuid.UUID, input models.UpdateLDAPConnectionInput) error {
	if r.updateErr != nil {
		return r.updateErr
	}
	c, ok := r.conns[id]
	if !ok {
		return apperrors.NotFound("LDAP connection")
	}
	if input.Name != nil {
		c.Name = *input.Name
	}
	if input.Host != nil {
		c.Host = *input.Host
	}
	if input.Port != nil {
		c.Port = *input.Port
	}
	if input.BindDN != nil {
		c.BindDN = *input.BindDN
	}
	if input.BindPassword != nil {
		c.BindPassword = *input.BindPassword
	}
	if input.BaseDN != nil {
		c.BaseDN = *input.BaseDN
	}
	if input.UseTLS != nil {
		c.UseTLS = *input.UseTLS
	}
	if input.StartTLS != nil {
		c.StartTLS = *input.StartTLS
	}
	if input.SkipTLSVerify != nil {
		c.SkipTLSVerify = *input.SkipTLSVerify
	}
	return nil
}

func (r *mockConnRepo) UpdateStatus(_ context.Context, id uuid.UUID, status models.LDAPConnectionStatus, _ string) error {
	r.statuses[id] = status
	return nil
}

func (r *mockConnRepo) Delete(_ context.Context, id uuid.UUID) error {
	if r.deleteErr != nil {
		return r.deleteErr
	}
	if _, ok := r.conns[id]; !ok {
		return apperrors.NotFound("LDAP connection")
	}
	delete(r.conns, id)
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func testLogger(t *testing.T) *logger.Logger {
	t.Helper()
	log, err := logger.NewWithOutput("error", "console", io.Discard)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	return log
}

func testEncryptor(t *testing.T) *crypto.Encryptor {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	enc, err := crypto.NewEncryptor(key)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}
	return enc
}

func newTestService(t *testing.T, repo *mockConnRepo) *Service {
	t.Helper()
	return &Service{
		connRepo: repo,
		crypto:   testEncryptor(t),
		logger:   testLogger(t),
	}
}

// ---------------------------------------------------------------------------
// CreateConnection tests
// ---------------------------------------------------------------------------

func TestCreateConnection(t *testing.T) {
	repo := newMockConnRepo()
	svc := newTestService(t, repo)
	ctx := context.Background()
	userID := uuid.New()

	input := models.CreateLDAPConnectionInput{
		Name:         "test-ldap",
		Host:         "ldap.example.com",
		Port:         389,
		BindDN:       "cn=admin,dc=example,dc=com",
		BindPassword: "secret",
		BaseDN:       "dc=example,dc=com",
	}

	conn, err := svc.CreateConnection(ctx, input, userID)
	if err != nil {
		t.Fatalf("CreateConnection returned error: %v", err)
	}
	if conn.ID == uuid.Nil {
		t.Fatal("expected non-nil connection ID")
	}
	if conn.Name != "test-ldap" {
		t.Errorf("Name = %q, want %q", conn.Name, "test-ldap")
	}
	if conn.Host != "ldap.example.com" {
		t.Errorf("Host = %q, want %q", conn.Host, "ldap.example.com")
	}
	if conn.Port != 389 {
		t.Errorf("Port = %d, want 389", conn.Port)
	}
	if conn.UserID != userID {
		t.Errorf("UserID = %v, want %v", conn.UserID, userID)
	}
	if conn.Status != models.LDAPStatusDisconnected {
		t.Errorf("Status = %q, want %q", conn.Status, models.LDAPStatusDisconnected)
	}
	if conn.BindDN != "cn=admin,dc=example,dc=com" {
		t.Errorf("BindDN = %q, want %q", conn.BindDN, "cn=admin,dc=example,dc=com")
	}
	if conn.BaseDN != "dc=example,dc=com" {
		t.Errorf("BaseDN = %q, want %q", conn.BaseDN, "dc=example,dc=com")
	}
	// Password should be encrypted, not plaintext
	if conn.BindPassword == "secret" {
		t.Error("password should be encrypted, not stored as plaintext")
	}
	if conn.BindPassword == "" {
		t.Error("encrypted password should not be empty")
	}
}

func TestCreateConnection_NoPassword(t *testing.T) {
	repo := newMockConnRepo()
	svc := newTestService(t, repo)
	ctx := context.Background()
	userID := uuid.New()

	input := models.CreateLDAPConnectionInput{
		Name:         "no-pass",
		Host:         "ldap.example.com",
		Port:         389,
		BindDN:       "cn=admin,dc=example,dc=com",
		BindPassword: "",
		BaseDN:       "dc=example,dc=com",
	}

	conn, err := svc.CreateConnection(ctx, input, userID)
	if err != nil {
		t.Fatalf("CreateConnection returned error: %v", err)
	}
	if conn.BindPassword != "" {
		t.Errorf("password should be empty, got %q", conn.BindPassword)
	}
}

func TestCreateConnection_NilCrypto(t *testing.T) {
	repo := newMockConnRepo()
	svc := &Service{
		connRepo: repo,
		crypto:   nil,
		logger:   testLogger(t),
	}
	ctx := context.Background()
	userID := uuid.New()

	input := models.CreateLDAPConnectionInput{
		Name:         "nil-crypto",
		Host:         "ldap.example.com",
		Port:         389,
		BindDN:       "cn=admin,dc=example,dc=com",
		BindPassword: "secret",
		BaseDN:       "dc=example,dc=com",
	}

	conn, err := svc.CreateConnection(ctx, input, userID)
	if err != nil {
		t.Fatalf("CreateConnection returned error: %v", err)
	}
	// With nil crypto, password should be empty (not encrypted)
	if conn.BindPassword != "" {
		t.Errorf("with nil crypto, password should be empty, got %q", conn.BindPassword)
	}
}

func TestCreateConnection_TLSOptions(t *testing.T) {
	repo := newMockConnRepo()
	svc := newTestService(t, repo)
	ctx := context.Background()
	userID := uuid.New()

	input := models.CreateLDAPConnectionInput{
		Name:          "tls-ldap",
		Host:          "ldap.example.com",
		Port:          636,
		UseTLS:        true,
		StartTLS:      false,
		SkipTLSVerify: true,
		BindDN:        "cn=admin,dc=example,dc=com",
		BindPassword:  "secret",
		BaseDN:        "dc=example,dc=com",
	}

	conn, err := svc.CreateConnection(ctx, input, userID)
	if err != nil {
		t.Fatalf("CreateConnection returned error: %v", err)
	}
	if !conn.UseTLS {
		t.Error("UseTLS should be true")
	}
	if conn.StartTLS {
		t.Error("StartTLS should be false")
	}
	if !conn.SkipTLSVerify {
		t.Error("SkipTLSVerify should be true")
	}
}

func TestCreateConnection_RepoError(t *testing.T) {
	repo := newMockConnRepo()
	repo.createErr = fmt.Errorf("database error")
	svc := newTestService(t, repo)
	ctx := context.Background()

	input := models.CreateLDAPConnectionInput{
		Name:         "fail",
		Host:         "ldap.example.com",
		Port:         389,
		BindDN:       "cn=admin,dc=example,dc=com",
		BindPassword: "secret",
		BaseDN:       "dc=example,dc=com",
	}

	_, err := svc.CreateConnection(ctx, input, uuid.New())
	if err == nil {
		t.Fatal("expected error from repo, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetConnection tests
// ---------------------------------------------------------------------------

func TestGetConnection(t *testing.T) {
	repo := newMockConnRepo()
	svc := newTestService(t, repo)
	ctx := context.Background()
	userID := uuid.New()

	input := models.CreateLDAPConnectionInput{
		Name:         "get-test",
		Host:         "ldap.example.com",
		Port:         389,
		BindDN:       "cn=admin,dc=example,dc=com",
		BindPassword: "secret",
		BaseDN:       "dc=example,dc=com",
	}
	created, err := svc.CreateConnection(ctx, input, userID)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	got, err := svc.GetConnection(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetConnection returned error: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("ID = %v, want %v", got.ID, created.ID)
	}
	if got.Name != "get-test" {
		t.Errorf("Name = %q, want %q", got.Name, "get-test")
	}
}

func TestGetConnection_NotFound(t *testing.T) {
	repo := newMockConnRepo()
	svc := newTestService(t, repo)
	ctx := context.Background()

	_, err := svc.GetConnection(ctx, uuid.New())
	if err == nil {
		t.Fatal("expected not-found error, got nil")
	}
	if !apperrors.IsNotFoundError(err) {
		t.Errorf("expected not-found error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ListConnections tests
// ---------------------------------------------------------------------------

func TestListConnections(t *testing.T) {
	repo := newMockConnRepo()
	svc := newTestService(t, repo)
	ctx := context.Background()

	userA := uuid.New()
	userB := uuid.New()

	for i := 0; i < 3; i++ {
		input := models.CreateLDAPConnectionInput{
			Name:         fmt.Sprintf("conn-a-%d", i),
			Host:         "ldap.example.com",
			Port:         389,
			BindDN:       "cn=admin,dc=example,dc=com",
			BindPassword: "secret",
			BaseDN:       "dc=example,dc=com",
		}
		if _, err := svc.CreateConnection(ctx, input, userA); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}
	input := models.CreateLDAPConnectionInput{
		Name:         "conn-b-0",
		Host:         "ldap2.example.com",
		Port:         636,
		BindDN:       "cn=admin,dc=example,dc=com",
		BindPassword: "secret",
		BaseDN:       "dc=example,dc=com",
	}
	if _, err := svc.CreateConnection(ctx, input, userB); err != nil {
		t.Fatalf("setup: %v", err)
	}

	listA, err := svc.ListConnections(ctx, userA)
	if err != nil {
		t.Fatalf("ListConnections(userA): %v", err)
	}
	if len(listA) != 3 {
		t.Errorf("userA connections = %d, want 3", len(listA))
	}

	listB, err := svc.ListConnections(ctx, userB)
	if err != nil {
		t.Fatalf("ListConnections(userB): %v", err)
	}
	if len(listB) != 1 {
		t.Errorf("userB connections = %d, want 1", len(listB))
	}
}

func TestListConnections_Empty(t *testing.T) {
	repo := newMockConnRepo()
	svc := newTestService(t, repo)
	ctx := context.Background()

	list, err := svc.ListConnections(ctx, uuid.New())
	if err != nil {
		t.Fatalf("ListConnections: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected empty list, got %d items", len(list))
	}
}

// ---------------------------------------------------------------------------
// UpdateConnection tests
// ---------------------------------------------------------------------------

func TestUpdateConnection(t *testing.T) {
	repo := newMockConnRepo()
	svc := newTestService(t, repo)
	ctx := context.Background()
	userID := uuid.New()

	input := models.CreateLDAPConnectionInput{
		Name:         "update-test",
		Host:         "ldap.example.com",
		Port:         389,
		BindDN:       "cn=admin,dc=example,dc=com",
		BindPassword: "secret",
		BaseDN:       "dc=example,dc=com",
	}
	created, err := svc.CreateConnection(ctx, input, userID)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	newName := "updated-name"
	newHost := "ldap2.example.com"
	newPort := 636
	err = svc.UpdateConnection(ctx, created.ID, models.UpdateLDAPConnectionInput{
		Name: &newName,
		Host: &newHost,
		Port: &newPort,
	})
	if err != nil {
		t.Fatalf("UpdateConnection: %v", err)
	}

	got, err := svc.GetConnection(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetConnection after update: %v", err)
	}
	if got.Name != "updated-name" {
		t.Errorf("Name = %q, want %q", got.Name, "updated-name")
	}
	if got.Host != "ldap2.example.com" {
		t.Errorf("Host = %q, want %q", got.Host, "ldap2.example.com")
	}
	if got.Port != 636 {
		t.Errorf("Port = %d, want 636", got.Port)
	}
}

func TestUpdateConnection_WithPassword(t *testing.T) {
	repo := newMockConnRepo()
	svc := newTestService(t, repo)
	ctx := context.Background()
	userID := uuid.New()

	input := models.CreateLDAPConnectionInput{
		Name:         "update-pass",
		Host:         "ldap.example.com",
		Port:         389,
		BindDN:       "cn=admin,dc=example,dc=com",
		BindPassword: "oldpass",
		BaseDN:       "dc=example,dc=com",
	}
	created, err := svc.CreateConnection(ctx, input, userID)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	oldPassword := created.BindPassword

	newPass := "newpassword"
	err = svc.UpdateConnection(ctx, created.ID, models.UpdateLDAPConnectionInput{
		BindPassword: &newPass,
	})
	if err != nil {
		t.Fatalf("UpdateConnection: %v", err)
	}

	got, err := svc.GetConnection(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetConnection after update: %v", err)
	}
	// Password should be encrypted and different from old one
	if got.BindPassword == "newpassword" {
		t.Error("password should be encrypted, not plaintext")
	}
	if got.BindPassword == oldPassword {
		t.Error("password should have changed after update")
	}
}

func TestUpdateConnection_EmptyPassword(t *testing.T) {
	repo := newMockConnRepo()
	svc := newTestService(t, repo)
	ctx := context.Background()
	userID := uuid.New()

	input := models.CreateLDAPConnectionInput{
		Name:         "empty-pass",
		Host:         "ldap.example.com",
		Port:         389,
		BindDN:       "cn=admin,dc=example,dc=com",
		BindPassword: "original",
		BaseDN:       "dc=example,dc=com",
	}
	created, err := svc.CreateConnection(ctx, input, userID)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Empty password string should not trigger re-encryption
	emptyPass := ""
	err = svc.UpdateConnection(ctx, created.ID, models.UpdateLDAPConnectionInput{
		BindPassword: &emptyPass,
	})
	if err != nil {
		t.Fatalf("UpdateConnection: %v", err)
	}
}

func TestUpdateConnection_NotFound(t *testing.T) {
	repo := newMockConnRepo()
	svc := newTestService(t, repo)
	ctx := context.Background()

	name := "x"
	err := svc.UpdateConnection(ctx, uuid.New(), models.UpdateLDAPConnectionInput{
		Name: &name,
	})
	if err == nil {
		t.Fatal("expected not-found error, got nil")
	}
	if !apperrors.IsNotFoundError(err) {
		t.Errorf("expected not-found error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// DeleteConnection tests
// ---------------------------------------------------------------------------

func TestDeleteConnection(t *testing.T) {
	repo := newMockConnRepo()
	svc := newTestService(t, repo)
	ctx := context.Background()
	userID := uuid.New()

	input := models.CreateLDAPConnectionInput{
		Name:         "delete-test",
		Host:         "ldap.example.com",
		Port:         389,
		BindDN:       "cn=admin,dc=example,dc=com",
		BindPassword: "secret",
		BaseDN:       "dc=example,dc=com",
	}
	created, err := svc.CreateConnection(ctx, input, userID)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	err = svc.DeleteConnection(ctx, created.ID)
	if err != nil {
		t.Fatalf("DeleteConnection: %v", err)
	}

	_, err = svc.GetConnection(ctx, created.ID)
	if err == nil {
		t.Fatal("expected not-found after delete, got nil")
	}
	if !apperrors.IsNotFoundError(err) {
		t.Errorf("expected not-found error, got: %v", err)
	}
}

func TestDeleteConnection_NotFound(t *testing.T) {
	repo := newMockConnRepo()
	svc := newTestService(t, repo)
	ctx := context.Background()

	err := svc.DeleteConnection(ctx, uuid.New())
	if err == nil {
		t.Fatal("expected not-found error, got nil")
	}
	if !apperrors.IsNotFoundError(err) {
		t.Errorf("expected not-found error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestResult tests
// ---------------------------------------------------------------------------

func TestTestResult_Interface(t *testing.T) {
	r := &TestResult{
		ConnectionID: uuid.New(),
		Success:      true,
		Message:      "Connection successful",
		Latency:      100,
	}

	if !r.IsSuccess() {
		t.Error("IsSuccess() = false, want true")
	}
	if r.GetMessage() != "Connection successful" {
		t.Errorf("GetMessage() = %q, want %q", r.GetMessage(), "Connection successful")
	}
	if r.GetLatency() != 100 {
		t.Errorf("GetLatency() = %v, want 100", r.GetLatency())
	}

	// Verify it implements LDAPTestResulter
	var _ models.LDAPTestResulter = r
}

func TestTestResult_Failure(t *testing.T) {
	r := &TestResult{
		ConnectionID: uuid.New(),
		Success:      false,
		Message:      "connection refused",
	}

	if r.IsSuccess() {
		t.Error("IsSuccess() = true, want false")
	}
	if r.GetMessage() != "connection refused" {
		t.Errorf("GetMessage() = %q, want %q", r.GetMessage(), "connection refused")
	}
	if r.GetLatency() != 0 {
		t.Errorf("GetLatency() = %v, want 0", r.GetLatency())
	}
}

// ---------------------------------------------------------------------------
// TestConnection error paths
// ---------------------------------------------------------------------------

func TestTestConnection_NotFound(t *testing.T) {
	repo := newMockConnRepo()
	svc := newTestService(t, repo)
	ctx := context.Background()

	_, err := svc.TestConnection(ctx, uuid.New())
	if err == nil {
		t.Fatal("expected not-found error, got nil")
	}
	if !apperrors.IsNotFoundError(err) {
		t.Errorf("expected not-found error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Connect error paths
// ---------------------------------------------------------------------------

func TestConnect_NotFound(t *testing.T) {
	repo := newMockConnRepo()
	svc := newTestService(t, repo)
	ctx := context.Background()

	_, err := svc.Connect(ctx, uuid.New())
	if err == nil {
		t.Fatal("expected not-found error, got nil")
	}
	if !apperrors.IsNotFoundError(err) {
		t.Errorf("expected not-found error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ListEntries error paths
// ---------------------------------------------------------------------------

func TestListEntries_NotFound(t *testing.T) {
	repo := newMockConnRepo()
	svc := newTestService(t, repo)
	ctx := context.Background()

	_, err := svc.ListEntries(ctx, uuid.New(), "", 0)
	if err == nil {
		t.Fatal("expected not-found error, got nil")
	}
	if !apperrors.IsNotFoundError(err) {
		t.Errorf("expected not-found error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetEntry error paths
// ---------------------------------------------------------------------------

func TestGetEntry_NotFound(t *testing.T) {
	repo := newMockConnRepo()
	svc := newTestService(t, repo)
	ctx := context.Background()

	_, err := svc.GetEntry(ctx, uuid.New(), "cn=test,dc=example,dc=com")
	if err == nil {
		t.Fatal("expected not-found error, got nil")
	}
	if !apperrors.IsNotFoundError(err) {
		t.Errorf("expected not-found error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Search error paths
// ---------------------------------------------------------------------------

func TestSearch_NotFound(t *testing.T) {
	repo := newMockConnRepo()
	svc := newTestService(t, repo)
	ctx := context.Background()

	_, err := svc.Search(ctx, uuid.New(), "", "", 0, nil)
	if err == nil {
		t.Fatal("expected not-found error, got nil")
	}
	if !apperrors.IsNotFoundError(err) {
		t.Errorf("expected not-found error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Helper function tests
// ---------------------------------------------------------------------------

func TestGetRDN(t *testing.T) {
	tests := []struct {
		dn   string
		want string
	}{
		{"cn=admin,dc=example,dc=com", "cn=admin"},
		{"dc=example,dc=com", "dc=example"},
		{"cn=single", "cn=single"},
		{"", ""},
	}

	for _, tt := range tests {
		got := getRDN(tt.dn)
		if got != tt.want {
			t.Errorf("getRDN(%q) = %q, want %q", tt.dn, got, tt.want)
		}
	}
}

func TestScopeToString(t *testing.T) {
	tests := []struct {
		scope int
		want  string
	}{
		{ldap.ScopeBaseObject, "base"},
		{ldap.ScopeSingleLevel, "one"},
		{ldap.ScopeWholeSubtree, "sub"},
		{999, "unknown"},
	}

	for _, tt := range tests {
		got := scopeToString(tt.scope)
		if got != tt.want {
			t.Errorf("scopeToString(%d) = %q, want %q", tt.scope, got, tt.want)
		}
	}
}
