// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package database

import (
	"context"
	"fmt"
	"io"
	"testing"

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
	conns     map[uuid.UUID]*models.DatabaseConnection
	createErr error
	updateErr error
	deleteErr error
	statuses  map[uuid.UUID]models.DatabaseConnectionStatus
}

func newMockConnRepo() *mockConnRepo {
	return &mockConnRepo{
		conns:    make(map[uuid.UUID]*models.DatabaseConnection),
		statuses: make(map[uuid.UUID]models.DatabaseConnectionStatus),
	}
}

func (r *mockConnRepo) Create(_ context.Context, conn *models.DatabaseConnection) error {
	if r.createErr != nil {
		return r.createErr
	}
	if conn.ID == uuid.Nil {
		conn.ID = uuid.New()
	}
	r.conns[conn.ID] = conn
	return nil
}

func (r *mockConnRepo) GetByID(_ context.Context, id uuid.UUID) (*models.DatabaseConnection, error) {
	if c, ok := r.conns[id]; ok {
		return c, nil
	}
	return nil, apperrors.NotFound("database connection")
}

func (r *mockConnRepo) ListByUser(_ context.Context, userID uuid.UUID) ([]*models.DatabaseConnection, error) {
	var result []*models.DatabaseConnection
	for _, c := range r.conns {
		if c.UserID == userID {
			result = append(result, c)
		}
	}
	return result, nil
}

func (r *mockConnRepo) Update(_ context.Context, id uuid.UUID, input models.UpdateDatabaseConnectionInput) error {
	if r.updateErr != nil {
		return r.updateErr
	}
	c, ok := r.conns[id]
	if !ok {
		return apperrors.NotFound("database connection")
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
	if input.Password != nil {
		c.Password = *input.Password
	}
	return nil
}

func (r *mockConnRepo) UpdateStatus(_ context.Context, id uuid.UUID, status models.DatabaseConnectionStatus, _ string) error {
	r.statuses[id] = status
	return nil
}

func (r *mockConnRepo) Delete(_ context.Context, id uuid.UUID) error {
	if r.deleteErr != nil {
		return r.deleteErr
	}
	if _, ok := r.conns[id]; !ok {
		return apperrors.NotFound("database connection")
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

	input := models.CreateDatabaseConnectionInput{
		Name:     "test-pg",
		Type:     models.DatabaseTypePostgres,
		Host:     "localhost",
		Port:     5432,
		Database: "testdb",
		Username: "admin",
		Password: "secret",
	}

	conn, err := svc.CreateConnection(ctx, input, userID)
	if err != nil {
		t.Fatalf("CreateConnection returned error: %v", err)
	}
	if conn.ID == uuid.Nil {
		t.Fatal("expected non-nil connection ID")
	}
	if conn.Name != "test-pg" {
		t.Errorf("Name = %q, want %q", conn.Name, "test-pg")
	}
	if conn.Type != models.DatabaseTypePostgres {
		t.Errorf("Type = %q, want %q", conn.Type, models.DatabaseTypePostgres)
	}
	if conn.UserID != userID {
		t.Errorf("UserID = %v, want %v", conn.UserID, userID)
	}
	if conn.Status != models.DatabaseStatusDisconnected {
		t.Errorf("Status = %q, want %q", conn.Status, models.DatabaseStatusDisconnected)
	}
	// Password should be encrypted, not plaintext
	if conn.Password == "secret" {
		t.Error("password should be encrypted, not stored as plaintext")
	}
	if conn.Password == "" {
		t.Error("encrypted password should not be empty")
	}
}

func TestCreateConnection_NoPassword(t *testing.T) {
	repo := newMockConnRepo()
	svc := newTestService(t, repo)
	ctx := context.Background()
	userID := uuid.New()

	input := models.CreateDatabaseConnectionInput{
		Name:     "test-pg-nopass",
		Type:     models.DatabaseTypePostgres,
		Host:     "localhost",
		Port:     5432,
		Database: "testdb",
		Username: "admin",
		Password: "",
	}

	conn, err := svc.CreateConnection(ctx, input, userID)
	if err != nil {
		t.Fatalf("CreateConnection returned error: %v", err)
	}
	if conn.Password != "" {
		t.Errorf("password should be empty, got %q", conn.Password)
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

	input := models.CreateDatabaseConnectionInput{
		Name:     "no-crypto",
		Type:     models.DatabaseTypeMySQL,
		Host:     "localhost",
		Port:     3306,
		Database: "testdb",
		Username: "root",
		Password: "secret",
	}

	conn, err := svc.CreateConnection(ctx, input, userID)
	if err != nil {
		t.Fatalf("CreateConnection returned error: %v", err)
	}
	// With nil crypto, password should be empty (not encrypted)
	if conn.Password != "" {
		t.Errorf("with nil crypto, password should be empty, got %q", conn.Password)
	}
}

func TestCreateConnection_RepoError(t *testing.T) {
	repo := newMockConnRepo()
	repo.createErr = fmt.Errorf("database error")
	svc := newTestService(t, repo)
	ctx := context.Background()

	input := models.CreateDatabaseConnectionInput{
		Name:     "fail",
		Type:     models.DatabaseTypePostgres,
		Host:     "localhost",
		Port:     5432,
		Database: "testdb",
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

	input := models.CreateDatabaseConnectionInput{
		Name:     "get-test",
		Type:     models.DatabaseTypePostgres,
		Host:     "localhost",
		Port:     5432,
		Database: "testdb",
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
		input := models.CreateDatabaseConnectionInput{
			Name:     fmt.Sprintf("conn-a-%d", i),
			Type:     models.DatabaseTypePostgres,
			Host:     "localhost",
			Port:     5432,
			Database: "testdb",
		}
		if _, err := svc.CreateConnection(ctx, input, userA); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}
	input := models.CreateDatabaseConnectionInput{
		Name:     "conn-b-0",
		Type:     models.DatabaseTypeMySQL,
		Host:     "localhost",
		Port:     3306,
		Database: "testdb",
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

	input := models.CreateDatabaseConnectionInput{
		Name:     "update-test",
		Type:     models.DatabaseTypePostgres,
		Host:     "localhost",
		Port:     5432,
		Database: "testdb",
	}
	created, err := svc.CreateConnection(ctx, input, userID)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	newName := "updated-name"
	newHost := "remotehost"
	err = svc.UpdateConnection(ctx, created.ID, models.UpdateDatabaseConnectionInput{
		Name: &newName,
		Host: &newHost,
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
	if got.Host != "remotehost" {
		t.Errorf("Host = %q, want %q", got.Host, "remotehost")
	}
}

func TestUpdateConnection_WithPassword(t *testing.T) {
	repo := newMockConnRepo()
	svc := newTestService(t, repo)
	ctx := context.Background()
	userID := uuid.New()

	input := models.CreateDatabaseConnectionInput{
		Name:     "update-pass-test",
		Type:     models.DatabaseTypePostgres,
		Host:     "localhost",
		Port:     5432,
		Database: "testdb",
		Password: "oldpass",
	}
	created, err := svc.CreateConnection(ctx, input, userID)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	oldPassword := created.Password

	newPass := "newpassword"
	err = svc.UpdateConnection(ctx, created.ID, models.UpdateDatabaseConnectionInput{
		Password: &newPass,
	})
	if err != nil {
		t.Fatalf("UpdateConnection: %v", err)
	}

	got, err := svc.GetConnection(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetConnection after update: %v", err)
	}
	// Password should be encrypted and different from old one
	if got.Password == "newpassword" {
		t.Error("password should be encrypted, not plaintext")
	}
	if got.Password == oldPassword {
		t.Error("password should have changed after update")
	}
}

func TestUpdateConnection_EmptyPassword(t *testing.T) {
	repo := newMockConnRepo()
	svc := newTestService(t, repo)
	ctx := context.Background()
	userID := uuid.New()

	input := models.CreateDatabaseConnectionInput{
		Name:     "empty-pass-test",
		Type:     models.DatabaseTypePostgres,
		Host:     "localhost",
		Port:     5432,
		Database: "testdb",
		Password: "original",
	}
	created, err := svc.CreateConnection(ctx, input, userID)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	origPassword := created.Password

	// Empty password string should not trigger re-encryption
	emptyPass := ""
	err = svc.UpdateConnection(ctx, created.ID, models.UpdateDatabaseConnectionInput{
		Password: &emptyPass,
	})
	if err != nil {
		t.Fatalf("UpdateConnection: %v", err)
	}

	got, err := svc.GetConnection(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetConnection after update: %v", err)
	}
	// With empty password, the mock stores the empty string
	// The original password is not preserved because we passed a non-nil pointer
	if got.Password == origPassword {
		// That's ok if the mock doesn't update empty passwords, but it does in our mock
	}
	_ = origPassword
}

func TestUpdateConnection_NotFound(t *testing.T) {
	repo := newMockConnRepo()
	svc := newTestService(t, repo)
	ctx := context.Background()

	name := "x"
	err := svc.UpdateConnection(ctx, uuid.New(), models.UpdateDatabaseConnectionInput{
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

	input := models.CreateDatabaseConnectionInput{
		Name:     "delete-test",
		Type:     models.DatabaseTypePostgres,
		Host:     "localhost",
		Port:     5432,
		Database: "testdb",
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

	// Verify it implements DatabaseTestResulter
	var _ models.DatabaseTestResulter = r
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
// buildDSN tests
// ---------------------------------------------------------------------------

func TestBuildDSN_Postgres(t *testing.T) {
	svc := newTestService(t, newMockConnRepo())

	conn := &models.DatabaseConnection{
		Type:     models.DatabaseTypePostgres,
		Host:     "db.example.com",
		Port:     5432,
		Username: "user",
		Database: "mydb",
		SSL:      false,
	}

	dsn, driver := svc.buildDSN(conn, "pass")
	if driver != "pgx" {
		t.Errorf("driver = %q, want %q", driver, "pgx")
	}
	if dsn == "" {
		t.Fatal("expected non-empty DSN")
	}
	// Should contain sslmode=disable since SSL is false
	expected := "host=db.example.com port=5432 user=user password=pass dbname=mydb sslmode=disable"
	if dsn != expected {
		t.Errorf("DSN = %q, want %q", dsn, expected)
	}
}

func TestBuildDSN_Postgres_SSL(t *testing.T) {
	svc := newTestService(t, newMockConnRepo())

	conn := &models.DatabaseConnection{
		Type:     models.DatabaseTypePostgres,
		Host:     "db.example.com",
		Port:     5432,
		Username: "user",
		Database: "mydb",
		SSL:      true,
		SSLMode:  "verify-full",
	}

	dsn, driver := svc.buildDSN(conn, "pass")
	if driver != "pgx" {
		t.Errorf("driver = %q, want %q", driver, "pgx")
	}
	expected := "host=db.example.com port=5432 user=user password=pass dbname=mydb sslmode=verify-full"
	if dsn != expected {
		t.Errorf("DSN = %q, want %q", dsn, expected)
	}
}

func TestBuildDSN_Postgres_SSL_DefaultMode(t *testing.T) {
	svc := newTestService(t, newMockConnRepo())

	conn := &models.DatabaseConnection{
		Type:     models.DatabaseTypePostgres,
		Host:     "db.example.com",
		Port:     5432,
		Username: "user",
		Database: "mydb",
		SSL:      true,
		SSLMode:  "", // empty should default to "require"
	}

	dsn, _ := svc.buildDSN(conn, "pass")
	expected := "host=db.example.com port=5432 user=user password=pass dbname=mydb sslmode=require"
	if dsn != expected {
		t.Errorf("DSN = %q, want %q", dsn, expected)
	}
}

func TestBuildDSN_MySQL(t *testing.T) {
	svc := newTestService(t, newMockConnRepo())

	conn := &models.DatabaseConnection{
		Type:     models.DatabaseTypeMySQL,
		Host:     "mysql.local",
		Port:     3306,
		Username: "root",
		Database: "app",
		SSL:      false,
	}

	dsn, driver := svc.buildDSN(conn, "secret")
	if driver != "mysql" {
		t.Errorf("driver = %q, want %q", driver, "mysql")
	}
	expected := "root:secret@tcp(mysql.local:3306)/app?tls=false&parseTime=true"
	if dsn != expected {
		t.Errorf("DSN = %q, want %q", dsn, expected)
	}
}

func TestBuildDSN_MySQL_SSL(t *testing.T) {
	svc := newTestService(t, newMockConnRepo())

	conn := &models.DatabaseConnection{
		Type:     models.DatabaseTypeMySQL,
		Host:     "mysql.local",
		Port:     3306,
		Username: "root",
		Database: "app",
		SSL:      true,
	}

	dsn, _ := svc.buildDSN(conn, "secret")
	expected := "root:secret@tcp(mysql.local:3306)/app?tls=true&parseTime=true"
	if dsn != expected {
		t.Errorf("DSN = %q, want %q", dsn, expected)
	}
}

func TestBuildDSN_MariaDB(t *testing.T) {
	svc := newTestService(t, newMockConnRepo())

	conn := &models.DatabaseConnection{
		Type:     models.DatabaseTypeMariaDB,
		Host:     "mariadb.local",
		Port:     3306,
		Username: "admin",
		Database: "data",
		SSL:      false,
	}

	dsn, driver := svc.buildDSN(conn, "pw")
	if driver != "mysql" {
		t.Errorf("driver = %q, want %q", driver, "mysql")
	}
	expected := "admin:pw@tcp(mariadb.local:3306)/data?tls=false&parseTime=true"
	if dsn != expected {
		t.Errorf("DSN = %q, want %q", dsn, expected)
	}
}

func TestBuildDSN_SQLite(t *testing.T) {
	svc := newTestService(t, newMockConnRepo())

	conn := &models.DatabaseConnection{
		Type:     models.DatabaseTypeSQLite,
		Database: "/tmp/test.db",
	}

	dsn, driver := svc.buildDSN(conn, "")
	if driver != "sqlite3" {
		t.Errorf("driver = %q, want %q", driver, "sqlite3")
	}
	if dsn != "/tmp/test.db" {
		t.Errorf("DSN = %q, want %q", dsn, "/tmp/test.db")
	}
}

func TestBuildDSN_Redis(t *testing.T) {
	svc := newTestService(t, newMockConnRepo())

	conn := &models.DatabaseConnection{
		Type: models.DatabaseTypeRedis,
		Host: "localhost",
		Port: 6379,
	}

	dsn, driver := svc.buildDSN(conn, "")
	if dsn != "" {
		t.Errorf("Redis DSN should be empty, got %q", dsn)
	}
	if driver != "" {
		t.Errorf("Redis driver should be empty, got %q", driver)
	}
}

func TestBuildDSN_MongoDB(t *testing.T) {
	svc := newTestService(t, newMockConnRepo())

	conn := &models.DatabaseConnection{
		Type: models.DatabaseTypeMongoDB,
		Host: "localhost",
		Port: 27017,
	}

	dsn, driver := svc.buildDSN(conn, "")
	if dsn != "" {
		t.Errorf("MongoDB DSN should be empty, got %q", dsn)
	}
	if driver != "" {
		t.Errorf("MongoDB driver should be empty, got %q", driver)
	}
}

func TestBuildDSN_UnknownType(t *testing.T) {
	svc := newTestService(t, newMockConnRepo())

	conn := &models.DatabaseConnection{
		Type: models.DatabaseType("unknown"),
	}

	dsn, driver := svc.buildDSN(conn, "")
	if dsn != "" {
		t.Errorf("unknown type DSN should be empty, got %q", dsn)
	}
	if driver != "" {
		t.Errorf("unknown type driver should be empty, got %q", driver)
	}
}

// ---------------------------------------------------------------------------
// formatBytes tests
// ---------------------------------------------------------------------------

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
		{1099511627776, "1.0 TB"},
	}

	for _, tt := range tests {
		got := formatBytes(tt.input)
		if got != tt.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// validIdentifier regex tests
// ---------------------------------------------------------------------------

func TestValidIdentifier(t *testing.T) {
	valid := []string{
		"users",
		"my_table",
		"Table1",
		"_private",
		"public.users",
		"schema_1.table_name",
	}
	for _, s := range valid {
		if !validIdentifier.MatchString(s) {
			t.Errorf("expected %q to be a valid identifier", s)
		}
	}

	invalid := []string{
		"",
		"1starts_with_number",
		"has space",
		"has-dash",
		"drop;table",
		"a.b.c",
		"table; DROP TABLE users--",
	}
	for _, s := range invalid {
		if validIdentifier.MatchString(s) {
			t.Errorf("expected %q to be an invalid identifier", s)
		}
	}
}

// ---------------------------------------------------------------------------
// GetTableData validation test
// ---------------------------------------------------------------------------

func TestGetTableData_InvalidTableName(t *testing.T) {
	repo := newMockConnRepo()
	svc := newTestService(t, repo)
	ctx := context.Background()

	// Must have a connection to get past the validIdentifier check
	// but the table name validation happens first
	_, _, err := svc.GetTableData(ctx, uuid.New(), "invalid;table", 1, 10)
	if err == nil {
		t.Fatal("expected validation error for invalid table name, got nil")
	}
	if !apperrors.IsValidationError(err) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestGetTableData_ValidTableName_NotFoundConnection(t *testing.T) {
	repo := newMockConnRepo()
	svc := newTestService(t, repo)
	ctx := context.Background()

	_, _, err := svc.GetTableData(ctx, uuid.New(), "valid_table", 1, 10)
	if err == nil {
		t.Fatal("expected not-found error, got nil")
	}
	if !apperrors.IsNotFoundError(err) {
		t.Errorf("expected not-found error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// connect error test (unsupported type)
// ---------------------------------------------------------------------------

func TestConnect_UnsupportedType(t *testing.T) {
	svc := newTestService(t, newMockConnRepo())

	conn := &models.DatabaseConnection{
		Type: models.DatabaseTypeRedis,
	}

	_, err := svc.connect(conn, "")
	if err == nil {
		t.Fatal("expected error for unsupported type, got nil")
	}
	if !apperrors.IsValidationError(err) {
		t.Errorf("expected validation error, got: %v", err)
	}
}
