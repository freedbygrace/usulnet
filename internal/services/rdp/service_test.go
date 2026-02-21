// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package rdp

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ---------------------------------------------------------------------------
// Mock repository
// ---------------------------------------------------------------------------

type mockRepo struct {
	connections map[uuid.UUID]*models.RDPConnection
	createErr   error
	lastStatus  models.RDPConnectionStatus
	lastMessage string
}

func newMockRepo() *mockRepo {
	return &mockRepo{
		connections: make(map[uuid.UUID]*models.RDPConnection),
	}
}

func (m *mockRepo) Create(_ context.Context, conn *models.RDPConnection) error {
	if m.createErr != nil {
		return m.createErr
	}
	if conn.ID == uuid.Nil {
		conn.ID = uuid.New()
	}
	m.connections[conn.ID] = conn
	return nil
}

func (m *mockRepo) GetByID(_ context.Context, id uuid.UUID) (*models.RDPConnection, error) {
	c, ok := m.connections[id]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return c, nil
}

func (m *mockRepo) ListByUser(_ context.Context, userID uuid.UUID) ([]*models.RDPConnection, error) {
	var result []*models.RDPConnection
	for _, c := range m.connections {
		if c.UserID == userID {
			result = append(result, c)
		}
	}
	return result, nil
}

func (m *mockRepo) Update(_ context.Context, id uuid.UUID, input models.UpdateRDPConnectionInput) error {
	c, ok := m.connections[id]
	if !ok {
		return fmt.Errorf("not found")
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
	return nil
}

func (m *mockRepo) UpdateStatus(_ context.Context, id uuid.UUID, status models.RDPConnectionStatus, message string) error {
	m.lastStatus = status
	m.lastMessage = message
	if c, ok := m.connections[id]; ok {
		c.Status = status
		c.StatusMessage = message
	}
	return nil
}

func (m *mockRepo) Delete(_ context.Context, id uuid.UUID) error {
	delete(m.connections, id)
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func testService(repo *mockRepo) *Service {
	log, _ := logger.NewWithOutput("error", "console", io.Discard)
	return NewService(repo, nil, log) // nil crypto — passwords stored as-is
}

var testUserID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestCreateConnection_Defaults(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	got, err := svc.CreateConnection(context.Background(), models.CreateRDPConnectionInput{
		Name:     "My Server",
		Host:     "192.168.1.100",
		Username: "admin",
	}, testUserID)
	if err != nil {
		t.Fatalf("CreateConnection() error = %v", err)
	}
	if got.Name != "My Server" {
		t.Errorf("Name = %q, want %q", got.Name, "My Server")
	}
	if got.Port != 3389 {
		t.Errorf("Port = %d, want 3389 (default)", got.Port)
	}
	if got.Resolution != "1920x1080" {
		t.Errorf("Resolution = %q, want %q (default)", got.Resolution, "1920x1080")
	}
	if got.ColorDepth != "32" {
		t.Errorf("ColorDepth = %q, want %q (default)", got.ColorDepth, "32")
	}
	if got.Security != models.RDPSecurityAny {
		t.Errorf("Security = %q, want %q (default)", got.Security, models.RDPSecurityAny)
	}
	if got.UserID != testUserID {
		t.Errorf("UserID = %v, want %v", got.UserID, testUserID)
	}
}

func TestCreateConnection_CustomValues(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	got, err := svc.CreateConnection(context.Background(), models.CreateRDPConnectionInput{
		Name:       "Custom",
		Host:       "10.0.0.5",
		Port:       3390,
		Username:   "user1",
		Domain:     "CORP",
		Resolution: "1280x720",
		ColorDepth: "16",
		Security:   models.RDPSecurityNLA,
		Tags:       []string{"production", "windows"},
	}, testUserID)
	if err != nil {
		t.Fatalf("CreateConnection() error = %v", err)
	}
	if got.Port != 3390 {
		t.Errorf("Port = %d, want 3390", got.Port)
	}
	if got.Domain != "CORP" {
		t.Errorf("Domain = %q, want %q", got.Domain, "CORP")
	}
	if got.Security != models.RDPSecurityNLA {
		t.Errorf("Security = %q, want %q", got.Security, models.RDPSecurityNLA)
	}
	if len(got.Tags) != 2 {
		t.Errorf("Tags len = %d, want 2", len(got.Tags))
	}
}

func TestCreateConnection_NilCryptoNoPassword(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	got, err := svc.CreateConnection(context.Background(), models.CreateRDPConnectionInput{
		Name:     "NoPwd",
		Host:     "host",
		Password: "secret123",
	}, testUserID)
	if err != nil {
		t.Fatalf("CreateConnection() error = %v", err)
	}
	// With nil crypto, password is stored empty (crypto check short-circuits)
	if got.Password != "" {
		t.Errorf("Password should be empty with nil crypto, got %q", got.Password)
	}
}

func TestCreateConnection_RepoError(t *testing.T) {
	repo := newMockRepo()
	repo.createErr = fmt.Errorf("db error")
	svc := testService(repo)

	_, err := svc.CreateConnection(context.Background(), models.CreateRDPConnectionInput{
		Name: "fail",
		Host: "host",
	}, testUserID)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetConnection(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	created, _ := svc.CreateConnection(context.Background(), models.CreateRDPConnectionInput{
		Name: "Test",
		Host: "host",
	}, testUserID)

	got, err := svc.GetConnection(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("GetConnection() error = %v", err)
	}
	if got.Name != "Test" {
		t.Errorf("Name = %q, want %q", got.Name, "Test")
	}
}

func TestGetConnection_NotFound(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	_, err := svc.GetConnection(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected not found error")
	}
}

func TestListConnections(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)
	otherUser := uuid.New()

	svc.CreateConnection(context.Background(), models.CreateRDPConnectionInput{Name: "A", Host: "h1"}, testUserID)
	svc.CreateConnection(context.Background(), models.CreateRDPConnectionInput{Name: "B", Host: "h2"}, testUserID)
	svc.CreateConnection(context.Background(), models.CreateRDPConnectionInput{Name: "C", Host: "h3"}, otherUser)

	got, err := svc.ListConnections(context.Background(), testUserID)
	if err != nil {
		t.Fatalf("ListConnections() error = %v", err)
	}
	if len(got) != 2 {
		t.Errorf("len = %d, want 2 (filtered by user)", len(got))
	}
}

func TestUpdateConnection(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	created, _ := svc.CreateConnection(context.Background(), models.CreateRDPConnectionInput{
		Name: "Original",
		Host: "old-host",
	}, testUserID)

	newName := "Updated"
	newHost := "new-host"
	err := svc.UpdateConnection(context.Background(), created.ID, models.UpdateRDPConnectionInput{
		Name: &newName,
		Host: &newHost,
	})
	if err != nil {
		t.Fatalf("UpdateConnection() error = %v", err)
	}

	got := repo.connections[created.ID]
	if got.Name != "Updated" {
		t.Errorf("Name = %q, want %q", got.Name, "Updated")
	}
	if got.Host != "new-host" {
		t.Errorf("Host = %q, want %q", got.Host, "new-host")
	}
}

func TestDeleteConnection(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	created, _ := svc.CreateConnection(context.Background(), models.CreateRDPConnectionInput{
		Name: "ToDelete",
		Host: "host",
	}, testUserID)

	err := svc.DeleteConnection(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("DeleteConnection() error = %v", err)
	}
	if _, ok := repo.connections[created.ID]; ok {
		t.Error("connection should be deleted")
	}
}

func TestTestConnection_NotFound(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	ok, msg, _, err := svc.TestConnection(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected error for missing connection")
	}
	if ok {
		t.Error("should not be ok")
	}
	if msg != "Connection not found" {
		t.Errorf("msg = %q, want %q", msg, "Connection not found")
	}
}

func TestTestConnection_UnreachableHost(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	created, _ := svc.CreateConnection(context.Background(), models.CreateRDPConnectionInput{
		Name: "Unreachable",
		Host: "192.0.2.1", // RFC 5737 TEST-NET, guaranteed unreachable
		Port: 3389,
	}, testUserID)

	// Use a very short timeout context to avoid long waits
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	ok, _, _, _ := svc.TestConnection(ctx, created.ID)
	if ok {
		t.Error("should not succeed connecting to unreachable host")
	}
	// Verify status was updated to error
	if repo.lastStatus != models.RDPConnectionError {
		t.Errorf("status = %q, want %q", repo.lastStatus, models.RDPConnectionError)
	}
}
