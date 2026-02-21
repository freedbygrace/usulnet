// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package redis

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSessionCreate(t *testing.T) {
	client := newTestClient(t)
	store := NewSessionStore(client, 30*time.Minute)
	ctx := context.Background()

	session, err := store.Create(ctx, "user-1", "alice", "admin", "Mozilla/5.0", "192.168.1.1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if session.ID == "" {
		t.Fatal("expected non-empty session ID")
	}
	if session.UserID != "user-1" {
		t.Fatalf("expected UserID 'user-1', got %q", session.UserID)
	}
	if session.Username != "alice" {
		t.Fatalf("expected Username 'alice', got %q", session.Username)
	}
	if session.Role != "admin" {
		t.Fatalf("expected Role 'admin', got %q", session.Role)
	}
	if session.UserAgent != "Mozilla/5.0" {
		t.Fatalf("expected UserAgent 'Mozilla/5.0', got %q", session.UserAgent)
	}
	if session.IPAddress != "192.168.1.1" {
		t.Fatalf("expected IPAddress '192.168.1.1', got %q", session.IPAddress)
	}
	if session.CreatedAt.IsZero() {
		t.Fatal("expected non-zero CreatedAt")
	}
	if session.ExpiresAt.Before(session.CreatedAt) {
		t.Fatal("ExpiresAt should be after CreatedAt")
	}
	if session.Data == nil {
		t.Fatal("expected Data to be initialized")
	}
}

func TestSessionGet(t *testing.T) {
	client := newTestClient(t)
	store := NewSessionStore(client, 30*time.Minute)
	ctx := context.Background()

	created, err := store.Create(ctx, "user-1", "alice", "admin", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := store.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if got.ID != created.ID {
		t.Fatalf("expected ID %q, got %q", created.ID, got.ID)
	}
	if got.UserID != "user-1" {
		t.Fatalf("expected UserID 'user-1', got %q", got.UserID)
	}
}

func TestSessionGet_NotFound(t *testing.T) {
	client := newTestClient(t)
	store := NewSessionStore(client, 30*time.Minute)
	ctx := context.Background()

	_, err := store.Get(ctx, "nonexistent-session-id")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestSessionGet_Expired(t *testing.T) {
	client, mr := newTestClientWithMR(t)
	store := NewSessionStore(client, 1*time.Minute)
	ctx := context.Background()

	session, err := store.Create(ctx, "user-1", "alice", "admin", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Fast-forward past the session TTL
	mr.FastForward(2 * time.Minute)

	_, err = store.Get(ctx, session.ID)
	// miniredis evicts keys on FastForward, so we get NotFound rather than Expired
	if err == nil {
		t.Fatal("expected error for expired session")
	}
}

func TestSessionDelete(t *testing.T) {
	client := newTestClient(t)
	store := NewSessionStore(client, 30*time.Minute)
	ctx := context.Background()

	session, err := store.Create(ctx, "user-1", "alice", "admin", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := store.Delete(ctx, session.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = store.Get(ctx, session.ID)
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound after delete, got %v", err)
	}
}

func TestSessionDeleteAllForUser(t *testing.T) {
	client := newTestClient(t)
	store := NewSessionStore(client, 30*time.Minute)
	ctx := context.Background()

	userID := "user-multi"
	// Create three sessions for the same user
	s1, err := store.Create(ctx, userID, "alice", "admin", "UA1", "")
	if err != nil {
		t.Fatalf("Create s1: %v", err)
	}
	s2, err := store.Create(ctx, userID, "alice", "admin", "UA2", "")
	if err != nil {
		t.Fatalf("Create s2: %v", err)
	}
	s3, err := store.Create(ctx, userID, "alice", "admin", "UA3", "")
	if err != nil {
		t.Fatalf("Create s3: %v", err)
	}

	if err := store.DeleteAllForUser(ctx, userID); err != nil {
		t.Fatalf("DeleteAllForUser: %v", err)
	}

	for _, sid := range []string{s1.ID, s2.ID, s3.ID} {
		_, err := store.Get(ctx, sid)
		if !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("expected ErrSessionNotFound for session %s after DeleteAllForUser, got %v", sid, err)
		}
	}
}

func TestSessionDeleteAllForUser_Empty(t *testing.T) {
	client := newTestClient(t)
	store := NewSessionStore(client, 30*time.Minute)
	ctx := context.Background()

	// Deleting for a user with no sessions should not error
	if err := store.DeleteAllForUser(ctx, "no-sessions-user"); err != nil {
		t.Fatalf("DeleteAllForUser on empty: %v", err)
	}
}

func TestSessionDeleteAllForUserExcept(t *testing.T) {
	client := newTestClient(t)
	store := NewSessionStore(client, 30*time.Minute)
	ctx := context.Background()

	userID := "user-except"
	s1, err := store.Create(ctx, userID, "alice", "admin", "UA1", "")
	if err != nil {
		t.Fatalf("Create s1: %v", err)
	}
	s2, err := store.Create(ctx, userID, "alice", "admin", "UA2", "")
	if err != nil {
		t.Fatalf("Create s2: %v", err)
	}
	s3, err := store.Create(ctx, userID, "alice", "admin", "UA3", "")
	if err != nil {
		t.Fatalf("Create s3: %v", err)
	}

	// Keep s2, delete s1 and s3
	if err := store.DeleteAllForUserExcept(ctx, userID, s2.ID); err != nil {
		t.Fatalf("DeleteAllForUserExcept: %v", err)
	}

	// s2 should still exist
	got, err := store.Get(ctx, s2.ID)
	if err != nil {
		t.Fatalf("Get s2: %v", err)
	}
	if got.ID != s2.ID {
		t.Fatalf("expected session %s, got %s", s2.ID, got.ID)
	}

	// s1 and s3 should be gone
	for _, sid := range []string{s1.ID, s3.ID} {
		_, err := store.Get(ctx, sid)
		if !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("expected ErrSessionNotFound for %s, got %v", sid, err)
		}
	}
}

func TestSessionTouch(t *testing.T) {
	client := newTestClient(t)
	store := NewSessionStore(client, 30*time.Minute)
	ctx := context.Background()

	session, err := store.Create(ctx, "user-1", "alice", "admin", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	originalLastAccess := session.LastAccessAt

	// Small sleep to ensure time difference
	time.Sleep(5 * time.Millisecond)

	if err := store.Touch(ctx, session.ID); err != nil {
		t.Fatalf("Touch: %v", err)
	}

	got, err := store.Get(ctx, session.ID)
	if err != nil {
		t.Fatalf("Get after Touch: %v", err)
	}

	if !got.LastAccessAt.After(originalLastAccess) {
		t.Fatal("expected LastAccessAt to be updated after Touch")
	}
}

func TestSessionTouch_NotFound(t *testing.T) {
	client := newTestClient(t)
	store := NewSessionStore(client, 30*time.Minute)
	ctx := context.Background()

	err := store.Touch(ctx, "nonexistent")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestSessionSetData_GetData(t *testing.T) {
	client := newTestClient(t)
	store := NewSessionStore(client, 30*time.Minute)
	ctx := context.Background()

	session, err := store.Create(ctx, "user-1", "alice", "admin", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := store.SetData(ctx, session.ID, "theme", "dark"); err != nil {
		t.Fatalf("SetData: %v", err)
	}

	val, err := store.GetData(ctx, session.ID, "theme")
	if err != nil {
		t.Fatalf("GetData: %v", err)
	}
	// JSON round-trip yields string
	if val != "dark" {
		t.Fatalf("expected 'dark', got %v", val)
	}
}

func TestSessionGetData_MissingKey(t *testing.T) {
	client := newTestClient(t)
	store := NewSessionStore(client, 30*time.Minute)
	ctx := context.Background()

	session, err := store.Create(ctx, "user-1", "alice", "admin", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	val, err := store.GetData(ctx, session.ID, "nonexistent")
	if err != nil {
		t.Fatalf("GetData: %v", err)
	}
	if val != nil {
		t.Fatalf("expected nil for missing key, got %v", val)
	}
}

func TestSessionGetAllForUser(t *testing.T) {
	client := newTestClient(t)
	store := NewSessionStore(client, 30*time.Minute)
	ctx := context.Background()

	userID := "user-getall"
	_, err := store.Create(ctx, userID, "alice", "admin", "UA1", "")
	if err != nil {
		t.Fatalf("Create 1: %v", err)
	}
	_, err = store.Create(ctx, userID, "alice", "admin", "UA2", "")
	if err != nil {
		t.Fatalf("Create 2: %v", err)
	}

	sessions, err := store.GetAllForUser(ctx, userID)
	if err != nil {
		t.Fatalf("GetAllForUser: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}
}

func TestSessionGetAllForUser_Empty(t *testing.T) {
	client := newTestClient(t)
	store := NewSessionStore(client, 30*time.Minute)
	ctx := context.Background()

	sessions, err := store.GetAllForUser(ctx, "user-empty")
	if err != nil {
		t.Fatalf("GetAllForUser: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("expected 0 sessions, got %d", len(sessions))
	}
}

func TestSessionCountForUser(t *testing.T) {
	client := newTestClient(t)
	store := NewSessionStore(client, 30*time.Minute)
	ctx := context.Background()

	userID := "user-count"
	for i := 0; i < 3; i++ {
		_, err := store.Create(ctx, userID, "alice", "admin", "", "")
		if err != nil {
			t.Fatalf("Create[%d]: %v", i, err)
		}
	}

	count, err := store.CountForUser(ctx, userID)
	if err != nil {
		t.Fatalf("CountForUser: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected count 3, got %d", count)
	}
}

func TestSessionExists(t *testing.T) {
	client := newTestClient(t)
	store := NewSessionStore(client, 30*time.Minute)
	ctx := context.Background()

	session, err := store.Create(ctx, "user-1", "alice", "admin", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	exists, err := store.Exists(ctx, session.ID)
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !exists {
		t.Fatal("expected session to exist")
	}
}

func TestSessionExists_NotFound(t *testing.T) {
	client := newTestClient(t)
	store := NewSessionStore(client, 30*time.Minute)
	ctx := context.Background()

	exists, err := store.Exists(ctx, "no-such-session")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if exists {
		t.Fatal("expected session to not exist")
	}
}

func TestSessionUpdate(t *testing.T) {
	client := newTestClient(t)
	store := NewSessionStore(client, 30*time.Minute)
	ctx := context.Background()

	session, err := store.Create(ctx, "user-1", "alice", "admin", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	err = store.Update(ctx, session.ID, func(s *Session) {
		s.Role = "operator"
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := store.Get(ctx, session.ID)
	if err != nil {
		t.Fatalf("Get after Update: %v", err)
	}
	if got.Role != "operator" {
		t.Fatalf("expected role 'operator', got %q", got.Role)
	}
}

func TestSessionUpdate_NotFound(t *testing.T) {
	client := newTestClient(t)
	store := NewSessionStore(client, 30*time.Minute)
	ctx := context.Background()

	err := store.Update(ctx, "nonexistent", func(s *Session) {
		s.Role = "admin"
	})
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}
