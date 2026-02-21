// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package redis

import (
	"context"
	"testing"
)

func TestClient_Ping(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	if err := client.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestClient_HealthCheck(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	if err := client.HealthCheck(ctx); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
}

func TestClient_DBSize(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	size, err := client.DBSize(ctx)
	if err != nil {
		t.Fatalf("DBSize: %v", err)
	}
	if size != 0 {
		t.Fatalf("expected 0 keys in fresh db, got %d", size)
	}

	// Add a key and check size again
	if err := client.Set(ctx, "test-key", "val", 0); err != nil {
		t.Fatalf("Set: %v", err)
	}

	size, err = client.DBSize(ctx)
	if err != nil {
		t.Fatalf("DBSize: %v", err)
	}
	if size != 1 {
		t.Fatalf("expected 1 key, got %d", size)
	}
}

func TestClient_FlushDB(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	if err := client.Set(ctx, "key1", "val", 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := client.Set(ctx, "key2", "val", 0); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if err := client.FlushDB(ctx); err != nil {
		t.Fatalf("FlushDB: %v", err)
	}

	size, err := client.DBSize(ctx)
	if err != nil {
		t.Fatalf("DBSize: %v", err)
	}
	if size != 0 {
		t.Fatalf("expected 0 keys after flush, got %d", size)
	}
}

func TestClient_Redis(t *testing.T) {
	client := newTestClient(t)

	rdb := client.Redis()
	if rdb == nil {
		t.Fatal("expected non-nil underlying redis.Client")
	}
}

func TestClient_PoolStats(t *testing.T) {
	client := newTestClient(t)

	stats := client.PoolStats()
	if stats == nil {
		t.Fatal("expected non-nil PoolStats")
	}
}

func TestClient_WithPrefix(t *testing.T) {
	client := newTestClient(t)

	key := client.WithPrefix("myprefix", "mykey")
	expected := "myprefix:mykey"
	if key != expected {
		t.Fatalf("expected %q, got %q", expected, key)
	}
}

func TestClient_SessionKey(t *testing.T) {
	client := newTestClient(t)

	key := client.SessionKey("sess-123")
	expected := "session:sess-123"
	if key != expected {
		t.Fatalf("expected %q, got %q", expected, key)
	}
}

func TestClient_UserSessionsKey(t *testing.T) {
	client := newTestClient(t)

	key := client.UserSessionsKey("user-42")
	expected := "user_sessions:user-42"
	if key != expected {
		t.Fatalf("expected %q, got %q", expected, key)
	}
}

func TestClient_CacheKey(t *testing.T) {
	client := newTestClient(t)

	key := client.CacheKey("images", "sha256:abc")
	expected := "cache:images:sha256:abc"
	if key != expected {
		t.Fatalf("expected %q, got %q", expected, key)
	}
}

func TestClient_LockKey(t *testing.T) {
	client := newTestClient(t)

	key := client.LockKey("my-resource")
	expected := "lock:my-resource"
	if key != expected {
		t.Fatalf("expected %q, got %q", expected, key)
	}
}

func TestClient_RateLimitKey(t *testing.T) {
	client := newTestClient(t)

	key := client.RateLimitKey("192.168.1.1")
	expected := "ratelimit:192.168.1.1"
	if key != expected {
		t.Fatalf("expected %q, got %q", expected, key)
	}
}
