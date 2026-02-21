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

func TestLock_AcquireRelease(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	lock := client.NewLock("test-resource", 10*time.Second)

	if err := lock.Acquire(ctx); err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	held, err := lock.IsHeld(ctx)
	if err != nil {
		t.Fatalf("IsHeld: %v", err)
	}
	if !held {
		t.Fatal("expected lock to be held")
	}

	if err := lock.Release(ctx); err != nil {
		t.Fatalf("Release: %v", err)
	}

	held, err = lock.IsHeld(ctx)
	if err != nil {
		t.Fatalf("IsHeld after release: %v", err)
	}
	if held {
		t.Fatal("expected lock to not be held after release")
	}
}

func TestLock_DoubleAcquireFails(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	lock1 := client.NewLock("shared-resource", 10*time.Second)
	lock2 := client.NewLock("shared-resource", 10*time.Second)

	if err := lock1.Acquire(ctx); err != nil {
		t.Fatalf("Acquire lock1: %v", err)
	}
	defer func() { _ = lock1.Release(ctx) }()

	err := lock2.Acquire(ctx)
	if !errors.Is(err, ErrLockNotAcquired) {
		t.Fatalf("expected ErrLockNotAcquired, got %v", err)
	}
}

func TestLock_ReleaseNotHeld(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	lock := client.NewLock("unacquired", 10*time.Second)

	err := lock.Release(ctx)
	if !errors.Is(err, ErrLockNotHeld) {
		t.Fatalf("expected ErrLockNotHeld, got %v", err)
	}
}

func TestLock_ReleaseBySomeoneElse(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	lock1 := client.NewLock("resource", 10*time.Second)
	lock2 := client.NewLock("resource", 10*time.Second)

	if err := lock1.Acquire(ctx); err != nil {
		t.Fatalf("Acquire lock1: %v", err)
	}

	// lock2 has a different value, so it should not be able to release lock1
	err := lock2.Release(ctx)
	if !errors.Is(err, ErrLockNotHeld) {
		t.Fatalf("expected ErrLockNotHeld when releasing someone else's lock, got %v", err)
	}

	// lock1 should still hold it
	held, err := lock1.IsHeld(ctx)
	if err != nil {
		t.Fatalf("IsHeld: %v", err)
	}
	if !held {
		t.Fatal("lock1 should still hold the lock")
	}
}

func TestLock_Extend(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	lock := client.NewLock("extendable", 5*time.Second)

	if err := lock.Acquire(ctx); err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	if err := lock.Extend(ctx, 30*time.Second); err != nil {
		t.Fatalf("Extend: %v", err)
	}

	if lock.TTL() != 30*time.Second {
		t.Fatalf("expected TTL 30s, got %v", lock.TTL())
	}

	held, err := lock.IsHeld(ctx)
	if err != nil {
		t.Fatalf("IsHeld: %v", err)
	}
	if !held {
		t.Fatal("expected lock to be held after extend")
	}
}

func TestLock_ExtendNotHeld(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	lock := client.NewLock("not-held", 5*time.Second)

	err := lock.Extend(ctx, 30*time.Second)
	if !errors.Is(err, ErrLockNotHeld) {
		t.Fatalf("expected ErrLockNotHeld, got %v", err)
	}
}

func TestLock_IsHeldNotAcquired(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	lock := client.NewLock("never-acquired", 10*time.Second)

	held, err := lock.IsHeld(ctx)
	if err != nil {
		t.Fatalf("IsHeld: %v", err)
	}
	if held {
		t.Fatal("expected lock to not be held")
	}
}

func TestLock_Key(t *testing.T) {
	client := newTestClient(t)
	lock := client.NewLock("my-resource", 10*time.Second)

	expected := "lock:my-resource"
	if lock.Key() != expected {
		t.Fatalf("expected key %q, got %q", expected, lock.Key())
	}
}

func TestLock_ExpiryViaMiniRedis(t *testing.T) {
	client, mr := newTestClientWithMR(t)
	ctx := context.Background()

	lock1 := client.NewLock("expiry-test", 2*time.Second)

	if err := lock1.Acquire(ctx); err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	// Fast-forward past TTL
	mr.FastForward(3 * time.Second)

	// Lock should have expired; another lock should be able to acquire
	lock2 := client.NewLock("expiry-test", 10*time.Second)
	if err := lock2.Acquire(ctx); err != nil {
		t.Fatalf("Acquire after expiry: %v", err)
	}
}

func TestLock_AcquireWithRetry(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	// Acquire first lock
	lock1 := client.NewLock("retry-resource", 100*time.Millisecond)
	if err := lock1.Acquire(ctx); err != nil {
		t.Fatalf("Acquire lock1: %v", err)
	}

	// Release it in the background after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = lock1.Release(context.Background())
	}()

	// lock2 should succeed after retry
	lock2 := client.NewLock("retry-resource", 10*time.Second)
	err := lock2.AcquireWithRetry(ctx, LockOptions{
		RetryCount: 5,
		RetryDelay: 30 * time.Millisecond,
		TTL:        10 * time.Second,
	})
	if err != nil {
		t.Fatalf("AcquireWithRetry: %v", err)
	}
}

func TestLock_AcquireWithRetry_AllFail(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	// Hold the lock for the entire retry window
	blocker := client.NewLock("blocked-resource", 10*time.Second)
	if err := blocker.Acquire(ctx); err != nil {
		t.Fatalf("Acquire blocker: %v", err)
	}
	defer func() { _ = blocker.Release(ctx) }()

	lock := client.NewLock("blocked-resource", 10*time.Second)
	err := lock.AcquireWithRetry(ctx, LockOptions{
		RetryCount: 2,
		RetryDelay: 10 * time.Millisecond,
		TTL:        10 * time.Second,
	})
	if !errors.Is(err, ErrLockNotAcquired) {
		t.Fatalf("expected ErrLockNotAcquired, got %v", err)
	}
}

func TestLock_AcquireWithRetry_ContextCanceled(t *testing.T) {
	client := newTestClient(t)
	ctx, cancel := context.WithCancel(context.Background())

	// Hold the lock
	blocker := client.NewLock("cancel-resource", 10*time.Second)
	if err := blocker.Acquire(ctx); err != nil {
		t.Fatalf("Acquire blocker: %v", err)
	}

	// Cancel after a short delay
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	lock := client.NewLock("cancel-resource", 10*time.Second)
	err := lock.AcquireWithRetry(ctx, LockOptions{
		RetryCount: 100,
		RetryDelay: 20 * time.Millisecond,
		TTL:        10 * time.Second,
	})
	if err == nil {
		t.Fatal("expected error from context cancellation")
	}
}

func TestWithLock(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	executed := false
	err := client.WithLock(ctx, "withlock-resource", 10*time.Second, func(ctx context.Context) error {
		executed = true
		return nil
	})
	if err != nil {
		t.Fatalf("WithLock: %v", err)
	}
	if !executed {
		t.Fatal("expected function to be executed")
	}
}

func TestWithLock_FnError(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	expectedErr := errors.New("deliberate error")
	err := client.WithLock(ctx, "withlock-error", 10*time.Second, func(ctx context.Context) error {
		return expectedErr
	})
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected deliberate error, got %v", err)
	}
}

func TestTryWithLock_Acquired(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	acquired, err := client.TryWithLock(ctx, "try-resource", 10*time.Second, func(ctx context.Context) error {
		return nil
	})
	if err != nil {
		t.Fatalf("TryWithLock: %v", err)
	}
	if !acquired {
		t.Fatal("expected lock to be acquired")
	}
}

func TestTryWithLock_NotAvailable(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	blocker := client.NewLock("try-blocked", 10*time.Second)
	if err := blocker.Acquire(ctx); err != nil {
		t.Fatalf("Acquire blocker: %v", err)
	}
	defer func() { _ = blocker.Release(ctx) }()

	acquired, err := client.TryWithLock(ctx, "try-blocked", 10*time.Second, func(ctx context.Context) error {
		t.Fatal("function should not be called")
		return nil
	})
	if err != nil {
		t.Fatalf("TryWithLock: %v", err)
	}
	if acquired {
		t.Fatal("expected lock to not be acquired")
	}
}

func TestSemaphore_AcquireRelease(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	sem := client.NewSemaphore("test-sem", 3, 10*time.Second)

	// Acquire 3 slots
	for i := 0; i < 3; i++ {
		s := client.NewSemaphore("test-sem", 3, 10*time.Second)
		if err := s.Acquire(ctx); err != nil {
			t.Fatalf("Acquire[%d]: %v", i, err)
		}
	}

	// 4th should fail
	s4 := client.NewSemaphore("test-sem", 3, 10*time.Second)
	err := s4.Acquire(ctx)
	if !errors.Is(err, ErrLockNotAcquired) {
		t.Fatalf("expected ErrLockNotAcquired on 4th acquire, got %v", err)
	}

	// Release one and try again
	if err := sem.Release(ctx); err != nil {
		t.Fatalf("Release: %v", err)
	}
}

func TestSemaphore_CountAndAvailable(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	sem := client.NewSemaphore("count-sem", 5, 10*time.Second)
	if err := sem.Acquire(ctx); err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	count, err := sem.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected count 1, got %d", count)
	}

	avail, err := sem.Available(ctx)
	if err != nil {
		t.Fatalf("Available: %v", err)
	}
	if avail != 4 {
		t.Fatalf("expected 4 available, got %d", avail)
	}
}

func TestLockKeyHelpers(t *testing.T) {
	tests := []struct {
		name     string
		fn       func(string) string
		input    string
		expected string
	}{
		{"LockKey", LockKey, "resource", "lock:resource"},
		{"ContainerLock", ContainerLock, "abc123", "container:abc123"},
		{"HostLock", HostLock, "host-1", "host:host-1"},
		{"UpdateLock", UpdateLock, "ctr-1", "update:ctr-1"},
		{"BackupLock", BackupLock, "ctr-2", "backup:ctr-2"},
		{"SecurityScanLock", SecurityScanLock, "ctr-3", "security_scan:ctr-3"},
		{"StackDeployLock", StackDeployLock, "stack-1", "stack_deploy:stack-1"},
		{"ConfigSyncLock", ConfigSyncLock, "cfg-1", "config_sync:cfg-1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.fn(tt.input)
			if got != tt.expected {
				t.Fatalf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}
