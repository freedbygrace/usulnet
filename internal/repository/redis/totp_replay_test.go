// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package redis

import (
	"context"
	"testing"
	"time"
)

func TestTOTPReplayStore_FirstUse(t *testing.T) {
	client := newTestClient(t)
	store := NewTOTPReplayStore(client)
	ctx := context.Background()

	replayed, err := store.MarkCodeUsed(ctx, "user-1", "123456")
	if err != nil {
		t.Fatalf("MarkCodeUsed: %v", err)
	}
	if replayed {
		t.Fatal("expected first use to not be a replay")
	}
}

func TestTOTPReplayStore_ReplayDetected(t *testing.T) {
	client := newTestClient(t)
	store := NewTOTPReplayStore(client)
	ctx := context.Background()

	// First use
	replayed, err := store.MarkCodeUsed(ctx, "user-1", "123456")
	if err != nil {
		t.Fatalf("MarkCodeUsed (first): %v", err)
	}
	if replayed {
		t.Fatal("expected first use to not be a replay")
	}

	// Second use of same code
	replayed, err = store.MarkCodeUsed(ctx, "user-1", "123456")
	if err != nil {
		t.Fatalf("MarkCodeUsed (second): %v", err)
	}
	if !replayed {
		t.Fatal("expected second use to be a replay")
	}
}

func TestTOTPReplayStore_DifferentCodes(t *testing.T) {
	client := newTestClient(t)
	store := NewTOTPReplayStore(client)
	ctx := context.Background()

	replayed, err := store.MarkCodeUsed(ctx, "user-1", "111111")
	if err != nil {
		t.Fatalf("MarkCodeUsed (code1): %v", err)
	}
	if replayed {
		t.Fatal("expected first code to not be a replay")
	}

	replayed, err = store.MarkCodeUsed(ctx, "user-1", "222222")
	if err != nil {
		t.Fatalf("MarkCodeUsed (code2): %v", err)
	}
	if replayed {
		t.Fatal("expected different code to not be a replay")
	}
}

func TestTOTPReplayStore_DifferentUsers(t *testing.T) {
	client := newTestClient(t)
	store := NewTOTPReplayStore(client)
	ctx := context.Background()

	// Same code, different users - should both succeed
	replayed, err := store.MarkCodeUsed(ctx, "user-1", "999999")
	if err != nil {
		t.Fatalf("MarkCodeUsed (user-1): %v", err)
	}
	if replayed {
		t.Fatal("expected user-1 first use to not be a replay")
	}

	replayed, err = store.MarkCodeUsed(ctx, "user-2", "999999")
	if err != nil {
		t.Fatalf("MarkCodeUsed (user-2): %v", err)
	}
	if replayed {
		t.Fatal("expected user-2 first use to not be a replay")
	}
}

func TestTOTPReplayStore_ExpiredCode(t *testing.T) {
	client, mr := newTestClientWithMR(t)
	store := NewTOTPReplayStore(client)
	ctx := context.Background()

	replayed, err := store.MarkCodeUsed(ctx, "user-1", "555555")
	if err != nil {
		t.Fatalf("MarkCodeUsed: %v", err)
	}
	if replayed {
		t.Fatal("expected first use to not be a replay")
	}

	// Fast-forward past the 90-second TTL
	mr.FastForward(2 * time.Minute)

	// Same code should be accepted again after expiry
	replayed, err = store.MarkCodeUsed(ctx, "user-1", "555555")
	if err != nil {
		t.Fatalf("MarkCodeUsed after expiry: %v", err)
	}
	if replayed {
		t.Fatal("expected code to be accepted after TTL expiry")
	}
}
