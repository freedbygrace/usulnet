// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package redis

import (
	"context"
	"fmt"
	"time"
)

// TOTPReplayStore prevents TOTP code reuse within a time window using Redis.
// Each code is recorded with SetNX; if the key already exists the code was already
// consumed and must be rejected.
type TOTPReplayStore struct {
	client *Client
}

// NewTOTPReplayStore creates a new TOTP replay prevention store.
func NewTOTPReplayStore(client *Client) *TOTPReplayStore {
	return &TOTPReplayStore{client: client}
}

// MarkCodeUsed atomically checks whether a TOTP code was already used for the
// given user and, if not, marks it as used. The key expires after 90 seconds —
// enough to cover the ±1 skew window (3 periods × 30 s).
//
// Returns (true, nil) if the code was already consumed (replay).
// Returns (false, nil) if this is the first use and the code was recorded.
func (s *TOTPReplayStore) MarkCodeUsed(ctx context.Context, userID, code string) (bool, error) {
	key := fmt.Sprintf("totp:used:%s:%s", userID, code)
	// SetNX returns true when the key was newly set (first use).
	ok, err := s.client.rdb.SetNX(ctx, key, "1", 90*time.Second).Result()
	if err != nil {
		return false, fmt.Errorf("totp replay check: %w", err)
	}
	// ok == true  → key was set → first use → not a replay
	// ok == false → key existed → replay
	return !ok, nil
}
