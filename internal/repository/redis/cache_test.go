// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package redis

import (
	"context"
	"testing"
	"time"
)

func TestCache_SetGet(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	if err := client.Set(ctx, "key1", "value1", 5*time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	val, err := client.Get(ctx, "key1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if val != "value1" {
		t.Fatalf("expected 'value1', got %q", val)
	}
}

func TestCache_SetNX(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	// First call: key doesn't exist, should succeed
	ok, err := client.SetNX(ctx, "nx-key", "first", 5*time.Minute)
	if err != nil {
		t.Fatalf("SetNX: %v", err)
	}
	if !ok {
		t.Fatal("expected SetNX to succeed on first call")
	}

	// Second call: key exists, should fail
	ok, err = client.SetNX(ctx, "nx-key", "second", 5*time.Minute)
	if err != nil {
		t.Fatalf("SetNX: %v", err)
	}
	if ok {
		t.Fatal("expected SetNX to fail on second call")
	}

	// Verify original value persists
	val, err := client.Get(ctx, "nx-key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if val != "first" {
		t.Fatalf("expected 'first', got %q", val)
	}
}

func TestCache_SetXX(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	// Should fail: key doesn't exist
	ok, err := client.SetXX(ctx, "xx-key", "val", 5*time.Minute)
	if err != nil {
		t.Fatalf("SetXX: %v", err)
	}
	if ok {
		t.Fatal("expected SetXX to fail when key doesn't exist")
	}

	// Create the key
	if err := client.Set(ctx, "xx-key", "original", 5*time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Should succeed: key exists
	ok, err = client.SetXX(ctx, "xx-key", "updated", 5*time.Minute)
	if err != nil {
		t.Fatalf("SetXX: %v", err)
	}
	if !ok {
		t.Fatal("expected SetXX to succeed when key exists")
	}
}

func TestCache_Delete(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	if err := client.Set(ctx, "del-key", "val", 5*time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if err := client.Delete(ctx, "del-key"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	exists, err := client.Exists(ctx, "del-key")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if exists {
		t.Fatal("expected key to not exist after delete")
	}
}

func TestCache_Exists(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	exists, err := client.Exists(ctx, "missing-key")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if exists {
		t.Fatal("expected non-existent key to return false")
	}

	if err := client.Set(ctx, "present-key", "val", 5*time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	exists, err = client.Exists(ctx, "present-key")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !exists {
		t.Fatal("expected existing key to return true")
	}
}

func TestCache_Expire_TTL(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	if err := client.Set(ctx, "ttl-key", "val", 0); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if err := client.Expire(ctx, "ttl-key", 10*time.Minute); err != nil {
		t.Fatalf("Expire: %v", err)
	}

	ttl, err := client.TTL(ctx, "ttl-key")
	if err != nil {
		t.Fatalf("TTL: %v", err)
	}
	if ttl <= 0 {
		t.Fatalf("expected positive TTL, got %v", ttl)
	}
}

func TestCache_SetJSON_GetJSON(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	type testStruct struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}

	original := testStruct{Name: "test", Count: 42}
	if err := client.SetJSON(ctx, "json-key", original, 5*time.Minute); err != nil {
		t.Fatalf("SetJSON: %v", err)
	}

	var result testStruct
	if err := client.GetJSON(ctx, "json-key", &result); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}

	if result.Name != "test" || result.Count != 42 {
		t.Fatalf("expected {test, 42}, got {%s, %d}", result.Name, result.Count)
	}
}

func TestCache_GetOrSet(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	calls := 0
	fn := func() (interface{}, error) {
		calls++
		return "computed-value", nil
	}

	// First call: should compute
	val, err := client.GetOrSet(ctx, "getorset-key", 5*time.Minute, fn)
	if err != nil {
		t.Fatalf("GetOrSet (first): %v", err)
	}
	if val != "computed-value" {
		t.Fatalf("expected 'computed-value', got %q", val)
	}
	if calls != 1 {
		t.Fatalf("expected fn called 1 time, got %d", calls)
	}

	// Second call: should use cache
	val, err = client.GetOrSet(ctx, "getorset-key", 5*time.Minute, fn)
	if err != nil {
		t.Fatalf("GetOrSet (second): %v", err)
	}
	if val != "computed-value" {
		t.Fatalf("expected 'computed-value', got %q", val)
	}
	if calls != 1 {
		t.Fatalf("expected fn called 1 time (cached), got %d", calls)
	}
}

func TestCache_GetOrSetJSON(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	type data struct {
		Value string `json:"value"`
	}

	calls := 0
	fn := func() (interface{}, error) {
		calls++
		return data{Value: "hello"}, nil
	}

	var result data
	if err := client.GetOrSetJSON(ctx, "getorsetjson-key", &result, 5*time.Minute, fn); err != nil {
		t.Fatalf("GetOrSetJSON: %v", err)
	}
	if result.Value != "hello" {
		t.Fatalf("expected 'hello', got %q", result.Value)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call, got %d", calls)
	}

	// Second call: cached
	var result2 data
	if err := client.GetOrSetJSON(ctx, "getorsetjson-key", &result2, 5*time.Minute, fn); err != nil {
		t.Fatalf("GetOrSetJSON (cached): %v", err)
	}
	if result2.Value != "hello" {
		t.Fatalf("expected 'hello' from cache, got %q", result2.Value)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call (cached), got %d", calls)
	}
}

func TestCache_IncrDecr(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	val, err := client.Incr(ctx, "counter")
	if err != nil {
		t.Fatalf("Incr: %v", err)
	}
	if val != 1 {
		t.Fatalf("expected 1, got %d", val)
	}

	val, err = client.IncrBy(ctx, "counter", 5)
	if err != nil {
		t.Fatalf("IncrBy: %v", err)
	}
	if val != 6 {
		t.Fatalf("expected 6, got %d", val)
	}

	val, err = client.Decr(ctx, "counter")
	if err != nil {
		t.Fatalf("Decr: %v", err)
	}
	if val != 5 {
		t.Fatalf("expected 5, got %d", val)
	}

	val, err = client.DecrBy(ctx, "counter", 3)
	if err != nil {
		t.Fatalf("DecrBy: %v", err)
	}
	if val != 2 {
		t.Fatalf("expected 2, got %d", val)
	}
}

func TestCache_HashOperations(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	// HSet
	if err := client.HSet(ctx, "hash-key", "field1", "val1", "field2", "val2"); err != nil {
		t.Fatalf("HSet: %v", err)
	}

	// HGet
	val, err := client.HGet(ctx, "hash-key", "field1")
	if err != nil {
		t.Fatalf("HGet: %v", err)
	}
	if val != "val1" {
		t.Fatalf("expected 'val1', got %q", val)
	}

	// HExists
	exists, err := client.HExists(ctx, "hash-key", "field1")
	if err != nil {
		t.Fatalf("HExists: %v", err)
	}
	if !exists {
		t.Fatal("expected field1 to exist")
	}

	// HGetAll
	all, err := client.HGetAll(ctx, "hash-key")
	if err != nil {
		t.Fatalf("HGetAll: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(all))
	}

	// HDel
	if err := client.HDel(ctx, "hash-key", "field1"); err != nil {
		t.Fatalf("HDel: %v", err)
	}
	exists, err = client.HExists(ctx, "hash-key", "field1")
	if err != nil {
		t.Fatalf("HExists after delete: %v", err)
	}
	if exists {
		t.Fatal("expected field1 to not exist after delete")
	}

	// HIncrBy
	result, err := client.HIncrBy(ctx, "hash-key", "counter", 10)
	if err != nil {
		t.Fatalf("HIncrBy: %v", err)
	}
	if result != 10 {
		t.Fatalf("expected 10, got %d", result)
	}
}

func TestCache_SetOperations(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	if err := client.SAdd(ctx, "set-key", "a", "b", "c"); err != nil {
		t.Fatalf("SAdd: %v", err)
	}

	isMember, err := client.SIsMember(ctx, "set-key", "b")
	if err != nil {
		t.Fatalf("SIsMember: %v", err)
	}
	if !isMember {
		t.Fatal("expected 'b' to be a member")
	}

	card, err := client.SCard(ctx, "set-key")
	if err != nil {
		t.Fatalf("SCard: %v", err)
	}
	if card != 3 {
		t.Fatalf("expected cardinality 3, got %d", card)
	}

	members, err := client.SMembers(ctx, "set-key")
	if err != nil {
		t.Fatalf("SMembers: %v", err)
	}
	if len(members) != 3 {
		t.Fatalf("expected 3 members, got %d", len(members))
	}

	if err := client.SRem(ctx, "set-key", "b"); err != nil {
		t.Fatalf("SRem: %v", err)
	}

	isMember, err = client.SIsMember(ctx, "set-key", "b")
	if err != nil {
		t.Fatalf("SIsMember after remove: %v", err)
	}
	if isMember {
		t.Fatal("expected 'b' to not be a member after remove")
	}
}

func TestCache_ListOperations(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	if err := client.RPush(ctx, "list-key", "a", "b", "c"); err != nil {
		t.Fatalf("RPush: %v", err)
	}

	length, err := client.LLen(ctx, "list-key")
	if err != nil {
		t.Fatalf("LLen: %v", err)
	}
	if length != 3 {
		t.Fatalf("expected length 3, got %d", length)
	}

	items, err := client.LRange(ctx, "list-key", 0, -1)
	if err != nil {
		t.Fatalf("LRange: %v", err)
	}
	if len(items) != 3 || items[0] != "a" || items[1] != "b" || items[2] != "c" {
		t.Fatalf("expected [a b c], got %v", items)
	}

	val, err := client.LPop(ctx, "list-key")
	if err != nil {
		t.Fatalf("LPop: %v", err)
	}
	if val != "a" {
		t.Fatalf("expected 'a', got %q", val)
	}

	val, err = client.RPop(ctx, "list-key")
	if err != nil {
		t.Fatalf("RPop: %v", err)
	}
	if val != "c" {
		t.Fatalf("expected 'c', got %q", val)
	}

	// LPush
	if err := client.LPush(ctx, "list-key", "x"); err != nil {
		t.Fatalf("LPush: %v", err)
	}

	items, err = client.LRange(ctx, "list-key", 0, -1)
	if err != nil {
		t.Fatalf("LRange: %v", err)
	}
	if len(items) != 2 || items[0] != "x" || items[1] != "b" {
		t.Fatalf("expected [x b], got %v", items)
	}

	// LTrim
	if err := client.LTrim(ctx, "list-key", 0, 0); err != nil {
		t.Fatalf("LTrim: %v", err)
	}
	length, err = client.LLen(ctx, "list-key")
	if err != nil {
		t.Fatalf("LLen after trim: %v", err)
	}
	if length != 1 {
		t.Fatalf("expected length 1 after trim, got %d", length)
	}
}

func TestCache_MGet_MSet(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	if err := client.MSet(ctx, "mk1", "v1", "mk2", "v2", "mk3", "v3"); err != nil {
		t.Fatalf("MSet: %v", err)
	}

	vals, err := client.MGet(ctx, "mk1", "mk2", "mk3")
	if err != nil {
		t.Fatalf("MGet: %v", err)
	}
	if len(vals) != 3 {
		t.Fatalf("expected 3 values, got %d", len(vals))
	}
	if vals[0] != "v1" || vals[1] != "v2" || vals[2] != "v3" {
		t.Fatalf("unexpected values: %v", vals)
	}
}

func TestCache_Keys(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	if err := client.Set(ctx, "prefix:a", "1", 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := client.Set(ctx, "prefix:b", "2", 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := client.Set(ctx, "other:c", "3", 0); err != nil {
		t.Fatalf("Set: %v", err)
	}

	keys, err := client.Keys(ctx, "prefix:*")
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys matching prefix:*, got %d", len(keys))
	}
}
