// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package redis

import (
	"context"
	"fmt"
	"time"
)

const (
	// Cache key prefixes for inventory data
	inventoryPrefix       = "usulnet:inventory:"
	inventorySummaryKey   = inventoryPrefix + "summary"
	inventoryContainerKey = inventoryPrefix + "containers:"
	inventoryHostKey      = inventoryPrefix + "host:"

	// Default TTLs
	inventorySummaryTTL   = 30 * time.Second // Dashboard summary: short TTL, high hit rate
	inventoryContainerTTL = 15 * time.Second // Container lists: very short, frequently changing
	inventoryHostTTL      = 60 * time.Second // Per-host summary: slightly longer
)

// InventoryCache provides Redis-backed caching for inventory queries.
type InventoryCache struct {
	client *Client
}

// NewInventoryCache creates a new inventory cache.
func NewInventoryCache(client *Client) *InventoryCache {
	return &InventoryCache{client: client}
}

// GetOrSetSummary retrieves the inventory summary from cache, or computes it
// using the provided function and caches the result.
func (c *InventoryCache) GetOrSetSummary(ctx context.Context, dest interface{}, fn func() (interface{}, error)) error {
	return c.client.GetOrSetJSON(ctx, inventorySummaryKey, dest, inventorySummaryTTL, fn)
}

// InvalidateSummary removes the cached summary, forcing a refresh on next read.
func (c *InventoryCache) InvalidateSummary(ctx context.Context) error {
	return c.client.Delete(ctx, inventorySummaryKey)
}

// GetOrSetHostContainers retrieves cached container list for a host, or computes it.
func (c *InventoryCache) GetOrSetHostContainers(ctx context.Context, hostID string, dest interface{}, fn func() (interface{}, error)) error {
	key := fmt.Sprintf("%s%s", inventoryContainerKey, hostID)
	return c.client.GetOrSetJSON(ctx, key, dest, inventoryContainerTTL, fn)
}

// InvalidateHostContainers removes the cached container list for a host.
func (c *InventoryCache) InvalidateHostContainers(ctx context.Context, hostID string) error {
	key := fmt.Sprintf("%s%s", inventoryContainerKey, hostID)
	return c.client.Delete(ctx, key)
}

// GetOrSetHostSummary retrieves cached summary for a specific host.
func (c *InventoryCache) GetOrSetHostSummary(ctx context.Context, hostID string, dest interface{}, fn func() (interface{}, error)) error {
	key := fmt.Sprintf("%s%s", inventoryHostKey, hostID)
	return c.client.GetOrSetJSON(ctx, key, dest, inventoryHostTTL, fn)
}

// InvalidateHost removes all cached data for a specific host.
func (c *InventoryCache) InvalidateHost(ctx context.Context, hostID string) error {
	keys := []string{
		fmt.Sprintf("%s%s", inventoryContainerKey, hostID),
		fmt.Sprintf("%s%s", inventoryHostKey, hostID),
		inventorySummaryKey, // Also invalidate global summary
	}
	return c.client.Delete(ctx, keys...)
}

// InvalidateAll removes all inventory cache entries.
func (c *InventoryCache) InvalidateAll(ctx context.Context) error {
	// Use SCAN to find all inventory keys and delete them
	keys, err := c.client.Keys(ctx, inventoryPrefix+"*")
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return nil
	}
	return c.client.Delete(ctx, keys...)
}
