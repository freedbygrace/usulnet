// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers_test

import (
	"net/http"
	"testing"
)

type coreAPIContract struct {
	module string

	happyMethod string
	happyPath   string
	happyRole   string

	unauthMethod string
	unauthPath   string

	forbiddenMethod string
	forbiddenPath   string

	badRequestMethod string
	badRequestPath   string
}

var coreAPIContracts = []coreAPIContract{
	{
		module: "container",

		happyMethod: http.MethodGet,
		happyPath:   "/api/v1/containers/550e8400-e29b-41d4-a716-446655440000",
		happyRole:   "viewer",

		unauthMethod: http.MethodGet,
		unauthPath:   "/api/v1/containers/550e8400-e29b-41d4-a716-446655440000",

		forbiddenMethod: http.MethodPost,
		forbiddenPath:   "/api/v1/containers/550e8400-e29b-41d4-a716-446655440000/nginx/start",

		badRequestMethod: http.MethodGet,
		badRequestPath:   "/api/v1/containers/not-a-uuid",
	},
	{
		module: "image",

		happyMethod: http.MethodGet,
		happyPath:   "/api/v1/images/550e8400-e29b-41d4-a716-446655440000",
		happyRole:   "viewer",

		unauthMethod: http.MethodGet,
		unauthPath:   "/api/v1/images/550e8400-e29b-41d4-a716-446655440000",

		forbiddenMethod: http.MethodPost,
		forbiddenPath:   "/api/v1/images/550e8400-e29b-41d4-a716-446655440000/pull",

		badRequestMethod: http.MethodGet,
		badRequestPath:   "/api/v1/images/not-a-uuid",
	},
	{
		module: "network",

		happyMethod: http.MethodGet,
		happyPath:   "/api/v1/networks/550e8400-e29b-41d4-a716-446655440000",
		happyRole:   "viewer",

		unauthMethod: http.MethodGet,
		unauthPath:   "/api/v1/networks/550e8400-e29b-41d4-a716-446655440000",

		forbiddenMethod: http.MethodPost,
		forbiddenPath:   "/api/v1/networks/550e8400-e29b-41d4-a716-446655440000",

		badRequestMethod: http.MethodGet,
		badRequestPath:   "/api/v1/networks/not-a-uuid",
	},
	{
		module: "volume",

		happyMethod: http.MethodGet,
		happyPath:   "/api/v1/volumes/550e8400-e29b-41d4-a716-446655440000",
		happyRole:   "viewer",

		unauthMethod: http.MethodGet,
		unauthPath:   "/api/v1/volumes/550e8400-e29b-41d4-a716-446655440000",

		forbiddenMethod: http.MethodPost,
		forbiddenPath:   "/api/v1/volumes/550e8400-e29b-41d4-a716-446655440000",

		badRequestMethod: http.MethodGet,
		badRequestPath:   "/api/v1/volumes/not-a-uuid",
	},
	{
		module: "stack",

		happyMethod: http.MethodGet,
		happyPath:   "/api/v1/stacks",
		happyRole:   "viewer",

		unauthMethod: http.MethodGet,
		unauthPath:   "/api/v1/stacks",

		forbiddenMethod: http.MethodPost,
		forbiddenPath:   "/api/v1/stacks",

		badRequestMethod: http.MethodGet,
		badRequestPath:   "/api/v1/stacks/not-a-uuid",
	},
	{
		module: "proxy",

		happyMethod: http.MethodGet,
		happyPath:   "/api/v1/proxy/hosts",
		happyRole:   "viewer",

		unauthMethod: http.MethodGet,
		unauthPath:   "/api/v1/proxy/hosts",

		forbiddenMethod: http.MethodPost,
		forbiddenPath:   "/api/v1/proxy/sync",

		badRequestMethod: http.MethodGet,
		badRequestPath:   "/api/v1/proxy/hosts/not-a-uuid",
	},
	{
		module: "backup",

		happyMethod: http.MethodGet,
		happyPath:   "/api/v1/backups",
		happyRole:   "viewer",

		unauthMethod: http.MethodGet,
		unauthPath:   "/api/v1/backups",

		forbiddenMethod: http.MethodPost,
		forbiddenPath:   "/api/v1/backups/550e8400-e29b-41d4-a716-446655440000/restore",

		badRequestMethod: http.MethodGet,
		badRequestPath:   "/api/v1/backups/not-a-uuid",
	},
}

func TestCoreAPIContractMatrix_IsComplete(t *testing.T) {
	if len(coreAPIContracts) != 7 {
		t.Fatalf("expected 7 core module contracts, got %d", len(coreAPIContracts))
	}

	for _, c := range coreAPIContracts {
		if c.module == "" ||
			c.happyMethod == "" || c.happyPath == "" || c.happyRole == "" ||
			c.unauthMethod == "" || c.unauthPath == "" ||
			c.forbiddenMethod == "" || c.forbiddenPath == "" ||
			c.badRequestMethod == "" || c.badRequestPath == "" {
			t.Fatalf("incomplete contract entry for module %q", c.module)
		}
	}
}

func TestCoreAPIContractMatrix_HTTPStatusConsistency(t *testing.T) {
	ts := setupTestSuite(t)
	viewerToken := generateTestToken(t, testUser(), "viewer", "viewer")

	for _, c := range coreAPIContracts {
		t.Run(c.module+"_unauthorized_returns_401", func(t *testing.T) {
			w := doRequest(t, ts.router, c.unauthMethod, c.unauthPath, "", "")
			assertStatus(t, w, http.StatusUnauthorized)
		})

		t.Run(c.module+"_forbidden_returns_403", func(t *testing.T) {
			w := doRequest(t, ts.router, c.forbiddenMethod, c.forbiddenPath, "{}", viewerToken)
			assertStatus(t, w, http.StatusForbidden)
		})
	}
}

func TestCoreAPIContractMatrix_ErrorPayloadConsistency(t *testing.T) {
	ts := setupTestSuite(t)
	viewerToken := generateTestToken(t, testUser(), "viewer", "viewer")

	for _, c := range coreAPIContracts {
		t.Run(c.module+"_invalid_input_returns_consistent_payload", func(t *testing.T) {
			w := doRequest(t, ts.router, c.badRequestMethod, c.badRequestPath, "", viewerToken)
			assertStatus(t, w, http.StatusBadRequest)
			assertErrorCode(t, w, "INVALID_INPUT")
		})
	}
}
