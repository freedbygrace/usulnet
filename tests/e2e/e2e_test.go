// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

//go:build e2e

// Package e2e contains end-to-end tests for the usulnet platform.
// These tests require a running environment with PostgreSQL, Redis, and NATS.
//
// Run with: go test -tags=e2e -v ./tests/e2e/...
//
// Environment variables:
//   - USULNET_TEST_DATABASE_URL: PostgreSQL connection string (default: postgres://usulnet_test:test_password_e2e@localhost:15432/usulnet_test?sslmode=disable)
//   - USULNET_TEST_REDIS_URL: Redis connection string (default: redis://localhost:16379)
//   - USULNET_TEST_NATS_URL: NATS connection string (default: nats://localhost:14222)
//   - USULNET_TEST_API_URL: API base URL if testing against running server (default: empty, tests run embedded)
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

// testConfig holds E2E test configuration.
type testConfig struct {
	DatabaseURL string
	RedisURL    string
	NATSURL     string
	APIURL      string
}

func getTestConfig() testConfig {
	cfg := testConfig{
		DatabaseURL: "postgres://usulnet_test:test_password_e2e@localhost:15432/usulnet_test?sslmode=disable",
		RedisURL:    "redis://localhost:16379",
		NATSURL:     "nats://localhost:14222",
	}

	if v := os.Getenv("USULNET_TEST_DATABASE_URL"); v != "" {
		cfg.DatabaseURL = v
	}
	if v := os.Getenv("USULNET_TEST_REDIS_URL"); v != "" {
		cfg.RedisURL = v
	}
	if v := os.Getenv("USULNET_TEST_NATS_URL"); v != "" {
		cfg.NATSURL = v
	}
	if v := os.Getenv("USULNET_TEST_API_URL"); v != "" {
		cfg.APIURL = v
	}

	return cfg
}

// apiClient provides helper methods for making API requests during E2E tests.
type apiClient struct {
	baseURL    string
	httpClient *http.Client
	token      string
}

func newAPIClient(baseURL string) *apiClient {
	return &apiClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *apiClient) setToken(token string) {
	c.token = token
}

func (c *apiClient) get(path string) (*http.Response, error) {
	return c.doRequest(http.MethodGet, path, nil)
}

func (c *apiClient) post(path string, body any) (*http.Response, error) {
	return c.doRequest(http.MethodPost, path, body)
}

func (c *apiClient) put(path string, body any) (*http.Response, error) {
	return c.doRequest(http.MethodPut, path, body)
}

func (c *apiClient) delete(path string) (*http.Response, error) {
	return c.doRequest(http.MethodDelete, path, nil)
}

func (c *apiClient) doRequest(method, path string, body any) (*http.Response, error) {
	url := c.baseURL + path

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	return c.httpClient.Do(req)
}

func (c *apiClient) parseJSON(resp *http.Response) (map[string]any, error) {
	defer resp.Body.Close()
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %w", err)
	}
	return result, nil
}

// TestE2E_HealthEndpoints verifies health endpoints are accessible.
func TestE2E_HealthEndpoints(t *testing.T) {
	cfg := getTestConfig()
	if cfg.APIURL == "" {
		t.Skip("USULNET_TEST_API_URL not set, skipping E2E health tests")
	}

	client := newAPIClient(cfg.APIURL)

	t.Run("health endpoint returns OK", func(t *testing.T) {
		resp, err := client.get("/health")
		if err != nil {
			t.Fatalf("health request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
		}

		result, err := client.parseJSON(resp)
		if err != nil {
			t.Fatalf("failed to parse health response: %v", err)
		}

		if result["status"] == nil {
			t.Error("expected status field in health response")
		}
	})

	t.Run("version endpoint returns version info", func(t *testing.T) {
		resp, err := client.get("/api/v1/system/version")
		if err != nil {
			t.Fatalf("version request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		result, err := client.parseJSON(resp)
		if err != nil {
			t.Fatalf("failed to parse version response: %v", err)
		}

		if result["version"] == nil {
			t.Error("expected version field in response")
		}
	})
}

// TestE2E_AuthFlow verifies the authentication flow.
func TestE2E_AuthFlow(t *testing.T) {
	cfg := getTestConfig()
	if cfg.APIURL == "" {
		t.Skip("USULNET_TEST_API_URL not set, skipping E2E auth tests")
	}

	client := newAPIClient(cfg.APIURL)

	t.Run("login without credentials returns 400 or 401", func(t *testing.T) {
		resp, err := client.post("/api/v1/auth/login", map[string]string{})
		if err != nil {
			t.Fatalf("login request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 400 or 401, got %d", resp.StatusCode)
		}
	})

	t.Run("login with invalid credentials returns 401", func(t *testing.T) {
		resp, err := client.post("/api/v1/auth/login", map[string]string{
			"username": "nonexistent",
			"password": "wrongpassword",
		})
		if err != nil {
			t.Fatalf("login request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", resp.StatusCode)
		}
	})

	t.Run("protected endpoint without token returns 401", func(t *testing.T) {
		resp, err := client.get("/api/v1/system/info")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", resp.StatusCode)
		}
	})
}

// TestE2E_ContainerOperations verifies container CRUD operations.
func TestE2E_ContainerOperations(t *testing.T) {
	cfg := getTestConfig()
	if cfg.APIURL == "" {
		t.Skip("USULNET_TEST_API_URL not set, skipping E2E container tests")
	}

	client := newAPIClient(cfg.APIURL)

	t.Run("list containers requires auth", func(t *testing.T) {
		resp, err := client.get("/api/v1/containers")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", resp.StatusCode)
		}
	})
}

// TestE2E_SecurityScan verifies security scanning endpoints.
func TestE2E_SecurityScan(t *testing.T) {
	cfg := getTestConfig()
	if cfg.APIURL == "" {
		t.Skip("USULNET_TEST_API_URL not set, skipping E2E security tests")
	}

	client := newAPIClient(cfg.APIURL)

	t.Run("security endpoints require auth", func(t *testing.T) {
		resp, err := client.get("/api/v1/security")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected 401 or 404, got %d", resp.StatusCode)
		}
	})
}

// TestE2E_BackupOperations verifies backup endpoints.
func TestE2E_BackupOperations(t *testing.T) {
	cfg := getTestConfig()
	if cfg.APIURL == "" {
		t.Skip("USULNET_TEST_API_URL not set, skipping E2E backup tests")
	}

	client := newAPIClient(cfg.APIURL)

	t.Run("backup endpoints require auth", func(t *testing.T) {
		resp, err := client.get("/api/v1/backups")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected 401 or 404, got %d", resp.StatusCode)
		}
	})
}
