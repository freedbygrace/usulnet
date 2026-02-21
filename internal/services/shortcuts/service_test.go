// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package shortcuts

import (
	"net/http"
	"testing"
	"time"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

func TestNewService(t *testing.T) {
	t.Run("all nil repos", func(t *testing.T) {
		svc := NewService(nil, nil, logger.Nop())
		if svc == nil {
			t.Fatal("expected non-nil service")
		}
		if svc.shortcutRepo != nil {
			t.Error("expected nil shortcutRepo")
		}
		if svc.categoryRepo != nil {
			t.Error("expected nil categoryRepo")
		}
		if svc.logger == nil {
			t.Error("expected non-nil logger")
		}
	})

	t.Run("http client initialized", func(t *testing.T) {
		svc := NewService(nil, nil, logger.Nop())
		if svc.httpClient == nil {
			t.Fatal("expected non-nil httpClient")
		}
	})

	t.Run("http client timeout", func(t *testing.T) {
		svc := NewService(nil, nil, logger.Nop())
		expected := 10 * time.Second
		if svc.httpClient.Timeout != expected {
			t.Errorf("expected httpClient timeout %v, got %v", expected, svc.httpClient.Timeout)
		}
	})
}

func TestServiceStructFields(t *testing.T) {
	log := logger.Nop()
	svc := NewService(nil, nil, log)

	if svc.shortcutRepo != nil {
		t.Error("expected nil shortcutRepo")
	}
	if svc.categoryRepo != nil {
		t.Error("expected nil categoryRepo")
	}
	if svc.logger == nil {
		t.Error("logger should not be nil")
	}
	if svc.httpClient == nil {
		t.Error("httpClient should not be nil")
	}
}

func TestServiceHTTPClientIsUsable(t *testing.T) {
	// Verify the httpClient created by NewService is a valid *http.Client
	// with the expected configuration.
	svc := NewService(nil, nil, logger.Nop())

	// The client should have no custom transport (uses default).
	if svc.httpClient.Transport != nil {
		t.Error("expected nil Transport (uses http.DefaultTransport)")
	}

	// The client should have no cookie jar.
	if svc.httpClient.Jar != nil {
		t.Error("expected nil Jar")
	}

	// The client should have no custom redirect policy.
	if svc.httpClient.CheckRedirect != nil {
		t.Error("expected nil CheckRedirect")
	}
}

func TestNewServiceMultipleInstances(t *testing.T) {
	// Each NewService call should produce independent instances.
	svc1 := NewService(nil, nil, logger.Nop())
	svc2 := NewService(nil, nil, logger.Nop())

	if svc1 == svc2 {
		t.Error("expected distinct service instances")
	}
	if svc1.httpClient == svc2.httpClient {
		t.Error("expected distinct httpClient instances")
	}
}

func TestHTTPClientTimeoutValue(t *testing.T) {
	// This test documents the hardcoded timeout value in the constructor.
	svc := NewService(nil, nil, logger.Nop())

	// 10 seconds is a reasonable timeout for favicon fetching.
	if svc.httpClient.Timeout != 10*time.Second {
		t.Errorf("timeout changed from expected 10s to %v — was this intentional?", svc.httpClient.Timeout)
	}
}

func TestHTTPClientType(t *testing.T) {
	svc := NewService(nil, nil, logger.Nop())

	// Verify httpClient is the concrete *http.Client type expected.
	var _ *http.Client = svc.httpClient
}
