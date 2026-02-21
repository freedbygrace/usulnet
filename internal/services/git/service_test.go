// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package git

import (
	"sync"
	"testing"

	"github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

func TestNewService(t *testing.T) {
	t.Run("all nil deps with nop logger", func(t *testing.T) {
		svc := NewService(nil, nil, nil, logger.Nop())
		if svc == nil {
			t.Fatal("expected non-nil service")
		}
		if svc.connRepo != nil {
			t.Error("expected nil connRepo")
		}
		if svc.repoRepo != nil {
			t.Error("expected nil repoRepo")
		}
		if svc.encryptor != nil {
			t.Error("expected nil encryptor")
		}
		if svc.logger == nil {
			t.Error("expected non-nil logger")
		}
		if svc.limitProvider != nil {
			t.Error("expected nil limitProvider initially")
		}
	})

	t.Run("nil logger defaults to nop", func(t *testing.T) {
		svc := NewService(nil, nil, nil, nil)
		if svc == nil {
			t.Fatal("expected non-nil service")
		}
		if svc.logger == nil {
			t.Error("expected non-nil logger even when nil is passed")
		}
	})
}

// mockLimitProvider implements license.LimitProvider for testing.
type mockLimitProvider struct {
	limits license.Limits
}

func (m *mockLimitProvider) GetLimits() license.Limits {
	return m.limits
}

func TestSetLimitProvider(t *testing.T) {
	svc := NewService(nil, nil, nil, logger.Nop())

	if svc.limitProvider != nil {
		t.Fatal("expected nil limitProvider before SetLimitProvider")
	}

	lp := &mockLimitProvider{limits: license.Limits{MaxGitConnections: 5}}
	svc.SetLimitProvider(lp)

	svc.limitMu.RLock()
	got := svc.limitProvider
	svc.limitMu.RUnlock()

	if got == nil {
		t.Fatal("expected non-nil limitProvider after SetLimitProvider")
	}
	if got.GetLimits().MaxGitConnections != 5 {
		t.Errorf("expected MaxGitConnections=5, got %d", got.GetLimits().MaxGitConnections)
	}
}

func TestSetLimitProvider_Overwrite(t *testing.T) {
	svc := NewService(nil, nil, nil, logger.Nop())

	lp1 := &mockLimitProvider{limits: license.Limits{MaxGitConnections: 3}}
	lp2 := &mockLimitProvider{limits: license.Limits{MaxGitConnections: 10}}

	svc.SetLimitProvider(lp1)
	svc.SetLimitProvider(lp2)

	svc.limitMu.RLock()
	got := svc.limitProvider
	svc.limitMu.RUnlock()

	if got.GetLimits().MaxGitConnections != 10 {
		t.Errorf("expected MaxGitConnections=10 after overwrite, got %d", got.GetLimits().MaxGitConnections)
	}
}

func TestSetLimitProvider_ConcurrentAccess(t *testing.T) {
	svc := NewService(nil, nil, nil, logger.Nop())

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			svc.SetLimitProvider(&mockLimitProvider{
				limits: license.Limits{MaxGitConnections: n},
			})
		}(i)
		go func() {
			defer wg.Done()
			svc.limitMu.RLock()
			_ = svc.limitProvider // just read, no panic
			svc.limitMu.RUnlock()
		}()
	}
	wg.Wait()
}

func TestStrPtr(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "empty string", input: ""},
		{name: "non-empty string", input: "hello"},
		{name: "string with spaces", input: "hello world"},
		{name: "unicode string", input: "日本語テスト"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ptr := strPtr(tc.input)
			if ptr == nil {
				t.Fatal("expected non-nil pointer")
			}
			if *ptr != tc.input {
				t.Errorf("expected %q, got %q", tc.input, *ptr)
			}
		})
	}
}

func TestStrPtr_UniquePointers(t *testing.T) {
	// Each call to strPtr should return a distinct pointer.
	p1 := strPtr("same")
	p2 := strPtr("same")
	if p1 == p2 {
		t.Error("expected distinct pointers for separate calls")
	}
	if *p1 != *p2 {
		t.Error("expected same value behind distinct pointers")
	}
}

func TestCreateConnectionInputStruct(t *testing.T) {
	// Verify CreateConnectionInput fields are accessible and properly typed.
	input := CreateConnectionInput{
		Name:         "test-conn",
		ProviderType: models.GitProviderGitHub,
		URL:          "https://api.github.com",
		APIToken:     "tok_123",
	}
	if input.Name != "test-conn" {
		t.Error("unexpected Name value")
	}
	if input.ProviderType != models.GitProviderGitHub {
		t.Error("unexpected ProviderType value")
	}
}

func TestTestResultStruct(t *testing.T) {
	result := TestResult{
		Success:  true,
		Username: "user",
		Version:  "1.2.3",
	}
	if !result.Success {
		t.Error("expected Success=true")
	}
	if result.Username != "user" {
		t.Error("unexpected Username")
	}
	if result.Version != "1.2.3" {
		t.Error("unexpected Version")
	}
	if result.Error != "" {
		t.Error("expected empty Error for successful result")
	}
}

func TestStatsStruct(t *testing.T) {
	stats := Stats{
		Connections:       5,
		ActiveConnections: 3,
		Repositories:      42,
		ByProvider: map[models.GitProviderType]int{
			models.GitProviderGitHub: 2,
			models.GitProviderGitLab: 1,
		},
	}
	if stats.Connections != 5 {
		t.Errorf("expected Connections=5, got %d", stats.Connections)
	}
	if stats.ActiveConnections != 3 {
		t.Errorf("expected ActiveConnections=3, got %d", stats.ActiveConnections)
	}
	if stats.Repositories != 42 {
		t.Errorf("expected Repositories=42, got %d", stats.Repositories)
	}
	if len(stats.ByProvider) != 2 {
		t.Errorf("expected 2 providers, got %d", len(stats.ByProvider))
	}
	if stats.ByProvider[models.GitProviderGitHub] != 2 {
		t.Error("unexpected GitHub count")
	}
}
