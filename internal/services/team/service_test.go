// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package team

import (
	"sync"
	"testing"

	"github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// mockLimitProvider implements license.LimitProvider for testing.
type mockLimitProvider struct {
	limits license.Limits
}

func (m *mockLimitProvider) GetLimits() license.Limits {
	return m.limits
}

func TestNewService(t *testing.T) {
	t.Run("all nil repos with nop logger", func(t *testing.T) {
		svc := NewService(nil, nil, Config{}, logger.Nop())
		if svc == nil {
			t.Fatal("expected non-nil service")
		}
		if svc.teamRepo != nil {
			t.Error("expected nil teamRepo")
		}
		if svc.permRepo != nil {
			t.Error("expected nil permRepo")
		}
		if svc.logger == nil {
			t.Error("expected non-nil logger")
		}
		if svc.limitProvider != nil {
			t.Error("expected nil limitProvider initially")
		}
	})

	t.Run("nil logger defaults to nop", func(t *testing.T) {
		svc := NewService(nil, nil, Config{}, nil)
		if svc == nil {
			t.Fatal("expected non-nil service")
		}
		if svc.logger == nil {
			t.Error("expected non-nil logger even when nil is passed")
		}
	})

	t.Run("config is stored", func(t *testing.T) {
		cfg := Config{MaxTeams: 10}
		svc := NewService(nil, nil, cfg, logger.Nop())
		if svc.config.MaxTeams != 10 {
			t.Errorf("expected MaxTeams=10, got %d", svc.config.MaxTeams)
		}
	})
}

func TestConfig(t *testing.T) {
	t.Run("zero value", func(t *testing.T) {
		cfg := Config{}
		if cfg.MaxTeams != 0 {
			t.Errorf("expected MaxTeams=0 for zero value, got %d", cfg.MaxTeams)
		}
	})

	t.Run("with max teams", func(t *testing.T) {
		cfg := Config{MaxTeams: 5}
		if cfg.MaxTeams != 5 {
			t.Errorf("expected MaxTeams=5, got %d", cfg.MaxTeams)
		}
	})

	t.Run("config is value type", func(t *testing.T) {
		cfg1 := Config{MaxTeams: 3}
		cfg2 := cfg1
		cfg2.MaxTeams = 7
		if cfg1.MaxTeams != 3 {
			t.Error("modifying copy should not affect original")
		}
	})
}

func TestSetLimitProvider(t *testing.T) {
	svc := NewService(nil, nil, Config{}, logger.Nop())

	if svc.limitProvider != nil {
		t.Fatal("expected nil limitProvider before SetLimitProvider")
	}

	lp := &mockLimitProvider{limits: license.Limits{MaxTeams: 10}}
	svc.SetLimitProvider(lp)

	svc.limitMu.RLock()
	got := svc.limitProvider
	svc.limitMu.RUnlock()

	if got == nil {
		t.Fatal("expected non-nil limitProvider after SetLimitProvider")
	}
	if got.GetLimits().MaxTeams != 10 {
		t.Errorf("expected MaxTeams=10, got %d", got.GetLimits().MaxTeams)
	}
}

func TestSetLimitProvider_Overwrite(t *testing.T) {
	svc := NewService(nil, nil, Config{}, logger.Nop())

	lp1 := &mockLimitProvider{limits: license.Limits{MaxTeams: 3}}
	lp2 := &mockLimitProvider{limits: license.Limits{MaxTeams: 20}}

	svc.SetLimitProvider(lp1)
	svc.SetLimitProvider(lp2)

	svc.limitMu.RLock()
	got := svc.limitProvider
	svc.limitMu.RUnlock()

	if got.GetLimits().MaxTeams != 20 {
		t.Errorf("expected MaxTeams=20 after overwrite, got %d", got.GetLimits().MaxTeams)
	}
}

func TestSetLimitProvider_NilResets(t *testing.T) {
	svc := NewService(nil, nil, Config{}, logger.Nop())

	lp := &mockLimitProvider{limits: license.Limits{MaxTeams: 5}}
	svc.SetLimitProvider(lp)

	// Setting nil should clear the provider.
	svc.SetLimitProvider(nil)

	svc.limitMu.RLock()
	got := svc.limitProvider
	svc.limitMu.RUnlock()

	if got != nil {
		t.Error("expected nil limitProvider after SetLimitProvider(nil)")
	}
}

func TestSetLimitProvider_ConcurrentAccess(t *testing.T) {
	svc := NewService(nil, nil, Config{}, logger.Nop())

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			svc.SetLimitProvider(&mockLimitProvider{
				limits: license.Limits{MaxTeams: n},
			})
		}(i)
		go func() {
			defer wg.Done()
			svc.limitMu.RLock()
			lp := svc.limitProvider
			if lp != nil {
				_ = lp.GetLimits() // exercise the read path
			}
			svc.limitMu.RUnlock()
		}()
	}
	wg.Wait()
}

func TestNewServiceConfigPreserved(t *testing.T) {
	cfg := Config{MaxTeams: 42}
	svc := NewService(nil, nil, cfg, logger.Nop())

	// Config is a value type, so modifying the original should not affect the service.
	cfg.MaxTeams = 99
	if svc.config.MaxTeams != 42 {
		t.Errorf("expected stored MaxTeams=42, got %d (config should be copied)", svc.config.MaxTeams)
	}
}

func TestNewServiceMultipleInstances(t *testing.T) {
	svc1 := NewService(nil, nil, Config{MaxTeams: 1}, logger.Nop())
	svc2 := NewService(nil, nil, Config{MaxTeams: 2}, logger.Nop())

	if svc1 == svc2 {
		t.Error("expected distinct service instances")
	}
	if svc1.config.MaxTeams == svc2.config.MaxTeams {
		t.Error("expected different config values between instances")
	}
}
