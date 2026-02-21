// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package swarm

import (
	"testing"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

func TestNewService(t *testing.T) {
	t.Run("nil host service with nop logger", func(t *testing.T) {
		svc := NewService(nil, logger.Nop())
		if svc == nil {
			t.Fatal("expected non-nil service")
		}
		if svc.hostService != nil {
			t.Error("expected nil hostService")
		}
		if svc.logger == nil {
			t.Error("expected non-nil logger")
		}
	})

	t.Run("nil logger defaults to nop", func(t *testing.T) {
		svc := NewService(nil, nil)
		if svc == nil {
			t.Fatal("expected non-nil service")
		}
		if svc.logger == nil {
			t.Error("expected non-nil logger even when nil is passed")
		}
	})
}

func TestNewServiceMultipleInstances(t *testing.T) {
	svc1 := NewService(nil, logger.Nop())
	svc2 := NewService(nil, logger.Nop())

	if svc1 == svc2 {
		t.Error("expected distinct service instances")
	}
}

func TestServiceStructFields(t *testing.T) {
	svc := NewService(nil, logger.Nop())

	if svc.hostService != nil {
		t.Error("expected nil hostService when nil was passed")
	}
	if svc.logger == nil {
		t.Error("logger should not be nil after construction")
	}
}

func TestNewServiceMutexInitialized(t *testing.T) {
	// The sync.RWMutex is zero-value initialized (unlocked).
	// Verify we can lock/unlock without panic.
	svc := NewService(nil, logger.Nop())

	svc.mu.Lock()
	svc.mu.Unlock()

	svc.mu.RLock()
	svc.mu.RUnlock()
}

func TestNewServiceNilLoggerSafety(t *testing.T) {
	// Passing nil logger should be safe; the constructor guards against it.
	svc := NewService(nil, nil)

	// The logger should be a Nop logger, not nil.
	if svc.logger == nil {
		t.Fatal("logger should be set to Nop when nil is passed")
	}
}
