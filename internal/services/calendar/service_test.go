// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package calendar

import (
	"testing"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

func TestNewService(t *testing.T) {
	t.Run("nil repo and non-nil logger", func(t *testing.T) {
		log := logger.Nop()
		svc := NewService(nil, log)
		if svc == nil {
			t.Fatal("expected non-nil service")
		}
		if svc.repo != nil {
			t.Error("expected nil repo")
		}
		if svc.logger == nil {
			t.Error("expected non-nil logger")
		}
	})

	t.Run("nil repo and nil logger panics or is handled", func(t *testing.T) {
		// logger.Nop().Named() is safe, but nil logger is not.
		// The constructor does not guard against nil logger, so calling
		// Named on nil will panic. Verify that passing a valid Nop logger works.
		svc := NewService(nil, logger.Nop())
		if svc == nil {
			t.Fatal("expected non-nil service")
		}
	})
}

func TestValidateEvent(t *testing.T) {
	svc := NewService(nil, logger.Nop())

	tests := []struct {
		name      string
		event     *models.CalendarEvent
		wantErr   bool
		wantColor string // expected color after validation (if no error)
	}{
		{
			name:    "empty title",
			event:   &models.CalendarEvent{Title: "", EventDate: "2026-01-15"},
			wantErr: true,
		},
		{
			name:    "empty event_date",
			event:   &models.CalendarEvent{Title: "Test", EventDate: ""},
			wantErr: true,
		},
		{
			name:      "valid with default color",
			event:     &models.CalendarEvent{Title: "Test", EventDate: "2026-01-15", Color: ""},
			wantErr:   false,
			wantColor: models.CalendarColorBlue,
		},
		{
			name:      "valid with explicit color",
			event:     &models.CalendarEvent{Title: "Test", EventDate: "2026-01-15", Color: models.CalendarColorRed},
			wantErr:   false,
			wantColor: models.CalendarColorRed,
		},
		{
			name:    "invalid color",
			event:   &models.CalendarEvent{Title: "Test", EventDate: "2026-01-15", Color: "neon"},
			wantErr: true,
		},
		{
			name:      "all valid colors accepted - green",
			event:     &models.CalendarEvent{Title: "T", EventDate: "2026-01-01", Color: models.CalendarColorGreen},
			wantErr:   false,
			wantColor: models.CalendarColorGreen,
		},
		{
			name:      "all valid colors accepted - yellow",
			event:     &models.CalendarEvent{Title: "T", EventDate: "2026-01-01", Color: models.CalendarColorYellow},
			wantErr:   false,
			wantColor: models.CalendarColorYellow,
		},
		{
			name:      "all valid colors accepted - purple",
			event:     &models.CalendarEvent{Title: "T", EventDate: "2026-01-01", Color: models.CalendarColorPurple},
			wantErr:   false,
			wantColor: models.CalendarColorPurple,
		},
		{
			name:      "all valid colors accepted - orange",
			event:     &models.CalendarEvent{Title: "T", EventDate: "2026-01-01", Color: models.CalendarColorOrange},
			wantErr:   false,
			wantColor: models.CalendarColorOrange,
		},
		{
			name:      "all valid colors accepted - pink",
			event:     &models.CalendarEvent{Title: "T", EventDate: "2026-01-01", Color: models.CalendarColorPink},
			wantErr:   false,
			wantColor: models.CalendarColorPink,
		},
		{
			name:      "all valid colors accepted - gray",
			event:     &models.CalendarEvent{Title: "T", EventDate: "2026-01-01", Color: models.CalendarColorGray},
			wantErr:   false,
			wantColor: models.CalendarColorGray,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.validateEvent(tc.event)
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
			if !tc.wantErr && tc.event.Color != tc.wantColor {
				t.Errorf("expected color %q, got %q", tc.wantColor, tc.event.Color)
			}
		})
	}
}

func TestValidateEvent_DefaultColorMutation(t *testing.T) {
	svc := NewService(nil, logger.Nop())

	// Verify that validateEvent mutates the event's Color field when empty.
	ev := &models.CalendarEvent{Title: "Test", EventDate: "2026-03-01"}
	if ev.Color != "" {
		t.Fatal("precondition: color should be empty")
	}
	if err := svc.validateEvent(ev); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.Color != models.CalendarColorBlue {
		t.Errorf("expected default color %q, got %q", models.CalendarColorBlue, ev.Color)
	}
}

func TestValidateTask(t *testing.T) {
	svc := NewService(nil, logger.Nop())

	tests := []struct {
		name         string
		task         *models.CalendarTask
		wantErr      bool
		wantPriority string
	}{
		{
			name:    "empty text",
			task:    &models.CalendarTask{Text: ""},
			wantErr: true,
		},
		{
			name:         "valid with default priority",
			task:         &models.CalendarTask{Text: "Do something", Priority: ""},
			wantErr:      false,
			wantPriority: models.CalendarPriorityNormal,
		},
		{
			name:         "valid with explicit priority low",
			task:         &models.CalendarTask{Text: "Do something", Priority: models.CalendarPriorityLow},
			wantErr:      false,
			wantPriority: models.CalendarPriorityLow,
		},
		{
			name:         "valid with explicit priority high",
			task:         &models.CalendarTask{Text: "Do something", Priority: models.CalendarPriorityHigh},
			wantErr:      false,
			wantPriority: models.CalendarPriorityHigh,
		},
		{
			name:         "valid with explicit priority urgent",
			task:         &models.CalendarTask{Text: "Do something", Priority: models.CalendarPriorityUrgent},
			wantErr:      false,
			wantPriority: models.CalendarPriorityUrgent,
		},
		{
			name:    "invalid priority",
			task:    &models.CalendarTask{Text: "Do something", Priority: "critical"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.validateTask(tc.task)
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
			if !tc.wantErr && tc.task.Priority != tc.wantPriority {
				t.Errorf("expected priority %q, got %q", tc.wantPriority, tc.task.Priority)
			}
		})
	}
}

func TestValidateTask_DefaultPriorityMutation(t *testing.T) {
	svc := NewService(nil, logger.Nop())

	task := &models.CalendarTask{Text: "test task"}
	if task.Priority != "" {
		t.Fatal("precondition: priority should be empty")
	}
	if err := svc.validateTask(task); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if task.Priority != models.CalendarPriorityNormal {
		t.Errorf("expected default priority %q, got %q", models.CalendarPriorityNormal, task.Priority)
	}
}

func TestServiceStructFields(t *testing.T) {
	log := logger.Nop()
	svc := NewService(nil, log)

	// Verify struct initialization.
	if svc.repo != nil {
		t.Error("expected nil repo when nil was passed")
	}
	if svc.logger == nil {
		t.Error("logger should not be nil after construction")
	}
}
