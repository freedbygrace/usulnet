// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// CalendarEvent represents a calendar event (meeting, deadline, maintenance window, etc.).
type CalendarEvent struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	UserID      uuid.UUID  `json:"user_id" db:"user_id"`
	TeamID      *uuid.UUID `json:"team_id,omitempty" db:"team_id"`
	Title       string     `json:"title" db:"title"`
	Description string     `json:"description,omitempty" db:"description"`
	EventDate   string     `json:"event_date" db:"event_date"`
	EventTime   string     `json:"event_time,omitempty" db:"event_time"`
	Color       string     `json:"color" db:"color"`
	IsShared    bool       `json:"is_shared" db:"is_shared"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
}

// CalendarTask represents a task with priority and due date tracking.
type CalendarTask struct {
	ID        uuid.UUID  `json:"id" db:"id"`
	UserID    uuid.UUID  `json:"user_id" db:"user_id"`
	TeamID    *uuid.UUID `json:"team_id,omitempty" db:"team_id"`
	Text      string     `json:"text" db:"text"`
	Priority  string     `json:"priority" db:"priority"`
	DueDate   *string    `json:"due_date,omitempty" db:"due_date"`
	Done      bool       `json:"done" db:"done"`
	IsShared  bool       `json:"is_shared" db:"is_shared"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
}

// CalendarNote represents a free-form note.
type CalendarNote struct {
	ID        uuid.UUID  `json:"id" db:"id"`
	UserID    uuid.UUID  `json:"user_id" db:"user_id"`
	TeamID    *uuid.UUID `json:"team_id,omitempty" db:"team_id"`
	Title     string     `json:"title" db:"title"`
	Content   string     `json:"content,omitempty" db:"content"`
	IsShared  bool       `json:"is_shared" db:"is_shared"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
}

// CalendarChecklist represents a checklist with JSONB items.
type CalendarChecklist struct {
	ID        uuid.UUID       `json:"id" db:"id"`
	UserID    uuid.UUID       `json:"user_id" db:"user_id"`
	TeamID    *uuid.UUID      `json:"team_id,omitempty" db:"team_id"`
	Title     string          `json:"title" db:"title"`
	Items     json.RawMessage `json:"items" db:"items"`
	IsShared  bool            `json:"is_shared" db:"is_shared"`
	CreatedAt time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt time.Time       `json:"updated_at" db:"updated_at"`
}

// Calendar priority constants.
const (
	CalendarPriorityLow    = "low"
	CalendarPriorityNormal = "normal"
	CalendarPriorityHigh   = "high"
	CalendarPriorityUrgent = "urgent"
)

// Calendar color constants.
const (
	CalendarColorBlue   = "blue"
	CalendarColorRed    = "red"
	CalendarColorGreen  = "green"
	CalendarColorYellow = "yellow"
	CalendarColorPurple = "purple"
	CalendarColorOrange = "orange"
	CalendarColorPink   = "pink"
	CalendarColorGray   = "gray"
)

// ValidCalendarColors is the set of allowed event colors.
var ValidCalendarColors = map[string]bool{
	CalendarColorBlue:   true,
	CalendarColorRed:    true,
	CalendarColorGreen:  true,
	CalendarColorYellow: true,
	CalendarColorPurple: true,
	CalendarColorOrange: true,
	CalendarColorPink:   true,
	CalendarColorGray:   true,
}

// ValidCalendarPriorities is the set of allowed task priorities.
var ValidCalendarPriorities = map[string]bool{
	CalendarPriorityLow:    true,
	CalendarPriorityNormal: true,
	CalendarPriorityHigh:   true,
	CalendarPriorityUrgent: true,
}
