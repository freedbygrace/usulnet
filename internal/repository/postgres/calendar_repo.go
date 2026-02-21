// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// CalendarRepository handles CRUD operations for calendar entities.
type CalendarRepository struct {
	db *DB
}

// NewCalendarRepository creates a new calendar repository.
func NewCalendarRepository(db *DB) *CalendarRepository {
	return &CalendarRepository{db: db}
}

// ============================================================================
// Events
// ============================================================================

// CreateEvent creates a new calendar event.
func (r *CalendarRepository) CreateEvent(ctx context.Context, ev *models.CalendarEvent) error {
	if ev.ID == uuid.Nil {
		ev.ID = uuid.New()
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO calendar_events (id, user_id, team_id, title, description, event_date, event_time, color, is_shared)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		ev.ID, ev.UserID, ev.TeamID, ev.Title, ev.Description,
		ev.EventDate, ev.EventTime, ev.Color, ev.IsShared,
	)
	return err
}

// GetEvent retrieves a calendar event by ID, visible to the given user.
func (r *CalendarRepository) GetEvent(ctx context.Context, id, userID uuid.UUID) (*models.CalendarEvent, error) {
	ev := &models.CalendarEvent{}
	err := r.db.QueryRow(ctx, `
		SELECT id, user_id, team_id, title, description, event_date, event_time, color, is_shared, created_at, updated_at
		FROM calendar_events
		WHERE id = $1 AND (user_id = $2 OR is_shared = TRUE)`, id, userID).Scan(
		&ev.ID, &ev.UserID, &ev.TeamID, &ev.Title, &ev.Description,
		&ev.EventDate, &ev.EventTime, &ev.Color, &ev.IsShared,
		&ev.CreatedAt, &ev.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return ev, nil
}

// ListEventsByMonth returns events for a given year/month visible to the user.
func (r *CalendarRepository) ListEventsByMonth(ctx context.Context, userID uuid.UUID, year, month int) ([]*models.CalendarEvent, error) {
	startDate := fmt.Sprintf("%04d-%02d-01", year, month)
	// Use interval arithmetic to get the last day of the month
	rows, err := r.db.Query(ctx, `
		SELECT id, user_id, team_id, title, description, event_date, event_time, color, is_shared, created_at, updated_at
		FROM calendar_events
		WHERE (user_id = $1 OR is_shared = TRUE)
		  AND event_date >= $2::date
		  AND event_date < ($2::date + INTERVAL '1 month')
		ORDER BY event_date, event_time NULLS LAST`,
		userID, startDate,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*models.CalendarEvent
	for rows.Next() {
		ev := &models.CalendarEvent{}
		if err := rows.Scan(
			&ev.ID, &ev.UserID, &ev.TeamID, &ev.Title, &ev.Description,
			&ev.EventDate, &ev.EventTime, &ev.Color, &ev.IsShared,
			&ev.CreatedAt, &ev.UpdatedAt,
		); err != nil {
			return nil, err
		}
		events = append(events, ev)
	}
	return events, nil
}

// UpdateEvent updates a calendar event. Only the owner can update.
func (r *CalendarRepository) UpdateEvent(ctx context.Context, ev *models.CalendarEvent) error {
	_, err := r.db.Exec(ctx, `
		UPDATE calendar_events SET
			title=$3, description=$4, event_date=$5, event_time=$6,
			color=$7, is_shared=$8, team_id=$9, updated_at=NOW()
		WHERE id=$1 AND user_id=$2`,
		ev.ID, ev.UserID, ev.Title, ev.Description, ev.EventDate,
		ev.EventTime, ev.Color, ev.IsShared, ev.TeamID,
	)
	return err
}

// DeleteEvent deletes a calendar event. Only the owner can delete.
func (r *CalendarRepository) DeleteEvent(ctx context.Context, id, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM calendar_events WHERE id = $1 AND user_id = $2`, id, userID)
	return err
}

// ============================================================================
// Tasks
// ============================================================================

// CreateTask creates a new calendar task.
func (r *CalendarRepository) CreateTask(ctx context.Context, t *models.CalendarTask) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO calendar_tasks (id, user_id, team_id, text, priority, due_date, done, is_shared)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		t.ID, t.UserID, t.TeamID, t.Text, t.Priority,
		t.DueDate, t.Done, t.IsShared,
	)
	return err
}

// ListTasks returns tasks visible to the user with optional filter.
// filter: "all", "active", "done"
func (r *CalendarRepository) ListTasks(ctx context.Context, userID uuid.UUID, filter string) ([]*models.CalendarTask, error) {
	query := `
		SELECT id, user_id, team_id, text, priority, due_date, done, is_shared, created_at, updated_at
		FROM calendar_tasks
		WHERE (user_id = $1 OR is_shared = TRUE)`

	switch filter {
	case "active":
		query += ` AND done = FALSE`
	case "done":
		query += ` AND done = TRUE`
	}

	query += ` ORDER BY
		CASE priority
			WHEN 'urgent' THEN 0
			WHEN 'high' THEN 1
			WHEN 'normal' THEN 2
			WHEN 'low' THEN 3
		END,
		due_date NULLS LAST,
		created_at DESC`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*models.CalendarTask
	for rows.Next() {
		t := &models.CalendarTask{}
		if err := rows.Scan(
			&t.ID, &t.UserID, &t.TeamID, &t.Text, &t.Priority,
			&t.DueDate, &t.Done, &t.IsShared, &t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, err
		}
		tasks = append(tasks, t)
	}
	return tasks, nil
}

// UpdateTask updates a calendar task. Only the owner can update.
func (r *CalendarRepository) UpdateTask(ctx context.Context, t *models.CalendarTask) error {
	_, err := r.db.Exec(ctx, `
		UPDATE calendar_tasks SET
			text=$3, priority=$4, due_date=$5, done=$6, is_shared=$7, team_id=$8, updated_at=NOW()
		WHERE id=$1 AND user_id=$2`,
		t.ID, t.UserID, t.Text, t.Priority, t.DueDate,
		t.Done, t.IsShared, t.TeamID,
	)
	return err
}

// ToggleTask toggles the done status of a task. Only the owner can toggle.
func (r *CalendarRepository) ToggleTask(ctx context.Context, id, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		UPDATE calendar_tasks SET done = NOT done, updated_at = NOW()
		WHERE id = $1 AND user_id = $2`, id, userID)
	return err
}

// DeleteTask deletes a calendar task. Only the owner can delete.
func (r *CalendarRepository) DeleteTask(ctx context.Context, id, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM calendar_tasks WHERE id = $1 AND user_id = $2`, id, userID)
	return err
}

// ============================================================================
// Notes
// ============================================================================

// CreateNote creates a new calendar note.
func (r *CalendarRepository) CreateNote(ctx context.Context, n *models.CalendarNote) error {
	if n.ID == uuid.Nil {
		n.ID = uuid.New()
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO calendar_notes (id, user_id, team_id, title, content, is_shared)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		n.ID, n.UserID, n.TeamID, n.Title, n.Content, n.IsShared,
	)
	return err
}

// ListNotes returns notes visible to the user.
func (r *CalendarRepository) ListNotes(ctx context.Context, userID uuid.UUID) ([]*models.CalendarNote, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, user_id, team_id, title, content, is_shared, created_at, updated_at
		FROM calendar_notes
		WHERE user_id = $1 OR is_shared = TRUE
		ORDER BY updated_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var notes []*models.CalendarNote
	for rows.Next() {
		n := &models.CalendarNote{}
		if err := rows.Scan(
			&n.ID, &n.UserID, &n.TeamID, &n.Title, &n.Content,
			&n.IsShared, &n.CreatedAt, &n.UpdatedAt,
		); err != nil {
			return nil, err
		}
		notes = append(notes, n)
	}
	return notes, nil
}

// UpdateNote updates a calendar note. Only the owner can update.
func (r *CalendarRepository) UpdateNote(ctx context.Context, n *models.CalendarNote) error {
	_, err := r.db.Exec(ctx, `
		UPDATE calendar_notes SET
			title=$3, content=$4, is_shared=$5, team_id=$6, updated_at=NOW()
		WHERE id=$1 AND user_id=$2`,
		n.ID, n.UserID, n.Title, n.Content, n.IsShared, n.TeamID,
	)
	return err
}

// DeleteNote deletes a calendar note. Only the owner can delete.
func (r *CalendarRepository) DeleteNote(ctx context.Context, id, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM calendar_notes WHERE id = $1 AND user_id = $2`, id, userID)
	return err
}

// ============================================================================
// Checklists
// ============================================================================

// CreateChecklist creates a new calendar checklist.
func (r *CalendarRepository) CreateChecklist(ctx context.Context, cl *models.CalendarChecklist) error {
	if cl.ID == uuid.Nil {
		cl.ID = uuid.New()
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO calendar_checklists (id, user_id, team_id, title, items, is_shared)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		cl.ID, cl.UserID, cl.TeamID, cl.Title, cl.Items, cl.IsShared,
	)
	return err
}

// ListChecklists returns checklists visible to the user.
func (r *CalendarRepository) ListChecklists(ctx context.Context, userID uuid.UUID) ([]*models.CalendarChecklist, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, user_id, team_id, title, items, is_shared, created_at, updated_at
		FROM calendar_checklists
		WHERE user_id = $1 OR is_shared = TRUE
		ORDER BY updated_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var checklists []*models.CalendarChecklist
	for rows.Next() {
		cl := &models.CalendarChecklist{}
		if err := rows.Scan(
			&cl.ID, &cl.UserID, &cl.TeamID, &cl.Title, &cl.Items,
			&cl.IsShared, &cl.CreatedAt, &cl.UpdatedAt,
		); err != nil {
			return nil, err
		}
		checklists = append(checklists, cl)
	}
	return checklists, nil
}

// UpdateChecklist updates a calendar checklist. Only the owner can update.
func (r *CalendarRepository) UpdateChecklist(ctx context.Context, cl *models.CalendarChecklist) error {
	_, err := r.db.Exec(ctx, `
		UPDATE calendar_checklists SET
			title=$3, items=$4, is_shared=$5, team_id=$6, updated_at=NOW()
		WHERE id=$1 AND user_id=$2`,
		cl.ID, cl.UserID, cl.Title, cl.Items, cl.IsShared, cl.TeamID,
	)
	return err
}

// DeleteChecklist deletes a calendar checklist. Only the owner can delete.
func (r *CalendarRepository) DeleteChecklist(ctx context.Context, id, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM calendar_checklists WHERE id = $1 AND user_id = $2`, id, userID)
	return err
}
