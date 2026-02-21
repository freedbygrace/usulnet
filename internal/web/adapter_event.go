// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

type eventAdapter struct {
	dockerClient docker.ClientAPI
	auditLogRepo *postgres.AuditLogRepository
}

func (a *eventAdapter) List(ctx context.Context, limit int) ([]EventView, error) {
	var events []EventView

	// 1. Docker events (last 1 hour)
	if a.dockerClient != nil {
		since := time.Now().Add(-1 * time.Hour)
		dockerEvents, err := a.dockerClient.GetEvents(ctx, since)
		if err == nil {
			for _, e := range dockerEvents {
				events = append(events, EventView{
					ID:        fmt.Sprintf("docker-%d", e.Time.UnixNano()),
					Type:      e.Type,
					Action:    e.Action,
					ActorID:   e.ActorID,
					ActorName: e.ActorName,
					ActorType: e.Type,
					Message:   fmt.Sprintf("%s %s: %s", e.Type, e.Action, e.ActorName),
					Timestamp: e.Time,
					TimeHuman: timeAgo(e.Time),
				})
			}
		}
	}

	// 2. Audit log events (user actions persisted in DB)
	if a.auditLogRepo != nil {
		auditEntries, err := a.auditLogRepo.GetRecent(ctx, limit)
		if err == nil {
			for _, entry := range auditEntries {
				username := "system"
				if entry.Username != nil && *entry.Username != "" {
					username = *entry.Username
				}

				msg := auditEventMessage(entry.Action, username, entry.EntityType)

				events = append(events, EventView{
					ID:        fmt.Sprintf("audit-%d", entry.ID),
					Type:      "audit",
					Action:    entry.Action,
					ActorID:   username,
					ActorName: username,
					ActorType: entry.EntityType,
					Message:   msg,
					Timestamp: entry.CreatedAt,
					TimeHuman: timeAgo(entry.CreatedAt),
				})
			}
		}
	}

	// Sort all events newest first
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.After(events[j].Timestamp)
	})

	// Trim to limit
	if len(events) > limit {
		events = events[:limit]
	}

	return events, nil
}

func (a *eventAdapter) Stream(ctx context.Context) (<-chan EventView, error) {
	if a.dockerClient == nil {
		ch := make(chan EventView)
		close(ch)
		return ch, nil
	}

	eventCh, errCh := a.dockerClient.StreamEvents(ctx)
	viewCh := make(chan EventView, 64)

	go func() {
		defer close(viewCh)
		for {
			select {
			case e, ok := <-eventCh:
				if !ok {
					return
				}
				view := EventView{
					ID:        fmt.Sprintf("%d", e.Time.UnixNano()),
					Type:      e.Type,
					Action:    e.Action,
					ActorID:   e.ActorID,
					ActorName: e.ActorName,
					ActorType: e.Type,
					Message:   fmt.Sprintf("%s %s: %s", e.Type, e.Action, e.ActorName),
					Timestamp: e.Time,
					TimeHuman: timeAgo(e.Time),
				}
				select {
				case viewCh <- view:
				case <-ctx.Done():
					return
				}
			case <-errCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	return viewCh, nil
}

// auditEventMessage builds a human-readable message for audit log events.
func auditEventMessage(action, username, entityType string) string {
	switch action {
	case "login":
		return fmt.Sprintf("%s logged in", username)
	case "logout":
		return fmt.Sprintf("%s logged out", username)
	case "login_failed":
		return fmt.Sprintf("Failed login attempt for %s", username)
	case "password_change":
		return fmt.Sprintf("%s changed password", username)
	case "password_reset":
		return fmt.Sprintf("Password reset for %s", username)
	case "api_key_create":
		return fmt.Sprintf("%s created an API key", username)
	case "api_key_delete":
		return fmt.Sprintf("%s deleted an API key", username)
	case "create":
		return fmt.Sprintf("%s created %s", username, entityType)
	case "update":
		return fmt.Sprintf("%s updated %s", username, entityType)
	case "delete":
		return fmt.Sprintf("%s deleted %s", username, entityType)
	case "security_scan":
		return fmt.Sprintf("%s triggered a security scan", username)
	case "backup":
		return fmt.Sprintf("%s created a backup", username)
	case "restore":
		return fmt.Sprintf("%s restored from backup", username)
	default:
		if entityType != "" {
			return fmt.Sprintf("%s %s %s", username, action, entityType)
		}
		return fmt.Sprintf("%s: %s", username, action)
	}
}
