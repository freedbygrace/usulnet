// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"fmt"
	"time"

	"github.com/fr4nsys/usulnet/internal/docker"
)

type eventAdapter struct {
	dockerClient docker.ClientAPI
}

func (a *eventAdapter) List(ctx context.Context, limit int) ([]EventView, error) {
	if a.dockerClient == nil {
		return nil, nil
	}
	since := time.Now().Add(-1 * time.Hour)
	dockerEvents, err := a.dockerClient.GetEvents(ctx, since)
	if err != nil {
		// Gracefully degrade - don't break the page if Docker events fail
		return nil, nil
	}

	// Build list from newest first
	var events []EventView
	for i := len(dockerEvents) - 1; i >= 0; i-- {
		e := dockerEvents[i]
		events = append(events, EventView{
			ID:        fmt.Sprintf("%d", e.Time.UnixNano()),
			Type:      e.Type,
			Action:    e.Action,
			ActorID:   e.ActorID,
			ActorName: e.ActorName,
			ActorType: e.Type,
			Message:   fmt.Sprintf("%s %s: %s", e.Type, e.Action, e.ActorName),
			Timestamp: e.Time,
			TimeHuman: timeAgo(e.Time),
		})
		if len(events) >= limit {
			break
		}
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
