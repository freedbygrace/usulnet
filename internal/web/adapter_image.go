// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"

	"github.com/google/uuid"

	imagesvc "github.com/fr4nsys/usulnet/internal/services/image"
)

type imageAdapter struct {
	svc    *imagesvc.Service
	hostID uuid.UUID
}

func (a *imageAdapter) List(ctx context.Context) ([]ImageView, error) {
	if a.svc == nil {
		return nil, nil
	}

	images, err := a.svc.List(ctx, resolveHostID(ctx, a.hostID))
	if err != nil {
		return nil, err
	}

	views := make([]ImageView, 0, len(images))
	for _, img := range images {
		views = append(views, imageToView(img))
	}
	return views, nil
}

func (a *imageAdapter) Get(ctx context.Context, id string) (*ImageView, error) {
	if a.svc == nil {
		return nil, nil
	}

	img, err := a.svc.Get(ctx, resolveHostID(ctx, a.hostID), id)
	if err != nil {
		return nil, err
	}

	view := imageToView(img)
	return &view, nil
}

func (a *imageAdapter) Remove(ctx context.Context, id string, force bool) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}
	return a.svc.Remove(ctx, resolveHostID(ctx, a.hostID), id, force)
}

func (a *imageAdapter) Prune(ctx context.Context) (int64, error) {
	if a.svc == nil {
		return 0, ErrServiceNotConfigured
	}
	result, err := a.svc.Prune(ctx, resolveHostID(ctx, a.hostID), true)
	if err != nil {
		return 0, err
	}
	return result.SpaceReclaimed, nil
}

func (a *imageAdapter) Pull(ctx context.Context, reference string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}
	return a.svc.Pull(ctx, resolveHostID(ctx, a.hostID), reference, nil)
}
