// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"testing"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ---------------------------------------------------------------------------
// Mock repository
// ---------------------------------------------------------------------------

type mockRepo struct {
	layouts map[uuid.UUID]*models.DashboardLayout
	widgets map[uuid.UUID]*models.DashboardWidget

	createLayoutFn func(ctx context.Context, l *models.DashboardLayout) error
	clearDefaultFn func(ctx context.Context, userID uuid.UUID) error
}

func newMockRepo() *mockRepo {
	return &mockRepo{
		layouts: make(map[uuid.UUID]*models.DashboardLayout),
		widgets: make(map[uuid.UUID]*models.DashboardWidget),
	}
}

func (m *mockRepo) CreateLayout(_ context.Context, l *models.DashboardLayout) error {
	if m.createLayoutFn != nil {
		return m.createLayoutFn(nil, l)
	}
	if l.ID == uuid.Nil {
		l.ID = uuid.New()
	}
	m.layouts[l.ID] = l
	return nil
}

func (m *mockRepo) GetLayout(_ context.Context, id uuid.UUID) (*models.DashboardLayout, error) {
	l, ok := m.layouts[id]
	if !ok {
		return nil, errors.NotFound("layout")
	}
	return l, nil
}

func (m *mockRepo) UpdateLayout(_ context.Context, l *models.DashboardLayout) error {
	m.layouts[l.ID] = l
	return nil
}

func (m *mockRepo) DeleteLayout(_ context.Context, id uuid.UUID) error {
	delete(m.layouts, id)
	return nil
}

func (m *mockRepo) ListLayouts(_ context.Context, _ uuid.UUID) ([]*models.DashboardLayout, error) {
	var result []*models.DashboardLayout
	for _, l := range m.layouts {
		result = append(result, l)
	}
	return result, nil
}

func (m *mockRepo) GetDefaultLayout(_ context.Context, userID uuid.UUID) (*models.DashboardLayout, error) {
	for _, l := range m.layouts {
		if l.IsDefault && l.UserID != nil && *l.UserID == userID {
			return l, nil
		}
	}
	return nil, errors.NotFound("layout")
}

func (m *mockRepo) ClearDefault(_ context.Context, userID uuid.UUID) error {
	if m.clearDefaultFn != nil {
		return m.clearDefaultFn(nil, userID)
	}
	for _, l := range m.layouts {
		if l.IsDefault && l.UserID != nil && *l.UserID == userID {
			l.IsDefault = false
		}
	}
	return nil
}

func (m *mockRepo) CreateWidget(_ context.Context, w *models.DashboardWidget) error {
	if w.ID == uuid.Nil {
		w.ID = uuid.New()
	}
	m.widgets[w.ID] = w
	return nil
}

func (m *mockRepo) GetWidget(_ context.Context, id uuid.UUID) (*models.DashboardWidget, error) {
	w, ok := m.widgets[id]
	if !ok {
		return nil, errors.NotFound("widget")
	}
	return w, nil
}

func (m *mockRepo) UpdateWidget(_ context.Context, w *models.DashboardWidget) error {
	m.widgets[w.ID] = w
	return nil
}

func (m *mockRepo) DeleteWidget(_ context.Context, id uuid.UUID) error {
	delete(m.widgets, id)
	return nil
}

func (m *mockRepo) ListWidgets(_ context.Context, layoutID uuid.UUID) ([]*models.DashboardWidget, error) {
	var result []*models.DashboardWidget
	for _, w := range m.widgets {
		if w.LayoutID == layoutID {
			result = append(result, w)
		}
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func testService(repo *mockRepo) *Service {
	log, _ := logger.NewWithOutput("error", "console", io.Discard)
	return NewService(repo, log)
}

var testUserID = uuid.MustParse("00000000-0000-0000-0000-000000000001")
var otherUserID = uuid.MustParse("00000000-0000-0000-0000-000000000002")

func seedLayout(repo *mockRepo, userID uuid.UUID, name string, shared bool) *models.DashboardLayout {
	id := uuid.New()
	l := &models.DashboardLayout{
		ID:       id,
		Name:     name,
		UserID:   &userID,
		IsShared: shared,
	}
	repo.layouts[id] = l
	return l
}

func seedWidget(repo *mockRepo, layoutID uuid.UUID, widgetType string) *models.DashboardWidget {
	id := uuid.New()
	w := &models.DashboardWidget{
		ID:         id,
		LayoutID:   layoutID,
		WidgetType: widgetType,
		Title:      widgetType + " widget",
		Width:      6,
		Height:     4,
	}
	repo.widgets[id] = w
	return w
}

// ---------------------------------------------------------------------------
// Layout tests
// ---------------------------------------------------------------------------

func TestCreateLayout_Success(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	input := &CreateLayoutInput{
		Name:       "My Dashboard",
		LayoutJSON: json.RawMessage(`{"columns":12}`),
	}

	got, err := svc.CreateLayout(context.Background(), testUserID, input)
	if err != nil {
		t.Fatalf("CreateLayout() error = %v", err)
	}
	if got.Name != "My Dashboard" {
		t.Errorf("Name = %q, want %q", got.Name, "My Dashboard")
	}
	if got.UserID == nil || *got.UserID != testUserID {
		t.Errorf("UserID = %v, want %v", got.UserID, testUserID)
	}
}

func TestCreateLayout_EmptyName(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	_, err := svc.CreateLayout(context.Background(), testUserID, &CreateLayoutInput{})
	if err == nil {
		t.Fatal("expected error for empty name")
	}
	if !errors.IsValidationError(err) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCreateLayout_SetsDefault_ClearsExisting(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	// Create first default layout
	existing := seedLayout(repo, testUserID, "Old Default", false)
	existing.IsDefault = true

	// Create new default
	input := &CreateLayoutInput{
		Name:      "New Default",
		IsDefault: true,
	}
	got, err := svc.CreateLayout(context.Background(), testUserID, input)
	if err != nil {
		t.Fatalf("CreateLayout() error = %v", err)
	}
	if !got.IsDefault {
		t.Error("new layout should be default")
	}
	if existing.IsDefault {
		t.Error("old layout should no longer be default")
	}
}

func TestCreateLayout_RepoError(t *testing.T) {
	repo := newMockRepo()
	repo.createLayoutFn = func(_ context.Context, _ *models.DashboardLayout) error {
		return fmt.Errorf("db connection failed")
	}
	svc := testService(repo)

	_, err := svc.CreateLayout(context.Background(), testUserID, &CreateLayoutInput{Name: "fail"})
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

func TestGetLayout_Owner(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)
	layout := seedLayout(repo, testUserID, "Mine", false)

	got, err := svc.GetLayout(context.Background(), testUserID, layout.ID)
	if err != nil {
		t.Fatalf("GetLayout() error = %v", err)
	}
	if got.ID != layout.ID {
		t.Errorf("ID = %v, want %v", got.ID, layout.ID)
	}
}

func TestGetLayout_SharedAccessAllowed(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)
	layout := seedLayout(repo, testUserID, "Shared", true)

	got, err := svc.GetLayout(context.Background(), otherUserID, layout.ID)
	if err != nil {
		t.Fatalf("GetLayout() error = %v", err)
	}
	if got.ID != layout.ID {
		t.Errorf("ID = %v, want %v", got.ID, layout.ID)
	}
}

func TestGetLayout_ForbiddenForNonOwnerNonShared(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)
	layout := seedLayout(repo, testUserID, "Private", false)

	_, err := svc.GetLayout(context.Background(), otherUserID, layout.ID)
	if err == nil {
		t.Fatal("expected forbidden error")
	}
	if !errors.IsForbiddenError(err) {
		t.Errorf("expected forbidden, got %v", err)
	}
}

func TestGetLayout_NotFound(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	_, err := svc.GetLayout(context.Background(), testUserID, uuid.New())
	if err == nil {
		t.Fatal("expected not found error")
	}
}

func TestUpdateLayout_Success(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)
	layout := seedLayout(repo, testUserID, "Original", false)

	newName := "Updated"
	got, err := svc.UpdateLayout(context.Background(), testUserID, layout.ID, &UpdateLayoutInput{
		Name: &newName,
	})
	if err != nil {
		t.Fatalf("UpdateLayout() error = %v", err)
	}
	if got.Name != "Updated" {
		t.Errorf("Name = %q, want %q", got.Name, "Updated")
	}
}

func TestUpdateLayout_EmptyName(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)
	layout := seedLayout(repo, testUserID, "Valid", false)

	empty := ""
	_, err := svc.UpdateLayout(context.Background(), testUserID, layout.ID, &UpdateLayoutInput{
		Name: &empty,
	})
	if err == nil {
		t.Fatal("expected validation error for empty name")
	}
}

func TestUpdateLayout_Forbidden(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)
	layout := seedLayout(repo, testUserID, "NotYours", false)

	newName := "Hacked"
	_, err := svc.UpdateLayout(context.Background(), otherUserID, layout.ID, &UpdateLayoutInput{
		Name: &newName,
	})
	if err == nil {
		t.Fatal("expected forbidden error")
	}
	if !errors.IsForbiddenError(err) {
		t.Errorf("expected forbidden, got %v", err)
	}
}

func TestUpdateLayout_SetsNewDefault(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)

	old := seedLayout(repo, testUserID, "Old Default", false)
	old.IsDefault = true

	layout := seedLayout(repo, testUserID, "Will Be Default", false)

	isDefault := true
	_, err := svc.UpdateLayout(context.Background(), testUserID, layout.ID, &UpdateLayoutInput{
		IsDefault: &isDefault,
	})
	if err != nil {
		t.Fatalf("UpdateLayout() error = %v", err)
	}
	if old.IsDefault {
		t.Error("old default should be cleared")
	}
}

func TestDeleteLayout_Success(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)
	layout := seedLayout(repo, testUserID, "ToDelete", false)

	err := svc.DeleteLayout(context.Background(), testUserID, layout.ID)
	if err != nil {
		t.Fatalf("DeleteLayout() error = %v", err)
	}
	if _, ok := repo.layouts[layout.ID]; ok {
		t.Error("layout should be deleted")
	}
}

func TestDeleteLayout_Forbidden(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)
	layout := seedLayout(repo, testUserID, "NotYours", false)

	err := svc.DeleteLayout(context.Background(), otherUserID, layout.ID)
	if err == nil {
		t.Fatal("expected forbidden error")
	}
}

func TestListLayouts(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)
	seedLayout(repo, testUserID, "A", false)
	seedLayout(repo, testUserID, "B", true)

	got, err := svc.ListLayouts(context.Background(), testUserID)
	if err != nil {
		t.Fatalf("ListLayouts() error = %v", err)
	}
	if len(got) != 2 {
		t.Errorf("len = %d, want 2", len(got))
	}
}

// ---------------------------------------------------------------------------
// Widget tests
// ---------------------------------------------------------------------------

func TestAddWidget_Success(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)
	layout := seedLayout(repo, testUserID, "Dashboard", false)

	got, err := svc.AddWidget(context.Background(), testUserID, layout.ID, &AddWidgetInput{
		WidgetType: models.WidgetTypeCPUGauge,
		Title:      "CPU Usage",
		Width:      8,
		Height:     6,
	})
	if err != nil {
		t.Fatalf("AddWidget() error = %v", err)
	}
	if got.WidgetType != models.WidgetTypeCPUGauge {
		t.Errorf("WidgetType = %q, want %q", got.WidgetType, models.WidgetTypeCPUGauge)
	}
	if got.Width != 8 {
		t.Errorf("Width = %d, want 8", got.Width)
	}
}

func TestAddWidget_DefaultDimensions(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)
	layout := seedLayout(repo, testUserID, "Dashboard", false)

	got, err := svc.AddWidget(context.Background(), testUserID, layout.ID, &AddWidgetInput{
		WidgetType: models.WidgetTypeMemoryGauge,
		Title:      "Memory",
	})
	if err != nil {
		t.Fatalf("AddWidget() error = %v", err)
	}
	if got.Width != 6 {
		t.Errorf("default Width = %d, want 6", got.Width)
	}
	if got.Height != 4 {
		t.Errorf("default Height = %d, want 4", got.Height)
	}
}

func TestAddWidget_InvalidType(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)
	layout := seedLayout(repo, testUserID, "Dashboard", false)

	_, err := svc.AddWidget(context.Background(), testUserID, layout.ID, &AddWidgetInput{
		WidgetType: "invalid_type",
		Title:      "Bad",
	})
	if err == nil {
		t.Fatal("expected validation error for invalid widget type")
	}
}

func TestAddWidget_Forbidden(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)
	layout := seedLayout(repo, testUserID, "Dashboard", false)

	_, err := svc.AddWidget(context.Background(), otherUserID, layout.ID, &AddWidgetInput{
		WidgetType: models.WidgetTypeCPUGauge,
		Title:      "Hacked",
	})
	if err == nil {
		t.Fatal("expected forbidden error")
	}
}

func TestUpdateWidget_Success(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)
	layout := seedLayout(repo, testUserID, "Dashboard", false)
	widget := seedWidget(repo, layout.ID, models.WidgetTypeCPUGauge)

	newTitle := "Updated CPU"
	newWidth := 12
	got, err := svc.UpdateWidget(context.Background(), testUserID, widget.ID, &UpdateWidgetInput{
		Title: &newTitle,
		Width: &newWidth,
	})
	if err != nil {
		t.Fatalf("UpdateWidget() error = %v", err)
	}
	if got.Title != "Updated CPU" {
		t.Errorf("Title = %q, want %q", got.Title, "Updated CPU")
	}
	if got.Width != 12 {
		t.Errorf("Width = %d, want 12", got.Width)
	}
}

func TestUpdateWidget_Forbidden(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)
	layout := seedLayout(repo, testUserID, "Dashboard", false)
	widget := seedWidget(repo, layout.ID, models.WidgetTypeCPUGauge)

	newTitle := "Hacked"
	_, err := svc.UpdateWidget(context.Background(), otherUserID, widget.ID, &UpdateWidgetInput{
		Title: &newTitle,
	})
	if err == nil {
		t.Fatal("expected forbidden error")
	}
}

func TestRemoveWidget_Success(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)
	layout := seedLayout(repo, testUserID, "Dashboard", false)
	widget := seedWidget(repo, layout.ID, models.WidgetTypeCPUGauge)

	err := svc.RemoveWidget(context.Background(), testUserID, widget.ID)
	if err != nil {
		t.Fatalf("RemoveWidget() error = %v", err)
	}
	if _, ok := repo.widgets[widget.ID]; ok {
		t.Error("widget should be deleted")
	}
}

func TestRemoveWidget_Forbidden(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)
	layout := seedLayout(repo, testUserID, "Dashboard", false)
	widget := seedWidget(repo, layout.ID, models.WidgetTypeCPUGauge)

	err := svc.RemoveWidget(context.Background(), otherUserID, widget.ID)
	if err == nil {
		t.Fatal("expected forbidden error")
	}
}

func TestGetLayoutWidgets_Owner(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)
	layout := seedLayout(repo, testUserID, "Dashboard", false)
	seedWidget(repo, layout.ID, models.WidgetTypeCPUGauge)
	seedWidget(repo, layout.ID, models.WidgetTypeMemoryGauge)

	got, err := svc.GetLayoutWidgets(context.Background(), testUserID, layout.ID)
	if err != nil {
		t.Fatalf("GetLayoutWidgets() error = %v", err)
	}
	if len(got) != 2 {
		t.Errorf("len = %d, want 2", len(got))
	}
}

func TestGetLayoutWidgets_SharedAccess(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)
	layout := seedLayout(repo, testUserID, "Shared", true)
	seedWidget(repo, layout.ID, models.WidgetTypeCPUGauge)

	got, err := svc.GetLayoutWidgets(context.Background(), otherUserID, layout.ID)
	if err != nil {
		t.Fatalf("GetLayoutWidgets() error = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("len = %d, want 1", len(got))
	}
}

func TestGetLayoutWidgets_Forbidden(t *testing.T) {
	repo := newMockRepo()
	svc := testService(repo)
	layout := seedLayout(repo, testUserID, "Private", false)
	seedWidget(repo, layout.ID, models.WidgetTypeCPUGauge)

	_, err := svc.GetLayoutWidgets(context.Background(), otherUserID, layout.ID)
	if err == nil {
		t.Fatal("expected forbidden error")
	}
}
