// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package manifest_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/services/manifest"
)

// ============================================================================
// Mock Repository
// ============================================================================

type mockRepo struct {
	mu         sync.Mutex
	templates  map[uuid.UUID]*models.ManifestTemplate
	sessions   map[uuid.UUID]*models.ManifestBuilderSession
	components map[uuid.UUID]*models.ManifestBuilderComponent
}

func newMockRepo() *mockRepo {
	return &mockRepo{
		templates:  make(map[uuid.UUID]*models.ManifestTemplate),
		sessions:   make(map[uuid.UUID]*models.ManifestBuilderSession),
		components: make(map[uuid.UUID]*models.ManifestBuilderComponent),
	}
}

func (m *mockRepo) CreateTemplate(_ context.Context, t *models.ManifestTemplate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.templates[t.ID] = t
	return nil
}

func (m *mockRepo) GetTemplate(_ context.Context, id uuid.UUID) (*models.ManifestTemplate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.templates[id]
	if !ok {
		return nil, fmt.Errorf("template %s not found", id)
	}
	return t, nil
}

func (m *mockRepo) ListTemplates(_ context.Context, format, category string) ([]*models.ManifestTemplate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*models.ManifestTemplate
	for _, t := range m.templates {
		if format != "" && string(t.Format) != format {
			continue
		}
		if category != "" && t.Category != category {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

func (m *mockRepo) UpdateTemplate(_ context.Context, t *models.ManifestTemplate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.templates[t.ID] = t
	return nil
}

func (m *mockRepo) DeleteTemplate(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.templates[id]; !ok {
		return fmt.Errorf("template %s not found", id)
	}
	delete(m.templates, id)
	return nil
}

func (m *mockRepo) IncrementTemplateUsage(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.templates[id]
	if !ok {
		return fmt.Errorf("template %s not found", id)
	}
	t.UsageCount++
	return nil
}

func (m *mockRepo) ListTemplateCategories(_ context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := make(map[string]bool)
	for _, t := range m.templates {
		if t.Category != "" {
			seen[t.Category] = true
		}
	}
	var out []string
	for c := range seen {
		out = append(out, c)
	}
	return out, nil
}

func (m *mockRepo) CreateSession(_ context.Context, s *models.ManifestBuilderSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.ID] = s
	return nil
}

func (m *mockRepo) GetSession(_ context.Context, id uuid.UUID) (*models.ManifestBuilderSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return nil, fmt.Errorf("session %s not found", id)
	}
	return s, nil
}

func (m *mockRepo) ListSessions(_ context.Context, userID uuid.UUID) ([]*models.ManifestBuilderSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*models.ManifestBuilderSession
	for _, s := range m.sessions {
		if s.UserID == userID {
			out = append(out, s)
		}
	}
	return out, nil
}

func (m *mockRepo) UpdateSession(_ context.Context, s *models.ManifestBuilderSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.ID] = s
	return nil
}

func (m *mockRepo) DeleteSession(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[id]; !ok {
		return fmt.Errorf("session %s not found", id)
	}
	delete(m.sessions, id)
	return nil
}

func (m *mockRepo) CreateComponent(_ context.Context, c *models.ManifestBuilderComponent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.components[c.ID] = c
	return nil
}

func (m *mockRepo) GetComponent(_ context.Context, id uuid.UUID) (*models.ManifestBuilderComponent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.components[id]
	if !ok {
		return nil, fmt.Errorf("component %s not found", id)
	}
	return c, nil
}

func (m *mockRepo) ListComponents(_ context.Context, category string) ([]*models.ManifestBuilderComponent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*models.ManifestBuilderComponent
	for _, c := range m.components {
		if category != "" && c.Category != category {
			continue
		}
		out = append(out, c)
	}
	return out, nil
}

func (m *mockRepo) DeleteComponent(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.components, id)
	return nil
}

func (m *mockRepo) SeedBuiltinComponents(_ context.Context) error {
	return nil
}

// ============================================================================
// Tests
// ============================================================================

func newService() (*manifest.Service, *mockRepo) {
	repo := newMockRepo()
	svc := manifest.NewService(repo, manifest.DefaultConfig(), nil)
	return svc, repo
}

func TestCreateTemplate(t *testing.T) {
	svc, repo := newService()
	ctx := context.Background()

	input := manifest.CreateTemplateInput{
		Name:     "My Template",
		Content:  "version: '3'\nservices:\n  web:\n    image: nginx",
		Format:   models.ManifestFormatCompose,
		Category: "web",
	}

	tmpl, err := svc.CreateTemplate(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tmpl.Name != "My Template" {
		t.Errorf("Name = %q, want %q", tmpl.Name, "My Template")
	}
	if tmpl.Format != models.ManifestFormatCompose {
		t.Errorf("Format = %q, want %q", tmpl.Format, models.ManifestFormatCompose)
	}
	if tmpl.IsBuiltin {
		t.Error("expected IsBuiltin = false")
	}

	// Verify stored.
	repo.mu.Lock()
	stored, ok := repo.templates[tmpl.ID]
	repo.mu.Unlock()
	if !ok {
		t.Fatal("template not found in repo")
	}
	if stored.Content != input.Content {
		t.Errorf("stored Content mismatch")
	}
}

func TestCreateTemplate_Validation(t *testing.T) {
	svc, _ := newService()
	ctx := context.Background()

	tests := []struct {
		name  string
		input manifest.CreateTemplateInput
	}{
		{"empty name", manifest.CreateTemplateInput{Content: "x"}},
		{"empty content", manifest.CreateTemplateInput{Name: "x"}},
		{"whitespace name", manifest.CreateTemplateInput{Name: "   ", Content: "x"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.CreateTemplate(ctx, tc.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestCreateSession(t *testing.T) {
	svc, _ := newService()
	ctx := context.Background()
	userID := uuid.New()

	session, err := svc.CreateSession(ctx, userID, "my-session", models.ManifestFormatCompose)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session.Name != "my-session" {
		t.Errorf("Name = %q, want %q", session.Name, "my-session")
	}
	if session.UserID != userID {
		t.Errorf("UserID = %s, want %s", session.UserID, userID)
	}
	if session.Format != models.ManifestFormatCompose {
		t.Errorf("Format = %q, want %q", session.Format, models.ManifestFormatCompose)
	}
	if session.IsSaved {
		t.Error("expected IsSaved = false for new session")
	}
}

func TestGenerateCompose(t *testing.T) {
	svc, _ := newService()

	services := []models.ManifestServiceBlock{
		{
			Name:  "web",
			Image: "nginx",
			Tag:   "alpine",
			Ports: []models.PortMapping{
				{Host: 8080, Container: 80, Protocol: "tcp"},
			},
			Environment: map[string]string{"ENV": "prod"},
			Restart:     "unless-stopped",
		},
		{
			Name:      "db",
			Image:     "postgres",
			Tag:       "16",
			DependsOn: []string{"web"},
		},
	}

	yaml, errs := svc.GenerateCompose(services, json.RawMessage(`{}`), json.RawMessage(`{}`), "3.8")

	if len(errs) != 0 {
		t.Errorf("unexpected validation errors: %v", errs)
	}
	if !strings.Contains(yaml, "version: \"3.8\"") {
		t.Error("missing version in output")
	}
	if !strings.Contains(yaml, "image: nginx:alpine") {
		t.Error("missing nginx:alpine image")
	}
	if !strings.Contains(yaml, "\"8080:80\"") {
		t.Error("missing port mapping")
	}
	if !strings.Contains(yaml, "image: postgres:16") {
		t.Error("missing postgres:16 image")
	}
	if !strings.Contains(yaml, "depends_on:") {
		t.Error("missing depends_on section")
	}
}

func TestGenerateCompose_PortConflicts(t *testing.T) {
	svc, _ := newService()

	services := []models.ManifestServiceBlock{
		{Name: "svc1", Image: "img1", Ports: []models.PortMapping{{Host: 8080, Container: 80}}},
		{Name: "svc2", Image: "img2", Ports: []models.PortMapping{{Host: 8080, Container: 3000}}},
	}

	_, errs := svc.GenerateCompose(services, json.RawMessage(`{}`), json.RawMessage(`{}`), "3.8")

	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "8080") && e.Severity == "error" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected port conflict error for port 8080")
	}
}

func TestValidateManifest(t *testing.T) {
	svc, _ := newService()

	// Valid manifest.
	validContent := "version: \"3.8\"\n\nservices:\n  web:\n    image: nginx\n"
	errs := svc.ValidateManifest(validContent, models.ManifestFormatCompose)
	for _, e := range errs {
		if e.Severity == "error" {
			t.Errorf("unexpected error on valid manifest: %s", e.Message)
		}
	}

	// Empty content.
	errs = svc.ValidateManifest("", models.ManifestFormatCompose)
	if len(errs) == 0 {
		t.Fatal("expected errors for empty manifest")
	}
	if errs[0].Field != "content" {
		t.Errorf("Field = %q, want %q", errs[0].Field, "content")
	}

	// Missing services section.
	noServices := "version: \"3.8\"\n"
	errs = svc.ValidateManifest(noServices, models.ManifestFormatCompose)
	found := false
	for _, e := range errs {
		if e.Field == "services" && e.Severity == "error" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected error about missing services section")
	}
}

func TestRenderTemplate(t *testing.T) {
	svc, repo := newService()
	ctx := context.Background()

	vars := []models.ManifestTemplateVariable{
		{Name: "AppPort", Type: "number", Default: "3000"},
		{Name: "AppImage", Type: "string", Default: "myapp:latest"},
	}
	varsJSON, _ := json.Marshal(vars)

	tmplID := uuid.New()
	repo.templates[tmplID] = &models.ManifestTemplate{
		ID:        tmplID,
		Name:      "test",
		Content:   "image: {{.AppImage}}\nports:\n  - \"{{.AppPort}}:80\"",
		Variables: varsJSON,
	}

	// Render with override.
	rendered, err := svc.RenderTemplate(ctx, tmplID, map[string]string{"AppPort": "9090"})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(rendered, "9090:80") {
		t.Error("expected overridden port 9090")
	}
	if !strings.Contains(rendered, "myapp:latest") {
		t.Error("expected default image from variable defaults")
	}

	// Verify usage count incremented.
	repo.mu.Lock()
	if repo.templates[tmplID].UsageCount != 1 {
		t.Errorf("UsageCount = %d, want 1", repo.templates[tmplID].UsageCount)
	}
	repo.mu.Unlock()
}

func TestSeedBuiltinTemplates(t *testing.T) {
	svc, repo := newService()
	ctx := context.Background()

	err := svc.SeedBuiltinTemplates(ctx)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	repo.mu.Lock()
	count := len(repo.templates)
	repo.mu.Unlock()

	if count == 0 {
		t.Fatal("expected builtin templates to be seeded")
	}
	if count < 4 {
		t.Errorf("seeded %d templates, expected at least 4", count)
	}
}
