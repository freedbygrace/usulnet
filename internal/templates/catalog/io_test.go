// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package catalog

import (
	"encoding/json"
	"testing"

	"github.com/fr4nsys/usulnet/internal/models"
)

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

func TestExport_RoundTrip(t *testing.T) {
	templates := []models.CatalogTemplate{
		{
			ID:            "test-app",
			Name:          "Test App",
			Description:   "A test application",
			Category:      "testing",
			Platform:      "linux",
			Type:          "container",
			Image:         "testapp:latest",
			Ports:         []string{"8080/tcp"},
			RestartPolicy: "unless-stopped",
		},
	}

	data, err := Export(templates)
	if err != nil {
		t.Fatalf("Export() error: %v", err)
	}

	// Parse back
	var ef ExportFormat
	if err := json.Unmarshal(data, &ef); err != nil {
		t.Fatalf("unmarshal export: %v", err)
	}
	if ef.Version != 1 {
		t.Errorf("version = %d, want 1", ef.Version)
	}
	if ef.Source != "usulnet" {
		t.Errorf("source = %q, want usulnet", ef.Source)
	}
	if len(ef.Templates) != 1 {
		t.Fatalf("templates = %d, want 1", len(ef.Templates))
	}
	if ef.Templates[0].Name != "Test App" {
		t.Errorf("name = %q, want Test App", ef.Templates[0].Name)
	}
}

func TestExportByID(t *testing.T) {
	data, err := ExportByID("postgresql")
	if err != nil {
		t.Fatalf("ExportByID() error: %v", err)
	}

	var ef ExportFormat
	if err := json.Unmarshal(data, &ef); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(ef.Templates) != 1 {
		t.Fatalf("templates = %d, want 1", len(ef.Templates))
	}
	if ef.Templates[0].Name != "PostgreSQL" {
		t.Errorf("name = %q, want PostgreSQL", ef.Templates[0].Name)
	}
}

func TestExportByID_NotFound(t *testing.T) {
	_, err := ExportByID("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent ID")
	}
}

func TestExportByCategory(t *testing.T) {
	data, err := ExportByCategory("databases")
	if err != nil {
		t.Fatalf("ExportByCategory() error: %v", err)
	}

	var ef ExportFormat
	if err := json.Unmarshal(data, &ef); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(ef.Templates) < 6 {
		t.Errorf("templates = %d, want at least 6", len(ef.Templates))
	}
}

func TestExportByCategory_NotFound(t *testing.T) {
	_, err := ExportByCategory("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent category")
	}
}

func TestExportAll(t *testing.T) {
	data, err := ExportAll()
	if err != nil {
		t.Fatalf("ExportAll() error: %v", err)
	}

	var ef ExportFormat
	if err := json.Unmarshal(data, &ef); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(ef.Templates) < 60 {
		t.Errorf("templates = %d, want at least 60", len(ef.Templates))
	}
}

// ---------------------------------------------------------------------------
// Import: native format
// ---------------------------------------------------------------------------

func TestImport_NativeFormat(t *testing.T) {
	input := ExportFormat{
		Version: 1,
		Source:  "usulnet",
		Templates: []models.CatalogTemplate{
			{Name: "MyApp", Image: "myapp:1.0", Description: "My app"},
		},
	}
	data, _ := json.Marshal(input)

	result, err := Import(data)
	if err != nil {
		t.Fatalf("Import() error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("imported %d, want 1", len(result))
	}
	if result[0].Name != "MyApp" {
		t.Errorf("name = %q, want MyApp", result[0].Name)
	}
	// Defaults applied
	if result[0].Platform != "linux" {
		t.Errorf("platform = %q, want linux", result[0].Platform)
	}
	if result[0].Type != "container" {
		t.Errorf("type = %q, want container", result[0].Type)
	}
}

func TestImport_NativeFormat_RoundTrip(t *testing.T) {
	exported, err := ExportByID("redis")
	if err != nil {
		t.Fatalf("ExportByID() error: %v", err)
	}

	imported, err := Import(exported)
	if err != nil {
		t.Fatalf("Import() error: %v", err)
	}
	if len(imported) != 1 {
		t.Fatalf("imported %d, want 1", len(imported))
	}
	if imported[0].Name != "Redis" {
		t.Errorf("name = %q, want Redis", imported[0].Name)
	}
}

// ---------------------------------------------------------------------------
// Import: CatalogFile format
// ---------------------------------------------------------------------------

func TestImport_CatalogFileFormat(t *testing.T) {
	input := models.CatalogFile{
		Templates: []models.CatalogTemplate{
			{Name: "TestDB", Image: "testdb:1", Description: "Test DB"},
			{Name: "TestCache", Image: "testcache:1", Description: "Test cache"},
		},
	}
	data, _ := json.Marshal(input)

	result, err := Import(data)
	if err != nil {
		t.Fatalf("Import() error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("imported %d, want 2", len(result))
	}
}

// ---------------------------------------------------------------------------
// Import: Portainer v2 format
// ---------------------------------------------------------------------------

func TestImport_PortainerFormat(t *testing.T) {
	portainer := `[
		{
			"type": 1,
			"title": "Nginx",
			"description": "High performance web server",
			"categories": ["webserver"],
			"platform": "linux",
			"logo": "https://example.com/nginx.png",
			"image": "nginx:latest",
			"ports": ["80/tcp", "443/tcp"],
			"volumes": [{"container": "/etc/nginx", "readonly": true}],
			"env": [
				{"name": "NGINX_HOST", "label": "Hostname", "default": "localhost"}
			],
			"restart_policy": "always"
		},
		{
			"type": 3,
			"title": "WordPress Stack",
			"description": "WordPress with MySQL",
			"categories": ["CMS"],
			"platform": "linux",
			"repository": {
				"url": "https://github.com/example/wp",
				"stackfile": "docker-compose.yml"
			}
		}
	]`

	result, err := Import([]byte(portainer))
	if err != nil {
		t.Fatalf("Import() error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("imported %d, want 2", len(result))
	}

	// Container template
	nginx := result[0]
	if nginx.Name != "Nginx" {
		t.Errorf("name = %q, want Nginx", nginx.Name)
	}
	if nginx.Type != "container" {
		t.Errorf("type = %q, want container", nginx.Type)
	}
	if nginx.Image != "nginx:latest" {
		t.Errorf("image = %q, want nginx:latest", nginx.Image)
	}
	if nginx.Category != "webserver" {
		t.Errorf("category = %q, want webserver", nginx.Category)
	}
	if nginx.RestartPolicy != "always" {
		t.Errorf("restart = %q, want always", nginx.RestartPolicy)
	}
	if len(nginx.Ports) != 2 {
		t.Errorf("ports = %d, want 2", len(nginx.Ports))
	}
	if len(nginx.Volumes) != 1 || !nginx.Volumes[0].ReadOnly {
		t.Error("volume readonly not preserved")
	}
	if len(nginx.Env) != 1 || nginx.Env[0].Name != "NGINX_HOST" {
		t.Error("env not imported correctly")
	}

	// Stack template
	wp := result[1]
	if wp.Type != "stack" {
		t.Errorf("type = %q, want stack", wp.Type)
	}
	if wp.Category != "cms" {
		t.Errorf("category = %q, want cms", wp.Category)
	}
}

func TestImport_PortainerFormat_SelectEnv(t *testing.T) {
	portainer := `[{
		"type": 1,
		"title": "TestSelect",
		"image": "test:1",
		"env": [{
			"name": "MODE",
			"label": "Run mode",
			"select": [
				{"text": "Production", "value": "prod", "default": true},
				{"text": "Development", "value": "dev"}
			]
		}]
	}]`

	result, err := Import([]byte(portainer))
	if err != nil {
		t.Fatalf("Import() error: %v", err)
	}
	if len(result[0].Env) != 1 {
		t.Fatalf("env count = %d, want 1", len(result[0].Env))
	}
	env := result[0].Env[0]
	if env.Type != "select" {
		t.Errorf("env type = %q, want select", env.Type)
	}
	if len(env.Options) != 2 {
		t.Errorf("options = %d, want 2", len(env.Options))
	}
	if env.Default != "prod" {
		t.Errorf("default = %q, want prod", env.Default)
	}
}

// ---------------------------------------------------------------------------
// Import: error cases
// ---------------------------------------------------------------------------

func TestImport_EmptyData(t *testing.T) {
	_, err := Import([]byte(""))
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestImport_InvalidJSON(t *testing.T) {
	_, err := Import([]byte("{not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestImport_EmptyTemplates(t *testing.T) {
	_, err := Import([]byte(`{"templates": []}`))
	if err == nil {
		t.Fatal("expected error for empty templates")
	}
}

func TestImport_OnlyNamelessEntries(t *testing.T) {
	_, err := Import([]byte(`{"version": 1, "templates": [{"image": "foo"}]}`))
	if err == nil {
		t.Fatal("expected error when all templates have no name")
	}
}
