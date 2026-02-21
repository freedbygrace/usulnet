// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package catalog

import (
	"testing"
)

func TestLoad_ReturnsTemplates(t *testing.T) {
	templates, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(templates) < 60 {
		t.Errorf("Load() returned %d templates, want at least 60", len(templates))
	}
}

func TestLoad_AllTemplatesHaveRequiredFields(t *testing.T) {
	templates, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	for _, tmpl := range templates {
		if tmpl.ID == "" {
			t.Errorf("template %q has empty ID", tmpl.Name)
		}
		if tmpl.Name == "" {
			t.Error("template has empty Name")
		}
		if tmpl.Description == "" {
			t.Errorf("template %q has empty Description", tmpl.Name)
		}
		if tmpl.Category == "" {
			t.Errorf("template %q has empty Category", tmpl.Name)
		}
		if tmpl.Platform == "" {
			t.Errorf("template %q has empty Platform", tmpl.Name)
		}
		if tmpl.Type != "container" && tmpl.Type != "stack" {
			t.Errorf("template %q has invalid Type %q", tmpl.Name, tmpl.Type)
		}
		if tmpl.Type == "container" && tmpl.Image == "" {
			t.Errorf("container template %q has empty Image", tmpl.Name)
		}
		if tmpl.RestartPolicy == "" {
			t.Errorf("template %q has empty RestartPolicy", tmpl.Name)
		}
	}
}

func TestLoad_NoDuplicateIDs(t *testing.T) {
	templates, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	seen := make(map[string]string)
	for _, tmpl := range templates {
		if prev, exists := seen[tmpl.ID]; exists {
			t.Errorf("duplicate ID %q: %q and %q", tmpl.ID, prev, tmpl.Name)
		}
		seen[tmpl.ID] = tmpl.Name
	}
}

func TestLoad_SortedByCategoryThenName(t *testing.T) {
	templates, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	for i := 1; i < len(templates); i++ {
		prev := templates[i-1]
		curr := templates[i]
		if prev.Category > curr.Category {
			t.Errorf("templates not sorted by category: %q (%s) before %q (%s)",
				prev.Name, prev.Category, curr.Name, curr.Category)
		}
		if prev.Category == curr.Category && prev.Name > curr.Name {
			t.Errorf("templates not sorted by name within %s: %q before %q",
				prev.Category, prev.Name, curr.Name)
		}
	}
}

func TestLoad_IsCached(t *testing.T) {
	t1, err1 := Load()
	t2, err2 := Load()
	if err1 != nil || err2 != nil {
		t.Fatalf("Load() errors: %v, %v", err1, err2)
	}
	if len(t1) != len(t2) {
		t.Errorf("cached Load() returned different lengths: %d vs %d", len(t1), len(t2))
	}
}

func TestCategories(t *testing.T) {
	cats, err := Categories()
	if err != nil {
		t.Fatalf("Categories() error: %v", err)
	}
	if len(cats) < 10 {
		t.Errorf("Categories() returned %d categories, want at least 10", len(cats))
	}
	// Check sorted order
	for i := 1; i < len(cats); i++ {
		if cats[i-1] >= cats[i] {
			t.Errorf("categories not sorted: %q >= %q", cats[i-1], cats[i])
		}
	}
}

func TestByCategory_Databases(t *testing.T) {
	templates, err := ByCategory("databases")
	if err != nil {
		t.Fatalf("ByCategory() error: %v", err)
	}
	if len(templates) < 6 {
		t.Errorf("databases category has %d templates, want at least 6", len(templates))
	}
	for _, tmpl := range templates {
		if tmpl.Category != "databases" {
			t.Errorf("template %q has category %q, want databases", tmpl.Name, tmpl.Category)
		}
	}
}

func TestByCategory_NonExistent(t *testing.T) {
	templates, err := ByCategory("nonexistent")
	if err != nil {
		t.Fatalf("ByCategory() error: %v", err)
	}
	if len(templates) != 0 {
		t.Errorf("nonexistent category returned %d templates, want 0", len(templates))
	}
}

func TestByID_Found(t *testing.T) {
	tmpl, err := ByID("postgresql")
	if err != nil {
		t.Fatalf("ByID() error: %v", err)
	}
	if tmpl.Name != "PostgreSQL" {
		t.Errorf("ByID('postgresql') name = %q, want PostgreSQL", tmpl.Name)
	}
}

func TestByID_NotFound(t *testing.T) {
	_, err := ByID("nonexistent-id")
	if err == nil {
		t.Fatal("ByID() expected error for nonexistent ID")
	}
}

func TestSearch_ByName(t *testing.T) {
	results, err := Search("postgres")
	if err != nil {
		t.Fatalf("Search() error: %v", err)
	}
	if len(results) < 1 {
		t.Fatal("Search('postgres') returned 0 results")
	}
	found := false
	for _, r := range results {
		if r.ID == "postgresql" {
			found = true
		}
	}
	if !found {
		t.Error("Search('postgres') did not include PostgreSQL")
	}
}

func TestSearch_ByCategory(t *testing.T) {
	results, err := Search("monitoring")
	if err != nil {
		t.Fatalf("Search() error: %v", err)
	}
	if len(results) < 5 {
		t.Errorf("Search('monitoring') returned %d results, want at least 5", len(results))
	}
}

func TestSearch_CaseInsensitive(t *testing.T) {
	r1, _ := Search("REDIS")
	r2, _ := Search("redis")
	if len(r1) != len(r2) {
		t.Errorf("case-insensitive search mismatch: %d vs %d", len(r1), len(r2))
	}
}

func TestSearch_NoResults(t *testing.T) {
	results, err := Search("zzzzznonexistent")
	if err != nil {
		t.Fatalf("Search() error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestCount(t *testing.T) {
	count, err := Count()
	if err != nil {
		t.Fatalf("Count() error: %v", err)
	}
	if count < 60 {
		t.Errorf("Count() = %d, want at least 60", count)
	}
}
