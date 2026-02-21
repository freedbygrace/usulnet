// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package catalog provides an embedded app template catalog.
// Templates are compiled into the binary via go:embed and available
// at startup without any external dependencies or network access.
package catalog

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"

	"github.com/fr4nsys/usulnet/internal/models"
)

//go:embed embedded/*.json
var embeddedFS embed.FS

var (
	once      sync.Once
	templates []models.CatalogTemplate
	loadErr   error
)

// Load returns all embedded catalog templates, sorted by category then name.
// Results are cached after the first call.
func Load() ([]models.CatalogTemplate, error) {
	once.Do(func() {
		templates, loadErr = loadAll()
	})
	if loadErr != nil {
		return nil, loadErr
	}
	// Return a copy to prevent mutation.
	out := make([]models.CatalogTemplate, len(templates))
	copy(out, templates)
	return out, nil
}

// Categories returns the list of distinct category names.
func Categories() ([]string, error) {
	all, err := Load()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	var cats []string
	for _, t := range all {
		if _, ok := seen[t.Category]; !ok {
			seen[t.Category] = struct{}{}
			cats = append(cats, t.Category)
		}
	}
	sort.Strings(cats)
	return cats, nil
}

// ByCategory returns templates filtered by category.
func ByCategory(category string) ([]models.CatalogTemplate, error) {
	all, err := Load()
	if err != nil {
		return nil, err
	}
	var result []models.CatalogTemplate
	for _, t := range all {
		if t.Category == category {
			result = append(result, t)
		}
	}
	return result, nil
}

// ByID returns a single template by its ID.
func ByID(id string) (*models.CatalogTemplate, error) {
	all, err := Load()
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].ID == id {
			return &all[i], nil
		}
	}
	return nil, fmt.Errorf("catalog template %q not found", id)
}

// Search returns templates matching the query string in name or description.
func Search(query string) ([]models.CatalogTemplate, error) {
	all, err := Load()
	if err != nil {
		return nil, err
	}
	q := strings.ToLower(query)
	var result []models.CatalogTemplate
	for _, t := range all {
		if strings.Contains(strings.ToLower(t.Name), q) ||
			strings.Contains(strings.ToLower(t.Description), q) ||
			strings.Contains(strings.ToLower(t.Category), q) {
			result = append(result, t)
		}
	}
	return result, nil
}

// Count returns the total number of templates in the catalog.
func Count() (int, error) {
	all, err := Load()
	if err != nil {
		return 0, err
	}
	return len(all), nil
}

func loadAll() ([]models.CatalogTemplate, error) {
	var all []models.CatalogTemplate

	entries, err := fs.ReadDir(embeddedFS, "embedded")
	if err != nil {
		return nil, fmt.Errorf("read embedded catalog dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		data, err := embeddedFS.ReadFile("embedded/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", entry.Name(), err)
		}

		var file models.CatalogFile
		if err := json.Unmarshal(data, &file); err != nil {
			return nil, fmt.Errorf("parse %s: %w", entry.Name(), err)
		}

		// Assign IDs if missing, default platform and restart policy.
		category := strings.TrimSuffix(entry.Name(), ".json")
		for i := range file.Templates {
			t := &file.Templates[i]
			if t.ID == "" {
				t.ID = strings.ToLower(strings.ReplaceAll(t.Name, " ", "-"))
			}
			if t.Category == "" {
				t.Category = category
			}
			if t.Platform == "" {
				t.Platform = "linux"
			}
			if t.Type == "" {
				t.Type = "container"
			}
			if t.RestartPolicy == "" {
				t.RestartPolicy = "unless-stopped"
			}
		}

		all = append(all, file.Templates...)
	}

	// Sort by category, then name.
	sort.Slice(all, func(i, j int) bool {
		if all[i].Category != all[j].Category {
			return all[i].Category < all[j].Category
		}
		return all[i].Name < all[j].Name
	})

	return all, nil
}
