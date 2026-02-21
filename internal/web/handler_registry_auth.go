// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"log/slog"
	"strings"

	"github.com/fr4nsys/usulnet/internal/models"
)

// resolveRegistryAuth looks up stored registry credentials that match the given
// image reference and returns a RegistryAuthConfig if found. Returns nil if no
// matching registry is found or if the registry has no credentials.
//
// Matching logic:
//  1. Parse the registry hostname from the image reference (e.g. "ghcr.io/org/image:tag" → "ghcr.io")
//  2. Compare against stored registry URLs
//  3. If no hostname prefix in the reference, try the default registry
func (h *Handler) resolveRegistryAuth(ctx context.Context, reference string) *models.RegistryAuthConfig {
	if h.registryRepo == nil {
		return nil
	}

	// List all registries
	registries, err := h.registryRepo.List(ctx)
	if err != nil {
		slog.Error("Failed to list registries for auth resolution", "error", err)
		return nil
	}
	if len(registries) == 0 {
		return nil
	}

	// Extract hostname from reference. Docker references can be:
	// - "nginx" (Docker Hub, no hostname)
	// - "library/nginx" (Docker Hub, no hostname)
	// - "ghcr.io/owner/image:tag" (custom registry)
	// - "registry.example.com:5000/image:tag" (custom registry with port)
	refHost := extractRegistryHost(reference)

	var matchedReg *models.Registry

	if refHost == "" {
		// No explicit host: try default registry or Docker Hub
		for _, reg := range registries {
			if reg.IsDefault {
				matchedReg = reg
				break
			}
			// Match Docker Hub URLs
			regHost := extractHostFromURL(reg.URL)
			if regHost == "registry-1.docker.io" || regHost == "docker.io" || regHost == "index.docker.io" {
				matchedReg = reg
				break
			}
		}
	} else {
		// Explicit host: find matching registry
		for _, reg := range registries {
			regHost := extractHostFromURL(reg.URL)
			if strings.EqualFold(regHost, refHost) {
				matchedReg = reg
				break
			}
		}
	}

	if matchedReg == nil {
		return nil
	}

	// Build auth config
	if matchedReg.Username == nil || *matchedReg.Username == "" {
		return nil // Anonymous registry
	}

	auth := &models.RegistryAuthConfig{
		Username:      *matchedReg.Username,
		ServerAddress: matchedReg.URL,
	}

	// Decrypt password if present
	if matchedReg.Password != nil && *matchedReg.Password != "" {
		if h.encryptor != nil {
			decrypted, err := h.encryptor.Decrypt(*matchedReg.Password)
			if err != nil {
				slog.Error("Failed to decrypt registry password",
					"registry", matchedReg.Name,
					"error", err,
				)
				return nil
			}
			auth.Password = decrypted
		} else {
			// No encryptor: use as-is (plain text fallback)
			auth.Password = *matchedReg.Password
		}
	}

	return auth
}

// extractRegistryHost extracts the registry hostname from a Docker image reference.
// Returns empty string for Docker Hub images (no explicit host).
func extractRegistryHost(reference string) string {
	// Remove tag/digest
	ref := reference
	if idx := strings.LastIndex(ref, "@"); idx != -1 {
		ref = ref[:idx]
	}
	if idx := strings.LastIndex(ref, ":"); idx != -1 {
		// Only strip tag if there's no "/" after the ":"
		afterColon := ref[idx+1:]
		if !strings.Contains(afterColon, "/") {
			ref = ref[:idx]
		}
	}

	// Split by "/"
	parts := strings.SplitN(ref, "/", 2)
	if len(parts) == 1 {
		// Single name like "nginx" → Docker Hub
		return ""
	}

	// Check if the first part looks like a hostname (contains "." or ":" or is "localhost")
	first := parts[0]
	if strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost" {
		return first
	}

	// "library/nginx" or "user/image" → Docker Hub
	return ""
}

// extractHostFromURL extracts the hostname from a URL like "https://registry.example.com/v2/"
func extractHostFromURL(rawURL string) string {
	// Strip scheme
	host := rawURL
	if idx := strings.Index(host, "://"); idx != -1 {
		host = host[idx+3:]
	}
	// Strip path
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	// Strip trailing port for comparison if it's standard
	return strings.TrimRight(host, "/")
}
