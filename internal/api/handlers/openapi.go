// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

import (
	"encoding/json"
	"net/http"
)

// OpenAPIHandler serves the OpenAPI 3.0 specification.
type OpenAPIHandler struct {
	version string
}

// NewOpenAPIHandler creates a new OpenAPI handler.
func NewOpenAPIHandler(version string) *OpenAPIHandler {
	return &OpenAPIHandler{version: version}
}

// Spec returns the OpenAPI 3.0 JSON specification.
func (h *OpenAPIHandler) Spec(w http.ResponseWriter, r *http.Request) {
	spec := h.buildSpec()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(spec)
}

func (h *OpenAPIHandler) buildSpec() map[string]any {
	return map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":       "usulnet API",
			"description": "Docker Management Platform REST API. Provides endpoints for managing containers, images, volumes, networks, stacks, hosts, backups, security scanning, and more.",
			"version":     h.version,
			"license": map[string]any{
				"name": "AGPL-3.0-or-later",
				"url":  "https://www.gnu.org/licenses/agpl-3.0.html",
			},
			"contact": map[string]any{
				"name": "usulnet",
				"url":  "https://github.com/fr4nsys/usulnet",
			},
		},
		"servers": []map[string]any{
			{"url": "/api/v1", "description": "API v1"},
		},
		"tags": h.buildTags(),
		"paths": h.buildPaths(),
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"bearerAuth": map[string]any{
					"type":         "http",
					"scheme":       "bearer",
					"bearerFormat": "JWT",
					"description":  "JWT token obtained from /api/v1/auth/login",
				},
				"apiKeyAuth": map[string]any{
					"type": "apiKey",
					"in":   "header",
					"name": "X-API-KEY",
					"description": "API key for programmatic access",
				},
			},
			"schemas": h.buildSchemas(),
		},
		"security": []map[string]any{
			{"bearerAuth": []string{}},
			{"apiKeyAuth": []string{}},
		},
	}
}

func (h *OpenAPIHandler) buildTags() []map[string]any {
	return []map[string]any{
		{"name": "Auth", "description": "Authentication and authorization"},
		{"name": "System", "description": "System information and health checks"},
		{"name": "Containers", "description": "Docker container management"},
		{"name": "Images", "description": "Docker image management"},
		{"name": "Volumes", "description": "Docker volume management"},
		{"name": "Networks", "description": "Docker network management"},
		{"name": "Stacks", "description": "Docker Compose stack management"},
		{"name": "Hosts", "description": "Host/node management"},
		{"name": "Backups", "description": "Backup and restore operations"},
		{"name": "Security", "description": "Security scanning and vulnerability management"},
		{"name": "Config", "description": "Configuration variable management"},
		{"name": "ConfigSync", "description": "Configuration synchronization to containers"},
		{"name": "Settings", "description": "Application settings management (admin)"},
		{"name": "LDAP", "description": "LDAP authentication settings (Business+)"},
		{"name": "License", "description": "License management (admin)"},
		{"name": "Updates", "description": "Container image update management"},
		{"name": "Jobs", "description": "Background job management"},
		{"name": "Notifications", "description": "Notification management"},
		{"name": "Users", "description": "User management (admin)"},
		{"name": "Proxy", "description": "Reverse proxy management"},
		{"name": "SSH", "description": "SSH connection management"},
		{"name": "Registries", "description": "Container registry management"},
		{"name": "Webhooks", "description": "Outgoing webhook management"},
		{"name": "Runbooks", "description": "Operational runbook management"},
		{"name": "Alerts", "description": "Alert rule and event management"},
	}
}

func (h *OpenAPIHandler) buildPaths() map[string]any {
	paths := map[string]any{
		// Auth
		"/auth/login": map[string]any{
			"post": op("Auth", "Login", "Authenticate with username and password", http.StatusOK),
		},
		"/auth/refresh": map[string]any{
			"post": op("Auth", "RefreshToken", "Refresh an expired JWT token", http.StatusOK),
		},
		"/auth/logout": map[string]any{
			"post": op("Auth", "Logout", "Invalidate the current session", http.StatusNoContent),
		},

		// System
		"/system/info": map[string]any{
			"get": op("System", "GetSystemInfo", "Get system information including Docker engine details", http.StatusOK),
		},
		"/system/version": map[string]any{
			"get": op("System", "GetVersion", "Get the API and application version", http.StatusOK),
		},

		// Containers
		"/containers": map[string]any{
			"get": op("Containers", "ListContainers", "List all containers with optional filters", http.StatusOK),
		},
		"/containers/{id}": map[string]any{
			"get":    op("Containers", "GetContainer", "Get detailed container information", http.StatusOK),
			"delete": op("Containers", "RemoveContainer", "Remove a container", http.StatusNoContent),
		},
		"/containers/{id}/start": map[string]any{
			"post": op("Containers", "StartContainer", "Start a stopped container", http.StatusNoContent),
		},
		"/containers/{id}/stop": map[string]any{
			"post": op("Containers", "StopContainer", "Stop a running container", http.StatusNoContent),
		},
		"/containers/{id}/restart": map[string]any{
			"post": op("Containers", "RestartContainer", "Restart a container", http.StatusNoContent),
		},
		"/containers/{id}/logs": map[string]any{
			"get": op("Containers", "GetContainerLogs", "Get container log output", http.StatusOK),
		},
		"/containers/{id}/stats": map[string]any{
			"get": op("Containers", "GetContainerStats", "Get container resource usage statistics", http.StatusOK),
		},

		// Images
		"/images": map[string]any{
			"get": op("Images", "ListImages", "List all Docker images", http.StatusOK),
		},
		"/images/{id}": map[string]any{
			"get":    op("Images", "GetImage", "Get image details and history", http.StatusOK),
			"delete": op("Images", "RemoveImage", "Remove a Docker image", http.StatusNoContent),
		},
		"/images/pull": map[string]any{
			"post": op("Images", "PullImage", "Pull an image from a registry", http.StatusOK),
		},

		// Volumes
		"/volumes": map[string]any{
			"get":  op("Volumes", "ListVolumes", "List all Docker volumes", http.StatusOK),
			"post": op("Volumes", "CreateVolume", "Create a new Docker volume", http.StatusCreated),
		},
		"/volumes/{name}": map[string]any{
			"get":    op("Volumes", "GetVolume", "Get volume details", http.StatusOK),
			"delete": op("Volumes", "RemoveVolume", "Remove a Docker volume", http.StatusNoContent),
		},

		// Networks
		"/networks": map[string]any{
			"get":  op("Networks", "ListNetworks", "List all Docker networks", http.StatusOK),
			"post": op("Networks", "CreateNetwork", "Create a new Docker network", http.StatusCreated),
		},
		"/networks/{id}": map[string]any{
			"get":    op("Networks", "GetNetwork", "Get network details", http.StatusOK),
			"delete": op("Networks", "RemoveNetwork", "Remove a Docker network", http.StatusNoContent),
		},

		// Stacks
		"/stacks": map[string]any{
			"get": op("Stacks", "ListStacks", "List all Docker Compose stacks", http.StatusOK),
		},
		"/stacks/{name}": map[string]any{
			"get":    op("Stacks", "GetStack", "Get stack details and services", http.StatusOK),
			"delete": op("Stacks", "RemoveStack", "Remove a stack and its resources", http.StatusNoContent),
		},
		"/stacks/deploy": map[string]any{
			"post": op("Stacks", "DeployStack", "Deploy a Docker Compose stack", http.StatusOK),
		},

		// Hosts
		"/hosts": map[string]any{
			"get":  op("Hosts", "ListHosts", "List all managed hosts/nodes", http.StatusOK),
			"post": op("Hosts", "CreateHost", "Add a new host to manage", http.StatusCreated),
		},
		"/hosts/{id}": map[string]any{
			"get":    op("Hosts", "GetHost", "Get host details and status", http.StatusOK),
			"put":    op("Hosts", "UpdateHost", "Update host configuration", http.StatusOK),
			"delete": op("Hosts", "RemoveHost", "Remove a managed host", http.StatusNoContent),
		},

		// Backups
		"/backups": map[string]any{
			"get":  op("Backups", "ListBackups", "List all backups", http.StatusOK),
			"post": op("Backups", "CreateBackup", "Create a new backup", http.StatusCreated),
		},
		"/backups/{id}": map[string]any{
			"get":    op("Backups", "GetBackup", "Get backup details", http.StatusOK),
			"delete": op("Backups", "DeleteBackup", "Delete a backup", http.StatusNoContent),
		},
		"/backups/{id}/restore": map[string]any{
			"post": op("Backups", "RestoreBackup", "Restore from a backup", http.StatusOK),
		},

		// Security
		"/security/scan": map[string]any{
			"post": op("Security", "ScanAll", "Trigger a security scan of all containers", http.StatusOK),
		},
		"/security/scan/{id}": map[string]any{
			"post": op("Security", "ScanContainer", "Scan a specific container for vulnerabilities", http.StatusOK),
		},

		// Config
		"/config/variables": map[string]any{
			"get":  op("Config", "ListVariables", "List all configuration variables", http.StatusOK),
			"post": op("Config", "CreateVariable", "Create a new configuration variable", http.StatusCreated),
		},
		"/config/variables/{id}": map[string]any{
			"get":    op("Config", "GetVariable", "Get a configuration variable by ID", http.StatusOK),
			"put":    op("Config", "UpdateVariable", "Update a configuration variable", http.StatusOK),
			"delete": op("Config", "DeleteVariable", "Delete a configuration variable", http.StatusNoContent),
		},
		"/config/variables/{id}/usage": map[string]any{
			"get": op("Config", "GetVariableUsage", "Get where a variable is used", http.StatusOK),
		},
		"/config/variables/{id}/history": map[string]any{
			"get": op("Config", "GetVariableHistory", "Get variable change history", http.StatusOK),
		},

		// Config Sync
		"/config/sync": map[string]any{
			"post": op("ConfigSync", "SyncConfig", "Synchronize configuration to a container", http.StatusOK),
		},
		"/config/sync/preview": map[string]any{
			"post": op("ConfigSync", "PreviewSync", "Preview config changes before syncing", http.StatusOK),
		},
		"/config/sync/bulk": map[string]any{
			"post": op("ConfigSync", "BulkSyncConfig", "Synchronize configuration to multiple containers", http.StatusOK),
		},
		"/config/sync/outdated": map[string]any{
			"get": op("ConfigSync", "ListOutdatedSyncs", "List containers with outdated configuration", http.StatusOK),
		},
		"/config/sync/stats": map[string]any{
			"get": op("ConfigSync", "GetSyncStats", "Get configuration sync statistics", http.StatusOK),
		},
		"/config/sync/{hostID}/{containerID}": map[string]any{
			"get":    op("ConfigSync", "GetSyncStatus", "Get sync status for a container", http.StatusOK),
			"delete": op("ConfigSync", "RemoveSync", "Remove sync tracking for a container", http.StatusNoContent),
		},

		// Settings (admin)
		"/settings": map[string]any{
			"get": op("Settings", "GetSettings", "Get application settings (admin only)", http.StatusOK),
			"put": op("Settings", "UpdateSettings", "Update application settings (admin only)", http.StatusOK),
		},

		// LDAP Settings (Business+)
		"/settings/ldap": map[string]any{
			"get": op("LDAP", "GetLDAPSettings", "Get LDAP configurations (Business+)", http.StatusOK),
			"put": op("LDAP", "UpdateLDAPSettings", "Create or update LDAP configuration (Business+)", http.StatusOK),
		},
		"/settings/ldap/test": map[string]any{
			"post": op("LDAP", "TestLDAPConnection", "Test LDAP connection with provided parameters (Business+)", http.StatusOK),
		},

		// License (admin)
		"/license": map[string]any{
			"get":    op("License", "GetLicense", "Get current license information (admin only)", http.StatusOK),
			"post":   op("License", "ActivateLicense", "Activate a license key (admin only)", http.StatusOK),
			"delete": op("License", "DeactivateLicense", "Deactivate license and revert to CE (admin only)", http.StatusOK),
		},

		// Updates
		"/updates": map[string]any{
			"get": op("Updates", "ListUpdates", "List available image updates", http.StatusOK),
		},
		"/updates/check": map[string]any{
			"post": op("Updates", "CheckUpdates", "Check for new image updates", http.StatusOK),
		},

		// Jobs
		"/jobs": map[string]any{
			"get": op("Jobs", "ListJobs", "List background jobs", http.StatusOK),
		},
		"/jobs/{id}": map[string]any{
			"get": op("Jobs", "GetJob", "Get job details and progress", http.StatusOK),
		},

		// Notifications
		"/notifications": map[string]any{
			"get": op("Notifications", "ListNotifications", "List notifications for the current user", http.StatusOK),
		},

		// Users (admin)
		"/users": map[string]any{
			"get":  op("Users", "ListUsers", "List all users (admin only)", http.StatusOK),
			"post": op("Users", "CreateUser", "Create a new user (admin only)", http.StatusCreated),
		},
		"/users/{id}": map[string]any{
			"get":    op("Users", "GetUser", "Get user details (admin only)", http.StatusOK),
			"put":    op("Users", "UpdateUser", "Update user details (admin only)", http.StatusOK),
			"delete": op("Users", "DeleteUser", "Delete a user (admin only)", http.StatusNoContent),
		},

		// SSH
		"/ssh/connections": map[string]any{
			"get":  op("SSH", "ListConnections", "List SSH connections", http.StatusOK),
			"post": op("SSH", "CreateConnection", "Create an SSH connection", http.StatusCreated),
		},

		// Health (public)
		"/health": map[string]any{
			"get": map[string]any{
				"tags":        []string{"System"},
				"operationId": "HealthCheck",
				"summary":     "Health check endpoint",
				"security":    []map[string]any{},
				"responses": map[string]any{
					"200": map[string]any{"description": "Service is healthy"},
				},
			},
		},
	}
	return paths
}

func (h *OpenAPIHandler) buildSchemas() map[string]any {
	return map[string]any{
		"Error": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"success": map[string]any{"type": "boolean", "example": false},
				"error": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"code":    map[string]any{"type": "string"},
						"message": map[string]any{"type": "string"},
					},
				},
			},
		},
		"Container": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":      map[string]any{"type": "string"},
				"name":    map[string]any{"type": "string"},
				"image":   map[string]any{"type": "string"},
				"state":   map[string]any{"type": "string", "enum": []string{"running", "stopped", "paused", "restarting", "dead"}},
				"status":  map[string]any{"type": "string"},
				"created": map[string]any{"type": "string", "format": "date-time"},
			},
		},
		"Image": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":       map[string]any{"type": "string"},
				"tags":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"size":     map[string]any{"type": "integer", "format": "int64"},
				"created":  map[string]any{"type": "string", "format": "date-time"},
			},
		},
		"Volume": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name":       map[string]any{"type": "string"},
				"driver":     map[string]any{"type": "string"},
				"mountpoint": map[string]any{"type": "string"},
				"created":    map[string]any{"type": "string", "format": "date-time"},
			},
		},
		"Network": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":     map[string]any{"type": "string"},
				"name":   map[string]any{"type": "string"},
				"driver": map[string]any{"type": "string"},
				"scope":  map[string]any{"type": "string"},
			},
		},
		"Stack": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name":     map[string]any{"type": "string"},
				"services": map[string]any{"type": "integer"},
				"status":   map[string]any{"type": "string"},
			},
		},
		"Host": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":     map[string]any{"type": "string", "format": "uuid"},
				"name":   map[string]any{"type": "string"},
				"url":    map[string]any{"type": "string"},
				"status": map[string]any{"type": "string"},
			},
		},
		"Settings": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"general": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"app_name":            map[string]any{"type": "string"},
						"app_url":             map[string]any{"type": "string"},
						"session_ttl_minutes": map[string]any{"type": "integer"},
						"enable_signup":       map[string]any{"type": "boolean"},
						"default_role":        map[string]any{"type": "string", "enum": []string{"viewer", "operator", "admin"}},
					},
				},
				"security": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"password_min_length":      map[string]any{"type": "integer"},
						"require_uppercase":        map[string]any{"type": "boolean"},
						"require_lowercase":        map[string]any{"type": "boolean"},
						"require_numbers":          map[string]any{"type": "boolean"},
						"require_special":          map[string]any{"type": "boolean"},
						"max_login_attempts":       map[string]any{"type": "integer"},
						"lockout_duration_minutes": map[string]any{"type": "integer"},
					},
				},
				"ui": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"theme":             map[string]any{"type": "string", "enum": []string{"light", "dark", "system"}},
						"items_per_page":    map[string]any{"type": "integer"},
						"date_format":       map[string]any{"type": "string"},
						"enable_animations": map[string]any{"type": "boolean"},
					},
				},
			},
		},
		"LDAPConfig": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":              map[string]any{"type": "string", "format": "uuid"},
				"name":            map[string]any{"type": "string"},
				"host":            map[string]any{"type": "string"},
				"port":            map[string]any{"type": "integer"},
				"use_tls":         map[string]any{"type": "boolean"},
				"start_tls":       map[string]any{"type": "boolean"},
				"skip_tls_verify": map[string]any{"type": "boolean"},
				"bind_dn":         map[string]any{"type": "string"},
				"base_dn":         map[string]any{"type": "string"},
				"user_filter":     map[string]any{"type": "string"},
				"username_attr":   map[string]any{"type": "string"},
				"email_attr":      map[string]any{"type": "string"},
				"default_role":    map[string]any{"type": "string"},
				"is_enabled":      map[string]any{"type": "boolean"},
			},
		},
		"LicenseInfo": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"edition":      map[string]any{"type": "string", "enum": []string{"ce", "biz", "ee"}},
				"edition_name": map[string]any{"type": "string"},
				"valid":        map[string]any{"type": "boolean"},
				"license_id":   map[string]any{"type": "string"},
				"expires_at":   map[string]any{"type": "string", "format": "date-time"},
				"features":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"limits": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"max_nodes":                map[string]any{"type": "integer"},
						"max_users":                map[string]any{"type": "integer"},
						"max_teams":                map[string]any{"type": "integer"},
						"max_api_keys":             map[string]any{"type": "integer"},
						"max_ldap_servers":         map[string]any{"type": "integer"},
						"max_backup_destinations":  map[string]any{"type": "integer"},
					},
				},
				"instance_id": map[string]any{"type": "string"},
			},
		},
		"ConfigSync": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"container_id":   map[string]any{"type": "string"},
				"container_name": map[string]any{"type": "string"},
				"template_name":  map[string]any{"type": "string"},
				"status":         map[string]any{"type": "string", "enum": []string{"pending", "synced", "failed", "outdated"}},
				"variables_hash": map[string]any{"type": "string"},
				"synced_at":      map[string]any{"type": "string", "format": "date-time"},
			},
		},
		"LoginRequest": map[string]any{
			"type":     "object",
			"required": []string{"username", "password"},
			"properties": map[string]any{
				"username": map[string]any{"type": "string"},
				"password": map[string]any{"type": "string", "format": "password"},
			},
		},
		"LoginResponse": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"success": map[string]any{"type": "boolean"},
				"data": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"token":      map[string]any{"type": "string"},
						"expires_at": map[string]any{"type": "string", "format": "date-time"},
					},
				},
			},
		},
	}
}

// op creates a standard operation definition.
func op(tag, opID, summary string, statusCode int) map[string]any {
	resp := map[string]any{
		"description": "Successful response",
	}
	responses := map[string]any{
		http.StatusText(statusCode): resp,
		"401": map[string]any{"description": "Unauthorized"},
		"500": map[string]any{"description": "Internal server error"},
	}

	return map[string]any{
		"tags":        []string{tag},
		"operationId": opID,
		"summary":     summary,
		"responses":   responses,
	}
}
