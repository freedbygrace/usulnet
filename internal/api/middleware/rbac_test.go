// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ============================================================================
// HasMinRole tests
// ============================================================================

func TestHasMinRole(t *testing.T) {
	tests := []struct {
		name     string
		userRole string
		minRole  Role
		want     bool
	}{
		// Admin can access everything
		{"admin meets admin", "admin", RoleAdmin, true},
		{"admin meets operator", "admin", RoleOperator, true},
		{"admin meets viewer", "admin", RoleViewer, true},
		// Operator can access operator and viewer
		{"operator meets operator", "operator", RoleOperator, true},
		{"operator meets viewer", "operator", RoleViewer, true},
		{"operator denied admin", "operator", RoleAdmin, false},
		// Viewer can only access viewer
		{"viewer meets viewer", "viewer", RoleViewer, true},
		{"viewer denied operator", "viewer", RoleOperator, false},
		{"viewer denied admin", "viewer", RoleAdmin, false},
		// Unknown role denied
		{"unknown role denied admin", "unknown", RoleAdmin, false},
		{"unknown role denied viewer", "unknown", RoleViewer, false},
		{"empty role denied", "", RoleViewer, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasMinRole(tt.userRole, tt.minRole)
			if got != tt.want {
				t.Errorf("HasMinRole(%q, %q) = %v, want %v", tt.userRole, tt.minRole, got, tt.want)
			}
		})
	}
}

// ============================================================================
// IsAdmin tests
// ============================================================================

func TestIsAdmin(t *testing.T) {
	tests := []struct {
		name     string
		userRole string
		want     bool
	}{
		{"admin is admin", "admin", true},
		{"operator is not admin", "operator", false},
		{"viewer is not admin", "viewer", false},
		{"empty is not admin", "", false},
		{"unknown is not admin", "superadmin", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAdmin(tt.userRole)
			if got != tt.want {
				t.Errorf("IsAdmin(%q) = %v, want %v", tt.userRole, got, tt.want)
			}
		})
	}
}

// ============================================================================
// HasPermission tests
// ============================================================================

func TestHasPermission(t *testing.T) {
	tests := []struct {
		name     string
		userRole string
		perm     Permission
		want     bool
	}{
		// Admin has all permissions
		{"admin has container:view", "admin", PermContainerView, true},
		{"admin has user:create", "admin", PermUserCreate, true},
		{"admin has settings:update", "admin", PermSettingsUpdate, true},
		{"admin has backup:restore", "admin", PermBackupRestore, true},
		{"admin has image:build", "admin", PermImageBuild, true},

		// Operator has management permissions but not user/host/settings
		{"operator has container:create", "operator", PermContainerCreate, true},
		{"operator has container:exec", "operator", PermContainerExec, true},
		{"operator has image:pull", "operator", PermImagePull, true},
		{"operator has stack:deploy", "operator", PermStackDeploy, true},
		{"operator has security:scan", "operator", PermSecurityScan, true},
		{"operator denied user:create", "operator", PermUserCreate, false},
		{"operator denied user:update", "operator", PermUserUpdate, false},
		{"operator denied settings:update", "operator", PermSettingsUpdate, false},
		{"operator denied host:create", "operator", PermHostCreate, false},
		{"operator denied backup:restore", "operator", PermBackupRestore, false},
		{"operator denied image:build", "operator", PermImageBuild, false},

		// Viewer has read-only permissions
		{"viewer has container:view", "viewer", PermContainerView, true},
		{"viewer has container:logs", "viewer", PermContainerLogs, true},
		{"viewer has image:view", "viewer", PermImageView, true},
		{"viewer has backup:view", "viewer", PermBackupView, true},
		{"viewer denied container:create", "viewer", PermContainerCreate, false},
		{"viewer denied container:start", "viewer", PermContainerStart, false},
		{"viewer denied image:pull", "viewer", PermImagePull, false},
		{"viewer denied stack:deploy", "viewer", PermStackDeploy, false},
		{"viewer denied security:scan", "viewer", PermSecurityScan, false},

		// Unknown role has no permissions
		{"unknown role denied", "unknown", PermContainerView, false},
		{"empty role denied", "", PermContainerView, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasPermission(tt.userRole, tt.perm)
			if got != tt.want {
				t.Errorf("HasPermission(%q, %q) = %v, want %v", tt.userRole, tt.perm, got, tt.want)
			}
		})
	}
}

// ============================================================================
// DefaultTeamAccessChecker tests
// ============================================================================

func TestDefaultTeamAccessChecker(t *testing.T) {
	tests := []struct {
		name         string
		userID       string
		userTeams    []string
		resourceTeam string
		want         bool
	}{
		{"member of team", "user1", []string{"team-a", "team-b"}, "team-a", true},
		{"member of second team", "user1", []string{"team-a", "team-b"}, "team-b", true},
		{"not member of team", "user1", []string{"team-a", "team-b"}, "team-c", false},
		{"no teams", "user1", []string{}, "team-a", false},
		{"nil teams", "user1", nil, "team-a", false},
		{"empty resource team", "user1", []string{"team-a"}, "", false},
		{"single team match", "user1", []string{"ops"}, "ops", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DefaultTeamAccessChecker(tt.userID, tt.userTeams, tt.resourceTeam)
			if got != tt.want {
				t.Errorf("DefaultTeamAccessChecker(%q, %v, %q) = %v, want %v",
					tt.userID, tt.userTeams, tt.resourceTeam, got, tt.want)
			}
		})
	}
}

// ============================================================================
// RequireRole middleware tests
// ============================================================================

func TestRequireRoleMiddleware(t *testing.T) {
	tests := []struct {
		name       string
		userRole   string
		minRole    Role
		wantStatus int
	}{
		{"admin passes admin check", "admin", RoleAdmin, http.StatusOK},
		{"operator passes operator check", "operator", RoleOperator, http.StatusOK},
		{"admin passes operator check", "admin", RoleOperator, http.StatusOK},
		{"viewer fails admin check", "viewer", RoleAdmin, http.StatusForbidden},
		{"operator fails admin check", "operator", RoleAdmin, http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := RequireRole(tt.minRole)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			ctx := context.WithValue(req.Context(), UserContextKey, &UserClaims{
				UserID: "test-user",
				Role:   tt.userRole,
			})
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("RequireRole(%q) with role %q: got status %d, want %d",
					tt.minRole, tt.userRole, rr.Code, tt.wantStatus)
			}
		})
	}
}

func TestRequireRoleMiddleware_NoUser(t *testing.T) {
	handler := RequireRole(RoleViewer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("RequireRole with no user: got status %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

// ============================================================================
// RequirePermission middleware tests
// ============================================================================

func TestRequirePermissionMiddleware(t *testing.T) {
	tests := []struct {
		name       string
		userRole   string
		perm       Permission
		wantStatus int
	}{
		{"admin has image:build", "admin", PermImageBuild, http.StatusOK},
		{"operator denied image:build", "operator", PermImageBuild, http.StatusForbidden},
		{"viewer denied container:create", "viewer", PermContainerCreate, http.StatusForbidden},
		{"operator has container:exec", "operator", PermContainerExec, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := RequirePermission(tt.perm)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			ctx := context.WithValue(req.Context(), UserContextKey, &UserClaims{
				UserID: "test-user",
				Role:   tt.userRole,
			})
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("RequirePermission(%q) with role %q: got status %d, want %d",
					tt.perm, tt.userRole, rr.Code, tt.wantStatus)
			}
		})
	}
}

// ============================================================================
// Role hierarchy consistency tests
// ============================================================================

func TestRoleHierarchyConsistency(t *testing.T) {
	// Verify that admin has strictly higher level than operator
	if roleHierarchy[RoleAdmin] <= roleHierarchy[RoleOperator] {
		t.Error("Admin should have higher hierarchy than operator")
	}

	// Verify that operator has strictly higher level than viewer
	if roleHierarchy[RoleOperator] <= roleHierarchy[RoleViewer] {
		t.Error("Operator should have higher hierarchy than viewer")
	}

	// Verify all defined roles are in the hierarchy
	for _, role := range []Role{RoleAdmin, RoleOperator, RoleViewer} {
		if _, ok := roleHierarchy[role]; !ok {
			t.Errorf("Role %q missing from hierarchy", role)
		}
	}
}

func TestPermissionCachePopulated(t *testing.T) {
	// Verify that the permission cache was populated during init()
	for role, perms := range rolePermissions {
		cached, ok := permissionCache[role]
		if !ok {
			t.Errorf("Permission cache missing role %q", role)
			continue
		}
		for _, perm := range perms {
			if !cached[perm] {
				t.Errorf("Permission cache missing %q for role %q", perm, role)
			}
		}
	}
}

func TestAdminHasAllPermissions(t *testing.T) {
	// Collect all unique permissions from all roles
	allPerms := make(map[Permission]bool)
	for _, perms := range rolePermissions {
		for _, perm := range perms {
			allPerms[perm] = true
		}
	}

	// Verify admin has all of them
	for perm := range allPerms {
		if !HasPermission("admin", perm) {
			t.Errorf("Admin should have permission %q but doesn't", perm)
		}
	}
}

func TestOperatorHasAllViewerPermissions(t *testing.T) {
	// Verify operator has all permissions that viewer has
	for _, perm := range rolePermissions[RoleViewer] {
		if !HasPermission("operator", perm) {
			t.Errorf("Operator should have viewer permission %q but doesn't", perm)
		}
	}
}
