// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	apierrors "github.com/fr4nsys/usulnet/internal/api/errors"
	"github.com/fr4nsys/usulnet/internal/license"
)

// ============================================================================
// Mock LicenseProvider
// ============================================================================

type mockLicenseProvider struct {
	info *license.Info
}

func (m *mockLicenseProvider) GetLicense(_ context.Context) (*license.Info, error) {
	return m.info, nil
}

func (m *mockLicenseProvider) HasFeature(_ context.Context, feature license.Feature) bool {
	return m.info.HasFeature(feature)
}

func (m *mockLicenseProvider) IsValid(_ context.Context) bool {
	return m.info != nil && m.info.Valid && !m.info.IsExpired()
}

func (m *mockLicenseProvider) GetLimits() license.Limits {
	if m.info != nil {
		return m.info.Limits
	}
	return license.CELimits()
}

// Helpers to create providers for each edition
func ceProvider() *mockLicenseProvider {
	return &mockLicenseProvider{info: license.NewCEInfo()}
}

func businessProvider() *mockLicenseProvider {
	future := time.Now().Add(365 * 24 * time.Hour)
	return &mockLicenseProvider{info: &license.Info{
		Edition:   license.Business,
		Valid:     true,
		LicenseID: "USN-test-biz",
		ExpiresAt: &future,
		Features:  license.AllBusinessFeatures(),
		Limits:    license.BusinessDefaultLimits(),
	}}
}

func enterpriseProvider() *mockLicenseProvider {
	future := time.Now().Add(365 * 24 * time.Hour)
	return &mockLicenseProvider{info: &license.Info{
		Edition:   license.Enterprise,
		Valid:     true,
		LicenseID: "USN-test-ent",
		ExpiresAt: &future,
		Features:  license.AllEnterpriseFeatures(),
		Limits:    license.EnterpriseLimits(),
	}}
}

func expiredBusinessProvider() *mockLicenseProvider {
	past := time.Now().Add(-24 * time.Hour)
	return &mockLicenseProvider{info: &license.Info{
		Edition:   license.Business,
		Valid:     true,
		LicenseID: "USN-test-expired",
		ExpiresAt: &past,
		Features:  license.AllBusinessFeatures(),
		Limits:    license.BusinessDefaultLimits(),
	}}
}

// okHandler returns a simple 200 OK response
func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
}

// parseErrorResponse parses the JSON error from response body
func parseErrorResponse(t *testing.T, w *httptest.ResponseRecorder) *apierrors.APIError {
	t.Helper()
	var apiErr apierrors.APIError
	if err := json.NewDecoder(w.Body).Decode(&apiErr); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	return &apiErr
}

// ============================================================================
// License middleware (context injection)
// ============================================================================

func TestLicense_AddsToContext(t *testing.T) {
	provider := businessProvider()
	mw := License(LicenseConfig{
		Provider:     provider,
		AddToContext: true,
	})

	var gotInfo *license.Info
	handler := mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotInfo = GetLicenseFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if gotInfo == nil {
		t.Fatal("license info not found in context")
	}
	if gotInfo.Edition != license.Business {
		t.Errorf("context edition = %q, want %q", gotInfo.Edition, license.Business)
	}
}

func TestLicense_SkipsContextWhenDisabled(t *testing.T) {
	provider := businessProvider()
	mw := License(LicenseConfig{
		Provider:     provider,
		AddToContext: false,
	})

	var gotInfo *license.Info
	handler := mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotInfo = GetLicenseFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if gotInfo != nil {
		t.Error("license info should not be in context when AddToContext=false")
	}
}

func TestLicense_NilProvider(t *testing.T) {
	mw := License(LicenseConfig{
		Provider:     nil,
		AddToContext: true,
	})

	called := false
	handler := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("next handler was not called with nil provider")
	}
}

// ============================================================================
// RequireFeature
// ============================================================================

func TestRequireFeature_Allowed(t *testing.T) {
	tests := []struct {
		name     string
		provider *mockLicenseProvider
		feature  license.Feature
	}{
		{"business with APIKeys", businessProvider(), license.FeatureAPIKeys},
		{"business with LDAP", businessProvider(), license.FeatureLDAP},
		{"business with OAuth", businessProvider(), license.FeatureOAuth},
		{"business with AuditExport", businessProvider(), license.FeatureAuditExport},
		{"business with Swarm", businessProvider(), license.FeatureSwarm},
		{"enterprise with Compliance", enterpriseProvider(), license.FeatureCompliance},
		{"enterprise with OPA", enterpriseProvider(), license.FeatureOPAPolicies},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := RequireFeature(tt.provider, tt.feature)
			handler := mw(okHandler())

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
			}
		})
	}
}

func TestRequireFeature_Blocked(t *testing.T) {
	tests := []struct {
		name     string
		provider *mockLicenseProvider
		feature  license.Feature
	}{
		{"CE blocks APIKeys", ceProvider(), license.FeatureAPIKeys},
		{"CE blocks LDAP", ceProvider(), license.FeatureLDAP},
		{"CE blocks OAuth", ceProvider(), license.FeatureOAuth},
		{"CE blocks AuditExport", ceProvider(), license.FeatureAuditExport},
		{"CE blocks Swarm", ceProvider(), license.FeatureSwarm},
		{"CE blocks SAML", ceProvider(), license.FeatureSSOSAML},
		{"CE blocks CustomRoles", ceProvider(), license.FeatureCustomRoles},
		// Unimplemented features are blocked for all tiers (not in AllEnterpriseFeatures)
		{"business blocks SAML", businessProvider(), license.FeatureSSOSAML},
		{"business blocks HA", businessProvider(), license.FeatureHAMode},
		{"business blocks SharedTerminals", businessProvider(), license.FeatureSharedTerminals},
		{"business blocks WhiteLabel", businessProvider(), license.FeatureWhiteLabel},
		{"enterprise blocks SAML (unimplemented)", enterpriseProvider(), license.FeatureSSOSAML},
		{"enterprise blocks HA (unimplemented)", enterpriseProvider(), license.FeatureHAMode},
		{"enterprise blocks SharedTerminals (unimplemented)", enterpriseProvider(), license.FeatureSharedTerminals},
		{"enterprise blocks WhiteLabel (unimplemented)", enterpriseProvider(), license.FeatureWhiteLabel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := RequireFeature(tt.provider, tt.feature)
			handler := mw(okHandler())

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusPaymentRequired {
				t.Errorf("status = %d, want %d (402 Payment Required)", w.Code, http.StatusPaymentRequired)
			}

			apiErr := parseErrorResponse(t, w)
			if apiErr.Code != apierrors.ErrCodeLicenseRequired {
				t.Errorf("error code = %q, want %q", apiErr.Code, apierrors.ErrCodeLicenseRequired)
			}
		})
	}
}

// ============================================================================
// RequirePaid
// ============================================================================

func TestRequirePaid_AllowsBusiness(t *testing.T) {
	mw := RequirePaid(businessProvider())
	handler := mw(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Business: status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestRequirePaid_AllowsEnterprise(t *testing.T) {
	mw := RequirePaid(enterpriseProvider())
	handler := mw(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Enterprise: status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestRequirePaid_BlocksCE(t *testing.T) {
	mw := RequirePaid(ceProvider())
	handler := mw(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Errorf("CE: status = %d, want %d", w.Code, http.StatusPaymentRequired)
	}
}

func TestRequirePaid_BlocksExpired(t *testing.T) {
	mw := RequirePaid(expiredBusinessProvider())
	handler := mw(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Errorf("Expired: status = %d, want %d", w.Code, http.StatusPaymentRequired)
	}
}

// ============================================================================
// RequireEnterprise
// ============================================================================

func TestRequireEnterprise_AllowsEnterprise(t *testing.T) {
	mw := RequireEnterprise(enterpriseProvider())
	handler := mw(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Enterprise: status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestRequireEnterprise_BlocksBusiness(t *testing.T) {
	mw := RequireEnterprise(businessProvider())
	handler := mw(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Errorf("Business: status = %d, want %d", w.Code, http.StatusPaymentRequired)
	}
}

func TestRequireEnterprise_BlocksCE(t *testing.T) {
	mw := RequireEnterprise(ceProvider())
	handler := mw(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Errorf("CE: status = %d, want %d", w.Code, http.StatusPaymentRequired)
	}
}

func TestRequireEnterprise_BlocksExpired(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour)
	provider := &mockLicenseProvider{info: &license.Info{
		Edition:   license.Enterprise,
		Valid:     true,
		ExpiresAt: &past,
		Features:  license.AllEnterpriseFeatures(),
		Limits:    license.EnterpriseLimits(),
	}}

	mw := RequireEnterprise(provider)
	handler := mw(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Errorf("Expired Enterprise: status = %d, want %d", w.Code, http.StatusPaymentRequired)
	}
}

// ============================================================================
// RequireValidLicense
// ============================================================================

func TestRequireValidLicense_AllowsValid(t *testing.T) {
	tests := []struct {
		name     string
		provider *mockLicenseProvider
	}{
		{"Business", businessProvider()},
		{"Enterprise", enterpriseProvider()},
		{"CE (always valid)", ceProvider()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := RequireValidLicense(tt.provider)
			handler := mw(okHandler())

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
			}
		})
	}
}

func TestRequireValidLicense_BlocksExpired(t *testing.T) {
	mw := RequireValidLicense(expiredBusinessProvider())
	handler := mw(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Errorf("Expired: status = %d, want %d", w.Code, http.StatusPaymentRequired)
	}
}

// ============================================================================
// RequireLimit
// ============================================================================

func TestRequireLimit_UnderLimit(t *testing.T) {
	provider := ceProvider() // CE: MaxUsers=3

	mw := RequireLimit(
		provider,
		"users",
		func(_ *http.Request) int { return 2 }, // current = 2, under limit
		func(l license.Limits) int { return l.MaxUsers },
	)

	handler := mw(okHandler())
	req := httptest.NewRequest(http.MethodPost, "/users", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("under limit: status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestRequireLimit_AtLimit(t *testing.T) {
	provider := ceProvider() // CE: MaxUsers=3

	mw := RequireLimit(
		provider,
		"users",
		func(_ *http.Request) int { return 3 }, // current = limit
		func(l license.Limits) int { return l.MaxUsers },
	)

	handler := mw(okHandler())
	req := httptest.NewRequest(http.MethodPost, "/users", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// At limit means creation should be blocked
	if w.Code != http.StatusPaymentRequired {
		t.Errorf("at limit: status = %d, want %d", w.Code, http.StatusPaymentRequired)
	}

	apiErr := parseErrorResponse(t, w)
	if apiErr.Code != apierrors.ErrCodeLicenseRequired {
		t.Errorf("error code = %q, want %q", apiErr.Code, apierrors.ErrCodeLicenseRequired)
	}

	// Verify details contain resource info
	details, ok := apiErr.Details.(map[string]any)
	if !ok {
		t.Fatal("details is not a map")
	}
	if details["resource"] != "users" {
		t.Errorf("resource = %v, want 'users'", details["resource"])
	}
}

func TestRequireLimit_OverLimit(t *testing.T) {
	provider := ceProvider() // CE: MaxNodes=1

	mw := RequireLimit(
		provider,
		"nodes",
		func(_ *http.Request) int { return 5 }, // way over limit
		func(l license.Limits) int { return l.MaxNodes },
	)

	handler := mw(okHandler())
	req := httptest.NewRequest(http.MethodPost, "/hosts", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Errorf("over limit: status = %d, want %d", w.Code, http.StatusPaymentRequired)
	}
}

func TestRequireLimit_Unlimited(t *testing.T) {
	provider := enterpriseProvider() // Enterprise: all limits = 0 (unlimited)

	mw := RequireLimit(
		provider,
		"users",
		func(_ *http.Request) int { return 10000 }, // high count
		func(l license.Limits) int { return l.MaxUsers },
	)

	handler := mw(okHandler())
	req := httptest.NewRequest(http.MethodPost, "/users", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Limit=0 means unlimited, should pass regardless of current count
	if w.Code != http.StatusOK {
		t.Errorf("unlimited: status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestRequireLimit_UpgradeMessage_CE(t *testing.T) {
	provider := ceProvider()

	mw := RequireLimit(
		provider,
		"users",
		func(_ *http.Request) int { return 3 },
		func(l license.Limits) int { return l.MaxUsers },
	)

	handler := mw(okHandler())
	req := httptest.NewRequest(http.MethodPost, "/users", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	apiErr := parseErrorResponse(t, w)
	details, ok := apiErr.Details.(map[string]any)
	if !ok {
		t.Fatal("details is not a map")
	}

	upgrade, ok := details["upgrade"].(string)
	if !ok {
		t.Fatal("upgrade message not found in details")
	}

	// CE should suggest upgrading to Business
	if upgrade != "Upgrade to usulnet Business for more users" {
		t.Errorf("CE upgrade message = %q", upgrade)
	}
}

func TestRequireLimit_UpgradeMessage_Business(t *testing.T) {
	provider := businessProvider()
	// Override MaxTeams to a non-zero limit for testing
	provider.info.Limits.MaxTeams = 5

	mw := RequireLimit(
		provider,
		"teams",
		func(_ *http.Request) int { return 5 }, // at limit
		func(l license.Limits) int { return l.MaxTeams },
	)

	handler := mw(okHandler())
	req := httptest.NewRequest(http.MethodPost, "/teams", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	apiErr := parseErrorResponse(t, w)
	details, ok := apiErr.Details.(map[string]any)
	if !ok {
		t.Fatal("details is not a map")
	}

	upgrade, ok := details["upgrade"].(string)
	if !ok {
		t.Fatal("upgrade message not found in details")
	}

	// Business should suggest upgrading to Enterprise
	if upgrade != "Upgrade to usulnet Enterprise for unlimited teams" {
		t.Errorf("Business upgrade message = %q", upgrade)
	}
}

// ============================================================================
// RequireLimit - all CE resource limits
// ============================================================================

func TestRequireLimit_CELimits(t *testing.T) {
	tests := []struct {
		name     string
		resource string
		current  int
		limitFn  func(license.Limits) int
		wantCode int
	}{
		// Under limit - allowed
		{"nodes under", "nodes", 0, func(l license.Limits) int { return l.MaxNodes }, http.StatusOK},
		{"users under", "users", 2, func(l license.Limits) int { return l.MaxUsers }, http.StatusOK},
		{"teams under", "teams", 0, func(l license.Limits) int { return l.MaxTeams }, http.StatusOK},
		{"api keys under", "api_keys", 2, func(l license.Limits) int { return l.MaxAPIKeys }, http.StatusOK},
		{"git under", "git_connections", 0, func(l license.Limits) int { return l.MaxGitConnections }, http.StatusOK},
		{"s3 under", "s3_connections", 0, func(l license.Limits) int { return l.MaxS3Connections }, http.StatusOK},
		{"backup under", "backup_destinations", 0, func(l license.Limits) int { return l.MaxBackupDestinations }, http.StatusOK},
		{"notification under", "notification_channels", 0, func(l license.Limits) int { return l.MaxNotificationChannels }, http.StatusOK},

		// At limit - blocked
		{"nodes at limit", "nodes", 1, func(l license.Limits) int { return l.MaxNodes }, http.StatusPaymentRequired},
		{"users at limit", "users", 3, func(l license.Limits) int { return l.MaxUsers }, http.StatusPaymentRequired},
		{"teams at limit", "teams", 1, func(l license.Limits) int { return l.MaxTeams }, http.StatusPaymentRequired},
		{"api keys at limit", "api_keys", 3, func(l license.Limits) int { return l.MaxAPIKeys }, http.StatusPaymentRequired},
		{"git at limit", "git_connections", 1, func(l license.Limits) int { return l.MaxGitConnections }, http.StatusPaymentRequired},
		{"s3 at limit", "s3_connections", 1, func(l license.Limits) int { return l.MaxS3Connections }, http.StatusPaymentRequired},
		{"backup at limit", "backup_destinations", 1, func(l license.Limits) int { return l.MaxBackupDestinations }, http.StatusPaymentRequired},
		{"notification at limit", "notification_channels", 1, func(l license.Limits) int { return l.MaxNotificationChannels }, http.StatusPaymentRequired},

		// Over limit - blocked
		{"nodes over", "nodes", 5, func(l license.Limits) int { return l.MaxNodes }, http.StatusPaymentRequired},
		{"users over", "users", 10, func(l license.Limits) int { return l.MaxUsers }, http.StatusPaymentRequired},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := ceProvider()
			mw := RequireLimit(
				provider,
				tt.resource,
				func(_ *http.Request) int { return tt.current },
				tt.limitFn,
			)

			handler := mw(okHandler())
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("status = %d, want %d", w.Code, tt.wantCode)
			}
		})
	}
}

// ============================================================================
// GetLicenseFromContext
// ============================================================================

func TestGetLicenseFromContext(t *testing.T) {
	t.Run("with info", func(t *testing.T) {
		info := license.NewCEInfo()
		ctx := context.WithValue(context.Background(), LicenseContextKey, info)
		got := GetLicenseFromContext(ctx)
		if got == nil {
			t.Fatal("GetLicenseFromContext() returned nil")
		}
		if got.Edition != license.CE {
			t.Errorf("edition = %q, want %q", got.Edition, license.CE)
		}
	})

	t.Run("without info", func(t *testing.T) {
		got := GetLicenseFromContext(context.Background())
		if got != nil {
			t.Error("GetLicenseFromContext() should return nil for empty context")
		}
	})
}

// ============================================================================
// IsPaidFromContext
// ============================================================================

func TestIsPaidFromContext(t *testing.T) {
	tests := []struct {
		name string
		info *license.Info
		want bool
	}{
		{"nil info", nil, false},
		{"CE", license.NewCEInfo(), false},
		{"Business valid", &license.Info{Edition: license.Business, Valid: true}, true},
		{"Enterprise valid", &license.Info{Edition: license.Enterprise, Valid: true}, true},
		{"Business invalid", &license.Info{Edition: license.Business, Valid: false}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ctx context.Context
			if tt.info != nil {
				ctx = context.WithValue(context.Background(), LicenseContextKey, tt.info)
			} else {
				ctx = context.Background()
			}

			if got := IsPaidFromContext(ctx); got != tt.want {
				t.Errorf("IsPaidFromContext() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ============================================================================
// HTTP 402 status code consistency
// ============================================================================

func TestLicenseMiddleware_Returns402(t *testing.T) {
	// All license enforcement middleware should return 402 (Payment Required)
	// This is a key contract: not 403, not 401, always 402
	provider := ceProvider()

	tests := []struct {
		name    string
		handler http.Handler
	}{
		{"RequireFeature", RequireFeature(provider, license.FeatureAPIKeys)(okHandler())},
		{"RequirePaid", RequirePaid(provider)(okHandler())},
		{"RequireEnterprise", RequireEnterprise(provider)(okHandler())},
		{"RequireLimit at limit", RequireLimit(provider, "users",
			func(_ *http.Request) int { return 3 },
			func(l license.Limits) int { return l.MaxUsers },
		)(okHandler())},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()
			tt.handler.ServeHTTP(w, req)

			if w.Code != http.StatusPaymentRequired {
				t.Errorf("status = %d, want 402 (Payment Required)", w.Code)
			}
		})
	}
}

// ============================================================================
// LicenseProvider interface compliance
// ============================================================================

func TestMockLicenseProvider_SatisfiesInterface(t *testing.T) {
	var _ LicenseProvider = (*mockLicenseProvider)(nil)
}
