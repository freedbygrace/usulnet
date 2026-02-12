// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package license

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ============================================================================
// Edition Constants
// ============================================================================

func TestEditionConstants(t *testing.T) {
	tests := []struct {
		name    string
		edition Edition
		want    string
	}{
		{"CE", CE, "ce"},
		{"Business", Business, "biz"},
		{"Enterprise", Enterprise, "ee"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.edition) != tt.want {
				t.Errorf("Edition %s = %q, want %q", tt.name, tt.edition, tt.want)
			}
		})
	}
}

// ============================================================================
// Feature Constants
// ============================================================================

func TestFeatureConstants(t *testing.T) {
	// Verify all 13 feature constants have expected string values
	features := map[Feature]string{
		FeatureCustomRoles:       "custom_roles",
		FeatureOAuth:             "oauth",
		FeatureLDAP:              "ldap",
		FeatureMultiNotification: "multi_notification",
		FeatureAuditExport:       "audit_export",
		FeatureMultiBackup:       "multi_backup",
		FeatureAPIKeys:           "api_keys",
		FeaturePrioritySupport:   "priority_support",
		FeatureSSOSAML:           "sso_saml",
		FeatureHAMode:            "ha_mode",
		FeatureSharedTerminals:   "shared_terminals",
		FeatureWhiteLabel:        "white_label",
		FeatureSwarm:             "swarm",
	}

	for feat, want := range features {
		if string(feat) != want {
			t.Errorf("Feature %q != %q", feat, want)
		}
	}
}

// ============================================================================
// AllBusinessFeatures / AllEnterpriseFeatures
// ============================================================================

func TestAllBusinessFeatures(t *testing.T) {
	features := AllBusinessFeatures()

	// Business edition has exactly 9 features
	if len(features) != 9 {
		t.Fatalf("AllBusinessFeatures() returned %d features, want 9", len(features))
	}

	// Business must include these features
	expected := []Feature{
		FeatureCustomRoles,
		FeatureOAuth,
		FeatureLDAP,
		FeatureMultiNotification,
		FeatureAuditExport,
		FeatureMultiBackup,
		FeatureAPIKeys,
		FeaturePrioritySupport,
		FeatureSwarm,
	}

	featureSet := make(map[Feature]bool)
	for _, f := range features {
		featureSet[f] = true
	}

	for _, f := range expected {
		if !featureSet[f] {
			t.Errorf("AllBusinessFeatures() missing %q", f)
		}
	}

	// Business must NOT include Enterprise-only features
	enterpriseOnly := []Feature{
		FeatureSSOSAML,
		FeatureHAMode,
		FeatureSharedTerminals,
		FeatureWhiteLabel,
	}
	for _, f := range enterpriseOnly {
		if featureSet[f] {
			t.Errorf("AllBusinessFeatures() should NOT include enterprise-only feature %q", f)
		}
	}
}

func TestAllEnterpriseFeatures(t *testing.T) {
	features := AllEnterpriseFeatures()

	// Enterprise has all 13 features
	if len(features) != 13 {
		t.Fatalf("AllEnterpriseFeatures() returned %d features, want 13", len(features))
	}

	// Enterprise must include all business features
	for _, bf := range AllBusinessFeatures() {
		found := false
		for _, ef := range features {
			if ef == bf {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("AllEnterpriseFeatures() missing business feature %q", bf)
		}
	}

	// Plus the 4 enterprise-only features
	enterpriseOnly := []Feature{
		FeatureSSOSAML,
		FeatureHAMode,
		FeatureSharedTerminals,
		FeatureWhiteLabel,
	}
	featureSet := make(map[Feature]bool)
	for _, f := range features {
		featureSet[f] = true
	}
	for _, f := range enterpriseOnly {
		if !featureSet[f] {
			t.Errorf("AllEnterpriseFeatures() missing enterprise feature %q", f)
		}
	}
}

// ============================================================================
// CELimits - Community Edition limits
// ============================================================================

func TestCELimits(t *testing.T) {
	limits := CELimits()

	tests := []struct {
		name string
		got  int
		want int
	}{
		{"MaxNodes", limits.MaxNodes, CEBaseNodes}, // 1
		{"MaxUsers", limits.MaxUsers, 3},
		{"MaxTeams", limits.MaxTeams, 1},
		{"MaxCustomRoles", limits.MaxCustomRoles, 1},
		{"MaxLDAPServers", limits.MaxLDAPServers, 0}, // disabled
		{"MaxOAuthProviders", limits.MaxOAuthProviders, 0}, // disabled
		{"MaxAPIKeys", limits.MaxAPIKeys, 3},
		{"MaxGitConnections", limits.MaxGitConnections, 1},
		{"MaxS3Connections", limits.MaxS3Connections, 1},
		{"MaxBackupDestinations", limits.MaxBackupDestinations, 1},
		{"MaxNotificationChannels", limits.MaxNotificationChannels, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("CELimits().%s = %d, want %d", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestCEBaseNodes(t *testing.T) {
	if CEBaseNodes != 1 {
		t.Errorf("CEBaseNodes = %d, want 1", CEBaseNodes)
	}
}

// ============================================================================
// BusinessDefaultLimits
// ============================================================================

func TestBusinessDefaultLimits(t *testing.T) {
	limits := BusinessDefaultLimits()

	tests := []struct {
		name string
		got  int
		want int
	}{
		{"MaxNodes", limits.MaxNodes, 0},     // from JWT (0 = placeholder)
		{"MaxUsers", limits.MaxUsers, 0},     // from JWT (0 = placeholder)
		{"MaxTeams", limits.MaxTeams, 5},
		{"MaxCustomRoles", limits.MaxCustomRoles, 0}, // unlimited
		{"MaxLDAPServers", limits.MaxLDAPServers, 3},
		{"MaxOAuthProviders", limits.MaxOAuthProviders, 3},
		{"MaxAPIKeys", limits.MaxAPIKeys, 25},
		{"MaxGitConnections", limits.MaxGitConnections, 5},
		{"MaxS3Connections", limits.MaxS3Connections, 5},
		{"MaxBackupDestinations", limits.MaxBackupDestinations, 5},
		{"MaxNotificationChannels", limits.MaxNotificationChannels, 0}, // unlimited
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("BusinessDefaultLimits().%s = %d, want %d", tt.name, tt.got, tt.want)
			}
		})
	}
}

// ============================================================================
// EnterpriseLimits - all unlimited (zeros)
// ============================================================================

func TestEnterpriseLimits(t *testing.T) {
	limits := EnterpriseLimits()

	// All Enterprise limits must be 0 (unlimited)
	if limits.MaxNodes != 0 {
		t.Errorf("MaxNodes = %d, want 0", limits.MaxNodes)
	}
	if limits.MaxUsers != 0 {
		t.Errorf("MaxUsers = %d, want 0", limits.MaxUsers)
	}
	if limits.MaxTeams != 0 {
		t.Errorf("MaxTeams = %d, want 0", limits.MaxTeams)
	}
	if limits.MaxCustomRoles != 0 {
		t.Errorf("MaxCustomRoles = %d, want 0", limits.MaxCustomRoles)
	}
	if limits.MaxLDAPServers != 0 {
		t.Errorf("MaxLDAPServers = %d, want 0", limits.MaxLDAPServers)
	}
	if limits.MaxOAuthProviders != 0 {
		t.Errorf("MaxOAuthProviders = %d, want 0", limits.MaxOAuthProviders)
	}
	if limits.MaxAPIKeys != 0 {
		t.Errorf("MaxAPIKeys = %d, want 0", limits.MaxAPIKeys)
	}
	if limits.MaxGitConnections != 0 {
		t.Errorf("MaxGitConnections = %d, want 0", limits.MaxGitConnections)
	}
	if limits.MaxS3Connections != 0 {
		t.Errorf("MaxS3Connections = %d, want 0", limits.MaxS3Connections)
	}
	if limits.MaxBackupDestinations != 0 {
		t.Errorf("MaxBackupDestinations = %d, want 0", limits.MaxBackupDestinations)
	}
	if limits.MaxNotificationChannels != 0 {
		t.Errorf("MaxNotificationChannels = %d, want 0", limits.MaxNotificationChannels)
	}
}

// ============================================================================
// NewCEInfo
// ============================================================================

func TestNewCEInfo(t *testing.T) {
	info := NewCEInfo()

	if info == nil {
		t.Fatal("NewCEInfo() returned nil")
	}
	if info.Edition != CE {
		t.Errorf("Edition = %q, want %q", info.Edition, CE)
	}
	if !info.Valid {
		t.Error("Valid = false, want true")
	}
	if info.LicenseID != "" {
		t.Errorf("LicenseID = %q, want empty", info.LicenseID)
	}
	if info.ExpiresAt != nil {
		t.Errorf("ExpiresAt = %v, want nil", info.ExpiresAt)
	}
	if info.Features != nil {
		t.Errorf("Features = %v, want nil (CE has no features)", info.Features)
	}

	// CE limits must match CELimits()
	ceLimits := CELimits()
	if info.Limits != ceLimits {
		t.Errorf("Limits = %+v, want %+v", info.Limits, ceLimits)
	}
}

// ============================================================================
// Info.HasFeature
// ============================================================================

func TestInfo_HasFeature(t *testing.T) {
	t.Run("nil info returns false", func(t *testing.T) {
		var info *Info
		if info.HasFeature(FeatureAPIKeys) {
			t.Error("nil Info.HasFeature() = true, want false")
		}
	})

	t.Run("invalid license returns false", func(t *testing.T) {
		info := &Info{
			Valid:    false,
			Features: []Feature{FeatureAPIKeys},
		}
		if info.HasFeature(FeatureAPIKeys) {
			t.Error("invalid Info.HasFeature(FeatureAPIKeys) = true, want false")
		}
	})

	t.Run("valid license with feature returns true", func(t *testing.T) {
		info := &Info{
			Valid:    true,
			Features: AllBusinessFeatures(),
		}
		for _, f := range AllBusinessFeatures() {
			if !info.HasFeature(f) {
				t.Errorf("HasFeature(%q) = false, want true", f)
			}
		}
	})

	t.Run("valid license without feature returns false", func(t *testing.T) {
		info := &Info{
			Valid:    true,
			Features: []Feature{FeatureAPIKeys},
		}
		if info.HasFeature(FeatureSSOSAML) {
			t.Error("HasFeature(FeatureSSOSAML) = true, want false")
		}
	})

	t.Run("CE info has no features", func(t *testing.T) {
		info := NewCEInfo()
		for _, f := range AllEnterpriseFeatures() {
			if info.HasFeature(f) {
				t.Errorf("CE HasFeature(%q) = true, want false", f)
			}
		}
	})

	t.Run("empty features returns false", func(t *testing.T) {
		info := &Info{
			Valid:    true,
			Features: []Feature{},
		}
		if info.HasFeature(FeatureAPIKeys) {
			t.Error("empty features HasFeature() = true, want false")
		}
	})
}

// ============================================================================
// Info.IsExpired
// ============================================================================

func TestInfo_IsExpired(t *testing.T) {
	t.Run("nil info returns false", func(t *testing.T) {
		var info *Info
		if info.IsExpired() {
			t.Error("nil Info.IsExpired() = true, want false")
		}
	})

	t.Run("nil ExpiresAt returns false", func(t *testing.T) {
		info := &Info{ExpiresAt: nil}
		if info.IsExpired() {
			t.Error("nil ExpiresAt IsExpired() = true, want false")
		}
	})

	t.Run("future expiration returns false", func(t *testing.T) {
		future := time.Now().Add(24 * time.Hour)
		info := &Info{ExpiresAt: &future}
		if info.IsExpired() {
			t.Error("future expiration IsExpired() = true, want false")
		}
	})

	t.Run("past expiration returns true", func(t *testing.T) {
		past := time.Now().Add(-24 * time.Hour)
		info := &Info{ExpiresAt: &past}
		if !info.IsExpired() {
			t.Error("past expiration IsExpired() = false, want true")
		}
	})

	t.Run("CE info never expires", func(t *testing.T) {
		info := NewCEInfo()
		if info.IsExpired() {
			t.Error("CE info IsExpired() = true, want false")
		}
	})
}

// ============================================================================
// Info.EditionName
// ============================================================================

func TestInfo_EditionName(t *testing.T) {
	tests := []struct {
		name string
		info *Info
		want string
	}{
		{"nil info", nil, "Community Edition"},
		{"CE", &Info{Edition: CE}, "Community Edition"},
		{"Business", &Info{Edition: Business}, "Business"},
		{"Enterprise", &Info{Edition: Enterprise}, "Enterprise"},
		{"unknown edition", &Info{Edition: "unknown"}, "Community Edition"},
		{"empty edition", &Info{Edition: ""}, "Community Edition"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.info.EditionName(); got != tt.want {
				t.Errorf("EditionName() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ============================================================================
// ClaimsToInfo
// ============================================================================

func TestClaimsToInfo_Business(t *testing.T) {
	expiry := time.Now().Add(365 * 24 * time.Hour)
	claims := &Claims{
		LicenseID: "USN-test-1234",
		EmailHash: "abc123",
		Edition:   Business,
		MaxNodes:  3,
		MaxUsers:  15,
		Features:  AllBusinessFeatures(),
	}
	claims.ExpiresAt = jwt.NewNumericDate(expiry)

	info := ClaimsToInfo(claims, "instance-abc")

	if info.Edition != Business {
		t.Errorf("Edition = %q, want %q", info.Edition, Business)
	}
	if !info.Valid {
		t.Error("Valid = false, want true")
	}
	if info.LicenseID != "USN-test-1234" {
		t.Errorf("LicenseID = %q, want %q", info.LicenseID, "USN-test-1234")
	}
	if info.InstanceID != "instance-abc" {
		t.Errorf("InstanceID = %q, want %q", info.InstanceID, "instance-abc")
	}

	// Business: purchased nodes (3) + CEBaseNodes (1) = 4 total
	wantNodes := 3 + CEBaseNodes
	if info.Limits.MaxNodes != wantNodes {
		t.Errorf("MaxNodes = %d, want %d (purchased %d + CE base %d)",
			info.Limits.MaxNodes, wantNodes, 3, CEBaseNodes)
	}

	// MaxUsers comes directly from JWT claims
	if info.Limits.MaxUsers != 15 {
		t.Errorf("MaxUsers = %d, want 15", info.Limits.MaxUsers)
	}

	// Other limits should be Business defaults
	bDefaults := BusinessDefaultLimits()
	if info.Limits.MaxTeams != bDefaults.MaxTeams {
		t.Errorf("MaxTeams = %d, want %d", info.Limits.MaxTeams, bDefaults.MaxTeams)
	}
	if info.Limits.MaxAPIKeys != bDefaults.MaxAPIKeys {
		t.Errorf("MaxAPIKeys = %d, want %d", info.Limits.MaxAPIKeys, bDefaults.MaxAPIKeys)
	}
	if info.Limits.MaxGitConnections != bDefaults.MaxGitConnections {
		t.Errorf("MaxGitConnections = %d, want %d", info.Limits.MaxGitConnections, bDefaults.MaxGitConnections)
	}
	if info.Limits.MaxS3Connections != bDefaults.MaxS3Connections {
		t.Errorf("MaxS3Connections = %d, want %d", info.Limits.MaxS3Connections, bDefaults.MaxS3Connections)
	}
	if info.Limits.MaxBackupDestinations != bDefaults.MaxBackupDestinations {
		t.Errorf("MaxBackupDestinations = %d, want %d", info.Limits.MaxBackupDestinations, bDefaults.MaxBackupDestinations)
	}
}

func TestClaimsToInfo_Enterprise(t *testing.T) {
	expiry := time.Now().Add(365 * 24 * time.Hour)
	claims := &Claims{
		LicenseID: "USN-ent-5678",
		Edition:   Enterprise,
		Features:  AllEnterpriseFeatures(),
	}
	claims.ExpiresAt = jwt.NewNumericDate(expiry)

	info := ClaimsToInfo(claims, "instance-xyz")

	if info.Edition != Enterprise {
		t.Errorf("Edition = %q, want %q", info.Edition, Enterprise)
	}
	if !info.Valid {
		t.Error("Valid = false, want true")
	}

	// Enterprise: all limits 0 (unlimited)
	eLimits := EnterpriseLimits()
	if info.Limits != eLimits {
		t.Errorf("Enterprise Limits = %+v, want %+v", info.Limits, eLimits)
	}
}

func TestClaimsToInfo_Expired(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour)
	claims := &Claims{
		LicenseID: "USN-expired",
		Edition:   Business,
		MaxNodes:  1,
		MaxUsers:  10,
		Features:  AllBusinessFeatures(),
	}
	claims.ExpiresAt = jwt.NewNumericDate(past)

	info := ClaimsToInfo(claims, "inst-1")

	// Expired license should be marked invalid
	if info.Valid {
		t.Error("Expired license Valid = true, want false")
	}
	// But edition should still be preserved (for UI display)
	if info.Edition != Business {
		t.Errorf("Expired license Edition = %q, want %q", info.Edition, Business)
	}
}

func TestClaimsToInfo_BusinessNodeCounting(t *testing.T) {
	// Verify the node counting formula: purchased + CEBaseNodes
	tests := []struct {
		name      string
		purchased int
		wantTotal int
	}{
		{"buy 1 node", 1, 1 + CEBaseNodes},
		{"buy 2 nodes", 2, 2 + CEBaseNodes},
		{"buy 5 nodes", 5, 5 + CEBaseNodes},
		{"buy 10 nodes", 10, 10 + CEBaseNodes},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expiry := time.Now().Add(365 * 24 * time.Hour)
			claims := &Claims{
				LicenseID: "USN-node-test",
				Edition:   Business,
				MaxNodes:  tt.purchased,
				MaxUsers:  10,
			}
			claims.ExpiresAt = jwt.NewNumericDate(expiry)

			info := ClaimsToInfo(claims, "inst")
			if info.Limits.MaxNodes != tt.wantTotal {
				t.Errorf("purchased=%d: MaxNodes = %d, want %d",
					tt.purchased, info.Limits.MaxNodes, tt.wantTotal)
			}
		})
	}
}

func TestClaimsToInfo_BusinessZeroNodes(t *testing.T) {
	// When JWT has 0 purchased nodes, Business default (0) should remain
	expiry := time.Now().Add(365 * 24 * time.Hour)
	claims := &Claims{
		LicenseID: "USN-zero-nodes",
		Edition:   Business,
		MaxNodes:  0,
		MaxUsers:  10,
	}
	claims.ExpiresAt = jwt.NewNumericDate(expiry)

	info := ClaimsToInfo(claims, "inst")
	// MaxNodes=0 means the node-add logic is skipped, default is 0 (from BusinessDefaultLimits)
	if info.Limits.MaxNodes != 0 {
		t.Errorf("zero purchased nodes: MaxNodes = %d, want 0 (unlimited)", info.Limits.MaxNodes)
	}
}

// ============================================================================
// LimitProvider interface compliance
// ============================================================================

type testLimitProvider struct {
	limits Limits
}

func (tp *testLimitProvider) GetLimits() Limits { return tp.limits }

func TestLimitProvider_InterfaceCompliance(t *testing.T) {
	// Compile-time check that testLimitProvider satisfies LimitProvider
	var _ LimitProvider = (*testLimitProvider)(nil)

	provider := &testLimitProvider{limits: CELimits()}
	got := provider.GetLimits()
	if got != CELimits() {
		t.Errorf("GetLimits() = %+v, want %+v", got, CELimits())
	}
}

// ============================================================================
// Limits zero-value convention (0 = unlimited)
// ============================================================================

func TestLimits_ZeroMeansUnlimited(t *testing.T) {
	// Verify that Enterprise uses the zero-value convention for "unlimited"
	limits := EnterpriseLimits()
	zero := Limits{}
	if limits != zero {
		t.Error("EnterpriseLimits() should be the zero value of Limits (all unlimited)")
	}
}

// ============================================================================
// CE has no LDAP and no OAuth (disabled = 0)
// ============================================================================

func TestCE_DisabledFeatures(t *testing.T) {
	limits := CELimits()

	// In CE, LDAP and OAuth are disabled entirely (0 = disabled, not unlimited)
	// These are special cases where 0 means disabled because the feature flags
	// (FeatureLDAP, FeatureOAuth) gate access before limits are checked
	if limits.MaxLDAPServers != 0 {
		t.Errorf("CE MaxLDAPServers = %d, want 0 (disabled)", limits.MaxLDAPServers)
	}
	if limits.MaxOAuthProviders != 0 {
		t.Errorf("CE MaxOAuthProviders = %d, want 0 (disabled)", limits.MaxOAuthProviders)
	}

	// CE info should have no features
	info := NewCEInfo()
	if info.HasFeature(FeatureLDAP) {
		t.Error("CE should not have FeatureLDAP")
	}
	if info.HasFeature(FeatureOAuth) {
		t.Error("CE should not have FeatureOAuth")
	}
}
