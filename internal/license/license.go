// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package license

import "time"

type Edition string

const (
	CE         Edition = "ce"
	Business   Edition = "biz"
	Enterprise Edition = "ee"
)

type Feature string

const (
	FeatureCustomRoles       Feature = "custom_roles"
	FeatureOAuth             Feature = "oauth"
	FeatureLDAP              Feature = "ldap"
	FeatureMultiNotification Feature = "multi_notification"
	FeatureAuditExport       Feature = "audit_export"
	FeatureMultiBackup       Feature = "multi_backup"
	FeatureAPIKeys           Feature = "api_keys"
	FeaturePrioritySupport   Feature = "priority_support"
	FeatureSSOSAML           Feature = "sso_saml"
	FeatureHAMode            Feature = "ha_mode"
	FeatureSharedTerminals   Feature = "shared_terminals"
	FeatureWhiteLabel        Feature = "white_label"
	FeatureSwarm             Feature = "swarm"
	FeatureCompliance        Feature = "compliance"
	FeatureOPAPolicies       Feature = "opa_policies"
	FeatureImageSigning      Feature = "image_signing"
	FeatureRuntimeSecurity   Feature = "runtime_security"
	FeatureLogAggregation    Feature = "log_aggregation"
	FeatureCustomDashboards  Feature = "custom_dashboards"
	FeatureTemplateCatalog   Feature = "template_catalog"
	FeatureGitSync           Feature = "git_sync"
	FeatureEphemeralEnvs     Feature = "ephemeral_envs"
	FeatureManifestBuilder   Feature = "manifest_builder"
	FeatureRegistryBrowsing  Feature = "registry_browsing"
)

func AllBusinessFeatures() []Feature {
	return []Feature{
		FeatureCustomRoles,
		FeatureOAuth,
		FeatureLDAP,
		FeatureMultiNotification,
		FeatureAuditExport,
		FeatureMultiBackup,
		FeatureAPIKeys,
		FeaturePrioritySupport,
		FeatureSwarm,
		FeatureTemplateCatalog,
		FeatureGitSync,
		FeatureRegistryBrowsing,
	}
}

func AllEnterpriseFeatures() []Feature {
	return []Feature{
		FeatureCustomRoles,
		FeatureOAuth,
		FeatureLDAP,
		FeatureMultiNotification,
		FeatureAuditExport,
		FeatureMultiBackup,
		FeatureAPIKeys,
		FeaturePrioritySupport,
		FeatureSwarm,
		FeatureTemplateCatalog,
		FeatureSSOSAML,
		FeatureHAMode,
		FeatureSharedTerminals,
		FeatureWhiteLabel,
		FeatureCompliance,
		FeatureOPAPolicies,
		FeatureImageSigning,
		FeatureRuntimeSecurity,
		FeatureLogAggregation,
		FeatureCustomDashboards,
		FeatureGitSync,
		FeatureEphemeralEnvs,
		FeatureManifestBuilder,
		FeatureRegistryBrowsing,
	}
}

type Limits struct {
	MaxNodes                int `json:"max_nodes"`
	MaxUsers                int `json:"max_users"`
	MaxTeams                int `json:"max_teams"`
	MaxCustomRoles          int `json:"max_custom_roles"`
	MaxLDAPServers          int `json:"max_ldap_servers"`
	MaxOAuthProviders       int `json:"max_oauth_providers"`
	MaxAPIKeys              int `json:"max_api_keys"`
	MaxGitConnections       int `json:"max_git_connections"`
	MaxS3Connections        int `json:"max_s3_connections"`
	MaxBackupDestinations   int `json:"max_backup_destinations"`
	MaxNotificationChannels int `json:"max_notification_channels"`
}

const (
	CEBaseNodes     = 1
	ReceiptTTL      = 7 * 24 * time.Hour
	SyncGracePeriod = 7 * 24 * time.Hour
)

func CELimits() Limits {
	return Limits{
		MaxNodes:                CEBaseNodes,
		MaxUsers:                3,
		MaxTeams:                1,
		MaxCustomRoles:          1,
		MaxLDAPServers:          1,
		MaxOAuthProviders:       0,
		MaxAPIKeys:              3,
		MaxGitConnections:       1,
		MaxS3Connections:        1,
		MaxBackupDestinations:   1,
		MaxNotificationChannels: 1,
	}
}

func BusinessDefaultLimits() Limits {
	return Limits{
		MaxNodes:                0,
		MaxUsers:                0,
		MaxTeams:                5,
		MaxCustomRoles:          0,
		MaxLDAPServers:          3,
		MaxOAuthProviders:       3,
		MaxAPIKeys:              25,
		MaxGitConnections:       5,
		MaxS3Connections:        5,
		MaxBackupDestinations:   5,
		MaxNotificationChannels: 0,
	}
}

func EnterpriseLimits() Limits {
	return Limits{}
}

type LimitProvider interface {
	GetLimits() Limits
}

type Info struct {
	Edition    Edition    `json:"edition"`
	Valid      bool       `json:"valid"`
	LicenseID  string     `json:"license_id,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	Features   []Feature  `json:"features"`
	Limits     Limits     `json:"limits"`
	InstanceID string     `json:"instance_id,omitempty"`

	ActivatedAt       *time.Time `json:"activated_at,omitempty"`
	LastCheckinAt     *time.Time `json:"last_checkin_at,omitempty"`
	SyncWarning       bool       `json:"sync_warning,omitempty"`
	SyncDegradationAt *time.Time `json:"sync_degradation_at,omitempty"`
}

func (i *Info) HasFeature(f Feature) bool {
	if i == nil || !i.Valid {
		return false
	}
	for _, feat := range i.Features {
		if feat == f {
			return true
		}
	}
	return false
}

func (i *Info) IsExpired() bool {
	if i == nil || i.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*i.ExpiresAt)
}

func (i *Info) EditionName() string {
	if i == nil {
		return "Community Edition"
	}
	switch i.Edition {
	case Business:
		return "Business"
	case Enterprise:
		return "Enterprise"
	default:
		return "Community Edition"
	}
}

func NewCEInfo() *Info {
	limits := CELimits()
	return &Info{
		Edition:  CE,
		Valid:    true,
		Features: nil,
		Limits:   limits,
	}
}

func IsWithinLimit(current, limit int) bool {
	if limit <= 0 {
		return true
	}
	return current < limit
}

func LimitUsagePercent(current, limit int) float64 {
	if limit <= 0 {
		return 0
	}
	return float64(current) / float64(limit) * 100
}
