package handlers

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	apierrors "github.com/fr4nsys/usulnet/internal/api/errors"
	"github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/audit"
)

type LicenseHandler struct {
	BaseHandler
	licenseProvider *license.Provider
	auditService    *audit.Service
}

func NewLicenseHandler(
	licenseProvider *license.Provider,
	auditService *audit.Service,
	log *logger.Logger,
) *LicenseHandler {
	return &LicenseHandler{
		BaseHandler:     NewBaseHandler(log),
		licenseProvider: licenseProvider,
		auditService:    auditService,
	}
}

func (h *LicenseHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Get("/", h.GetLicense)
	r.Post("/", h.ActivateLicense)
	r.Delete("/", h.DeactivateLicense)
	r.Get("/status", h.GetLicenseStatus)

	return r
}

type LicenseInfoResponse struct {
	Edition     string                `json:"edition"`
	EditionName string                `json:"edition_name"`
	Valid       bool                  `json:"valid"`
	LicenseID   string                `json:"license_id,omitempty"`
	ExpiresAt   *string               `json:"expires_at,omitempty"`
	Features    []string              `json:"features"`
	Limits      LicenseLimitsResponse `json:"limits"`
	InstanceID  string                `json:"instance_id,omitempty"`

	ActivatedAt       *string `json:"activated_at,omitempty"`
	LastCheckinAt     *string `json:"last_checkin_at,omitempty"`
	SyncWarning       bool    `json:"sync_warning,omitempty"`
	SyncDegradationAt *string `json:"sync_degradation_at,omitempty"`
}

type LicenseLimitsResponse struct {
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

type ActivateLicenseRequest struct {
	LicenseKey string `json:"license_key" validate:"required"`
}

type ActivateLicenseResponse struct {
	Success bool               `json:"success"`
	Message string             `json:"message"`
	License LicenseInfoResponse `json:"license"`
}

type DeactivateLicenseResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type LicenseStatusResponse struct {
	License       LicenseInfoResponse   `json:"license"`
	DaysRemaining int                   `json:"days_remaining"`
	IsExpired     bool                  `json:"is_expired"`
	IsDegraded    bool                  `json:"is_degraded"`
	DegradedFrom  string                `json:"degraded_from,omitempty"`
	ActiveLimits  LicenseLimitsResponse `json:"active_limits"`
	StatusMessage string                `json:"status_message"`
}

func (h *LicenseHandler) GetLicense(w http.ResponseWriter, r *http.Request) {
	if h.licenseProvider == nil {
		h.OK(w, toLicenseInfoResponse(license.NewCEInfo(), ""))
		return
	}

	info := h.licenseProvider.GetInfo()
	instanceID := h.licenseProvider.InstanceID()

	h.OK(w, toLicenseInfoResponse(info, instanceID))
}

func (h *LicenseHandler) ActivateLicense(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req ActivateLicenseRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.LicenseKey == "" {
		h.Error(w, apierrors.MissingField("license_key"))
		return
	}

	if h.licenseProvider == nil {
		h.Error(w, apierrors.Internal("license provider not available"))
		return
	}

	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.licenseProvider.Activate(req.LicenseKey); err != nil {
		if h.auditService != nil {
			claims := h.GetClaims(r)
			var username *string
			if claims != nil {
				username = &claims.Username
			}
			errMsg := err.Error()
			h.auditService.LogAsync(ctx, audit.LogEntry{
				UserID:       &userID,
				Username:     username,
				Action:       "license_activate",
				ResourceType: "license",
				Details: map[string]any{
					"error": errMsg,
				},
				IPAddress: strPtr(getClientIP(r)),
				UserAgent: strPtr(r.UserAgent()),
				Success:   false,
				ErrorMsg:  &errMsg,
			})
		}

		h.Error(w, apierrors.NewErrorWithDetails(
			http.StatusBadRequest,
			apierrors.ErrCodeLicenseInvalid,
			"Failed to activate license",
			map[string]string{"reason": err.Error()},
		))
		return
	}

	info := h.licenseProvider.GetInfo()
	instanceID := h.licenseProvider.InstanceID()

	if h.auditService != nil {
		claims := h.GetClaims(r)
		var username *string
		if claims != nil {
			username = &claims.Username
		}
		h.auditService.LogAsync(ctx, audit.LogEntry{
			UserID:       &userID,
			Username:     username,
			Action:       "license_activate",
			ResourceType: "license",
			ResourceID:   strPtr(info.LicenseID),
			Details: map[string]any{
				"edition":    string(info.Edition),
				"license_id": info.LicenseID,
			},
			IPAddress: strPtr(getClientIP(r)),
			UserAgent: strPtr(r.UserAgent()),
			Success:   true,
		})
	}

	h.OK(w, ActivateLicenseResponse{
		Success: true,
		Message: "License activated successfully",
		License: toLicenseInfoResponse(info, instanceID),
	})
}

func (h *LicenseHandler) DeactivateLicense(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.licenseProvider == nil {
		h.Error(w, apierrors.Internal("license provider not available"))
		return
	}

	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	currentInfo := h.licenseProvider.GetInfo()

	if err := h.licenseProvider.Deactivate(); err != nil {
		h.InternalError(w, err)
		return
	}

	if h.auditService != nil {
		claims := h.GetClaims(r)
		var username *string
		if claims != nil {
			username = &claims.Username
		}
		h.auditService.LogAsync(ctx, audit.LogEntry{
			UserID:       &userID,
			Username:     username,
			Action:       "license_deactivate",
			ResourceType: "license",
			ResourceID:   strPtr(currentInfo.LicenseID),
			Details: map[string]any{
				"previous_edition": string(currentInfo.Edition),
				"license_id":       currentInfo.LicenseID,
			},
			IPAddress: strPtr(getClientIP(r)),
			UserAgent: strPtr(r.UserAgent()),
			Success:   true,
		})
	}

	h.OK(w, DeactivateLicenseResponse{
		Success: true,
		Message: "License deactivated, reverted to Community Edition",
	})
}

func (h *LicenseHandler) GetLicenseStatus(w http.ResponseWriter, r *http.Request) {
	var info *license.Info
	var instanceID string

	if h.licenseProvider == nil {
		info = license.NewCEInfo()
	} else {
		info = h.licenseProvider.GetInfo()
		instanceID = h.licenseProvider.InstanceID()
	}

	degradation := license.GetDegradationState(info)
	daysRemaining := license.DaysUntilExpiration(info)

	h.OK(w, LicenseStatusResponse{
		License:       toLicenseInfoResponse(info, instanceID),
		DaysRemaining: daysRemaining,
		IsExpired:     degradation.IsExpired,
		IsDegraded:    degradation.IsExpired,
		DegradedFrom:  string(degradation.PreviousEdition),
		ActiveLimits: LicenseLimitsResponse{
			MaxNodes:                degradation.ActiveLimits.MaxNodes,
			MaxUsers:                degradation.ActiveLimits.MaxUsers,
			MaxTeams:                degradation.ActiveLimits.MaxTeams,
			MaxCustomRoles:          degradation.ActiveLimits.MaxCustomRoles,
			MaxLDAPServers:          degradation.ActiveLimits.MaxLDAPServers,
			MaxOAuthProviders:       degradation.ActiveLimits.MaxOAuthProviders,
			MaxAPIKeys:              degradation.ActiveLimits.MaxAPIKeys,
			MaxGitConnections:       degradation.ActiveLimits.MaxGitConnections,
			MaxS3Connections:        degradation.ActiveLimits.MaxS3Connections,
			MaxBackupDestinations:   degradation.ActiveLimits.MaxBackupDestinations,
			MaxNotificationChannels: degradation.ActiveLimits.MaxNotificationChannels,
		},
		StatusMessage: degradation.Message,
	})
}

func toLicenseInfoResponse(info *license.Info, instanceID string) LicenseInfoResponse {
	features := make([]string, len(info.Features))
	for i, f := range info.Features {
		features[i] = string(f)
	}

	var expiresAt *string
	if info.ExpiresAt != nil {
		s := info.ExpiresAt.UTC().Format(time.RFC3339)
		expiresAt = &s
	}

	var activatedAt, lastCheckinAt, syncDegradationAt *string
	if info.ActivatedAt != nil {
		s := info.ActivatedAt.UTC().Format(time.RFC3339)
		activatedAt = &s
	}
	if info.LastCheckinAt != nil {
		s := info.LastCheckinAt.UTC().Format(time.RFC3339)
		lastCheckinAt = &s
	}
	if info.SyncDegradationAt != nil {
		s := info.SyncDegradationAt.UTC().Format(time.RFC3339)
		syncDegradationAt = &s
	}

	return LicenseInfoResponse{
		Edition:           string(info.Edition),
		EditionName:       info.EditionName(),
		Valid:             info.Valid,
		LicenseID:         info.LicenseID,
		ExpiresAt:         expiresAt,
		Features:          features,
		Limits: LicenseLimitsResponse{
			MaxNodes:                info.Limits.MaxNodes,
			MaxUsers:                info.Limits.MaxUsers,
			MaxTeams:                info.Limits.MaxTeams,
			MaxCustomRoles:          info.Limits.MaxCustomRoles,
			MaxLDAPServers:          info.Limits.MaxLDAPServers,
			MaxOAuthProviders:       info.Limits.MaxOAuthProviders,
			MaxAPIKeys:              info.Limits.MaxAPIKeys,
			MaxGitConnections:       info.Limits.MaxGitConnections,
			MaxS3Connections:        info.Limits.MaxS3Connections,
			MaxBackupDestinations:   info.Limits.MaxBackupDestinations,
			MaxNotificationChannels: info.Limits.MaxNotificationChannels,
		},
		InstanceID:        instanceID,
		ActivatedAt:       activatedAt,
		LastCheckinAt:     lastCheckinAt,
		SyncWarning:       info.SyncWarning,
		SyncDegradationAt: syncDegradationAt,
	}
}
