// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// Mock implementations
// ============================================================================

type mockAuditLogger struct {
	mu              sync.Mutex
	loginCalls      int
	logoutCalls     int
	pwdChangeCalls  int
	lastLoginUserID *uuid.UUID
	lastLoginOK     bool
}

func (m *mockAuditLogger) LogLogin(_ context.Context, userID *uuid.UUID, _, _, _ string, success bool, _ *string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loginCalls++
	m.lastLoginUserID = userID
	m.lastLoginOK = success
}

func (m *mockAuditLogger) LogLogout(_ context.Context, _ uuid.UUID, _, _, _ string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logoutCalls++
}

func (m *mockAuditLogger) LogPasswordChange(_ context.Context, _ uuid.UUID, _, _, _ string, _ bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pwdChangeCalls++
}

type mockJWTBlacklist struct {
	mu                sync.Mutex
	blacklisted       map[string]bool
	userBlacklist     map[string]time.Time // userID -> issuedBefore
	blacklistErr      error
	isBlacklistedErr  error
}

func newMockJWTBlacklist() *mockJWTBlacklist {
	return &mockJWTBlacklist{
		blacklisted:   make(map[string]bool),
		userBlacklist: make(map[string]time.Time),
	}
}

func (m *mockJWTBlacklist) BlacklistToken(_ context.Context, jti string, _ time.Time, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.blacklistErr != nil {
		return m.blacklistErr
	}
	m.blacklisted[jti] = true
	return nil
}

func (m *mockJWTBlacklist) IsBlacklisted(_ context.Context, jti string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.isBlacklistedErr != nil {
		return false, m.isBlacklistedErr
	}
	return m.blacklisted[jti], nil
}

func (m *mockJWTBlacklist) BlacklistUserTokens(_ context.Context, userID string, issuedBefore time.Time, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.blacklistErr != nil {
		return m.blacklistErr
	}
	m.userBlacklist[userID] = issuedBefore
	return nil
}

func (m *mockJWTBlacklist) IsUserTokenBlacklisted(_ context.Context, userID string, issuedAt time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.isBlacklistedErr != nil {
		return false, m.isBlacklistedErr
	}
	issuedBefore, ok := m.userBlacklist[userID]
	if !ok {
		return false, nil
	}
	return issuedAt.Before(issuedBefore), nil
}

type mockTOTPValidator struct {
	valid bool
	err   error
}

func (m *mockTOTPValidator) ValidateTOTPCode(_ context.Context, _ uuid.UUID, _ string) (bool, error) {
	return m.valid, m.err
}

type mockLDAPProvider struct {
	name    string
	enabled bool
	user    *LDAPUser
	err     error
}

func (m *mockLDAPProvider) Authenticate(_ context.Context, _, _ string) (*LDAPUser, error) {
	return m.user, m.err
}

func (m *mockLDAPProvider) GetName() string  { return m.name }
func (m *mockLDAPProvider) IsEnabled() bool  { return m.enabled }

type mockOAuthProvider struct {
	name          string
	enabled       bool
	autoProvision bool
	authURL       string
	user          *OAuthUser
	err           error
}

func (m *mockOAuthProvider) GetAuthURL(state string) string           { return m.authURL + "?state=" + state }
func (m *mockOAuthProvider) Exchange(_ context.Context, _ string) (*OAuthUser, error) {
	return m.user, m.err
}
func (m *mockOAuthProvider) GetName() string              { return m.name }
func (m *mockOAuthProvider) IsEnabled() bool              { return m.enabled }
func (m *mockOAuthProvider) AutoProvisionEnabled() bool   { return m.autoProvision }

// ============================================================================
// Test helpers
// ============================================================================

func newTestAuthService() *Service {
	jwtSvc := newTestJWTService()
	cfg := DefaultAuthConfig()
	return NewService(nil, nil, nil, jwtSvc, nil, cfg, logger.Nop())
}

// ============================================================================
// DefaultAuthConfig
// ============================================================================

func TestDefaultAuthConfig(t *testing.T) {
	cfg := DefaultAuthConfig()

	if cfg.MaxLoginAttempts != 5 {
		t.Errorf("expected MaxLoginAttempts=5, got %d", cfg.MaxLoginAttempts)
	}
	if cfg.LockoutDuration != 15*time.Minute {
		t.Errorf("expected LockoutDuration=15m, got %v", cfg.LockoutDuration)
	}
	if cfg.RequirePasswordChange {
		t.Error("expected RequirePasswordChange=false")
	}
	if cfg.PasswordMinLength != 8 {
		t.Errorf("expected PasswordMinLength=8, got %d", cfg.PasswordMinLength)
	}
	if cfg.AllowAPIKeyAuth != true {
		t.Error("expected AllowAPIKeyAuth=true")
	}

	// Verify embedded PasswordPolicy uses defaults
	policy := cfg.PasswordPolicy
	defPolicy := crypto.DefaultPasswordPolicy()
	if policy.MinLength != defPolicy.MinLength {
		t.Errorf("expected PasswordPolicy.MinLength=%d, got %d", defPolicy.MinLength, policy.MinLength)
	}
	if policy.RequireUppercase != defPolicy.RequireUppercase {
		t.Errorf("expected PasswordPolicy.RequireUppercase=%v, got %v", defPolicy.RequireUppercase, policy.RequireUppercase)
	}
}

// ============================================================================
// AuthConfig struct fields
// ============================================================================

func TestAuthConfig_Fields(t *testing.T) {
	cfg := AuthConfig{
		MaxLoginAttempts:      10,
		LockoutDuration:       30 * time.Minute,
		RequirePasswordChange: true,
		PasswordMinLength:     12,
		PasswordPolicy:        crypto.StrictPasswordPolicy(),
		AllowAPIKeyAuth:       false,
	}

	if cfg.MaxLoginAttempts != 10 {
		t.Errorf("MaxLoginAttempts: expected 10, got %d", cfg.MaxLoginAttempts)
	}
	if cfg.LockoutDuration != 30*time.Minute {
		t.Errorf("LockoutDuration: expected 30m, got %v", cfg.LockoutDuration)
	}
	if !cfg.RequirePasswordChange {
		t.Error("RequirePasswordChange: expected true")
	}
	if cfg.PasswordMinLength != 12 {
		t.Errorf("PasswordMinLength: expected 12, got %d", cfg.PasswordMinLength)
	}
	if cfg.AllowAPIKeyAuth {
		t.Error("AllowAPIKeyAuth: expected false")
	}
	if !cfg.PasswordPolicy.RequireSpecial {
		t.Error("StrictPasswordPolicy should require special characters")
	}
}

// ============================================================================
// NewService constructor
// ============================================================================

func TestNewService_NilLogger(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil, DefaultAuthConfig(), nil)
	if svc == nil {
		t.Fatal("expected non-nil service with nil logger")
	}
	if svc.logger == nil {
		t.Fatal("expected logger to be set to Nop when nil is passed")
	}
}

func TestNewService_WithLogger(t *testing.T) {
	log := logger.Nop()
	svc := NewService(nil, nil, nil, nil, nil, DefaultAuthConfig(), log)
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
	if svc.logger == nil {
		t.Fatal("expected logger to be set")
	}
}

func TestNewService_NilRepos(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil, DefaultAuthConfig(), logger.Nop())
	if svc == nil {
		t.Fatal("expected non-nil service with nil repos")
	}
	if svc.userRepo != nil {
		t.Error("expected nil userRepo")
	}
	if svc.sessionRepo != nil {
		t.Error("expected nil sessionRepo")
	}
	if svc.apiKeyRepo != nil {
		t.Error("expected nil apiKeyRepo")
	}
}

func TestNewService_ConfigPreserved(t *testing.T) {
	cfg := AuthConfig{
		MaxLoginAttempts: 99,
		LockoutDuration:  42 * time.Minute,
		AllowAPIKeyAuth:  false,
	}
	svc := NewService(nil, nil, nil, nil, nil, cfg, logger.Nop())
	if svc.config.MaxLoginAttempts != 99 {
		t.Errorf("expected MaxLoginAttempts=99, got %d", svc.config.MaxLoginAttempts)
	}
	if svc.config.LockoutDuration != 42*time.Minute {
		t.Errorf("expected LockoutDuration=42m, got %v", svc.config.LockoutDuration)
	}
	if svc.config.AllowAPIKeyAuth {
		t.Error("expected AllowAPIKeyAuth=false")
	}
}

func TestNewService_OAuthProviderMapInitialized(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil, DefaultAuthConfig(), logger.Nop())
	if svc.oauthProviders == nil {
		t.Fatal("expected oauthProviders map to be initialized")
	}
	if len(svc.oauthProviders) != 0 {
		t.Errorf("expected empty oauthProviders, got %d entries", len(svc.oauthProviders))
	}
}

// ============================================================================
// SetJWTBlacklist
// ============================================================================

func TestSetJWTBlacklist(t *testing.T) {
	svc := newTestAuthService()

	if svc.HasJWTBlacklist() {
		t.Error("expected no blacklist before SetJWTBlacklist")
	}

	bl := newMockJWTBlacklist()
	svc.SetJWTBlacklist(bl)

	if !svc.HasJWTBlacklist() {
		t.Error("expected blacklist after SetJWTBlacklist")
	}
}

func TestSetJWTBlacklist_NilClearsBlacklist(t *testing.T) {
	svc := newTestAuthService()
	svc.SetJWTBlacklist(newMockJWTBlacklist())
	if !svc.HasJWTBlacklist() {
		t.Fatal("precondition: expected blacklist set")
	}

	svc.SetJWTBlacklist(nil)
	if svc.HasJWTBlacklist() {
		t.Error("expected no blacklist after setting nil")
	}
}

func TestSetJWTBlacklist_ThreadSafe(t *testing.T) {
	svc := newTestAuthService()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			svc.SetJWTBlacklist(newMockJWTBlacklist())
		}()
		go func() {
			defer wg.Done()
			_ = svc.HasJWTBlacklist()
		}()
	}
	wg.Wait()
}

// ============================================================================
// SetAuditService
// ============================================================================

func TestSetAuditService(t *testing.T) {
	svc := newTestAuthService()

	// Initially nil
	svc.auditMu.RLock()
	if svc.auditSvc != nil {
		t.Error("expected nil audit service initially")
	}
	svc.auditMu.RUnlock()

	audit := &mockAuditLogger{}
	svc.SetAuditService(audit)

	svc.auditMu.RLock()
	if svc.auditSvc == nil {
		t.Error("expected audit service to be set")
	}
	svc.auditMu.RUnlock()
}

func TestSetAuditService_ThreadSafe(t *testing.T) {
	svc := newTestAuthService()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			svc.SetAuditService(&mockAuditLogger{})
		}()
		go func() {
			defer wg.Done()
			svc.auditMu.RLock()
			_ = svc.auditSvc
			svc.auditMu.RUnlock()
		}()
	}
	wg.Wait()
}

// ============================================================================
// SetTOTPValidator
// ============================================================================

func TestSetTOTPValidator(t *testing.T) {
	svc := newTestAuthService()

	// Without validator, ValidateTOTPCode should return error
	_, err := svc.ValidateTOTPCode(context.Background(), uuid.New(), "123456")
	if err == nil {
		t.Error("expected error when TOTP validator not set")
	}
	if err.Error() != "TOTP validation not configured" {
		t.Errorf("expected 'TOTP validation not configured', got %q", err.Error())
	}

	// Set validator
	svc.SetTOTPValidator(&mockTOTPValidator{valid: true})

	valid, err := svc.ValidateTOTPCode(context.Background(), uuid.New(), "123456")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Error("expected valid TOTP code")
	}
}

func TestSetTOTPValidator_Invalid(t *testing.T) {
	svc := newTestAuthService()
	svc.SetTOTPValidator(&mockTOTPValidator{valid: false})

	valid, err := svc.ValidateTOTPCode(context.Background(), uuid.New(), "000000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Error("expected invalid TOTP code")
	}
}

func TestSetTOTPValidator_Error(t *testing.T) {
	svc := newTestAuthService()
	svc.SetTOTPValidator(&mockTOTPValidator{err: errors.New("totp backend failure")})

	_, err := svc.ValidateTOTPCode(context.Background(), uuid.New(), "123456")
	if err == nil {
		t.Fatal("expected error from TOTP validator")
	}
	if err.Error() != "totp backend failure" {
		t.Errorf("expected 'totp backend failure', got %q", err.Error())
	}
}

func TestSetTOTPValidator_ThreadSafe(t *testing.T) {
	svc := newTestAuthService()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			svc.SetTOTPValidator(&mockTOTPValidator{valid: true})
		}()
		go func() {
			defer wg.Done()
			// This may return error (not configured) or succeed depending on race.
			// We just check it doesn't panic.
			_, _ = svc.ValidateTOTPCode(context.Background(), uuid.New(), "123456")
		}()
	}
	wg.Wait()
}

// ============================================================================
// RegisterLDAPProvider / SetLDAPProvider
// ============================================================================

func TestRegisterLDAPProvider(t *testing.T) {
	svc := newTestAuthService()

	provider := &mockLDAPProvider{name: "corp-ldap", enabled: true}
	svc.RegisterLDAPProvider(provider)

	svc.providerMu.RLock()
	if len(svc.ldapProviders) != 1 {
		t.Errorf("expected 1 LDAP provider, got %d", len(svc.ldapProviders))
	}
	svc.providerMu.RUnlock()
}

func TestRegisterLDAPProvider_Multiple(t *testing.T) {
	svc := newTestAuthService()

	svc.RegisterLDAPProvider(&mockLDAPProvider{name: "ldap-1", enabled: true})
	svc.RegisterLDAPProvider(&mockLDAPProvider{name: "ldap-2", enabled: true})

	svc.providerMu.RLock()
	if len(svc.ldapProviders) != 2 {
		t.Errorf("expected 2 LDAP providers, got %d", len(svc.ldapProviders))
	}
	svc.providerMu.RUnlock()
}

// ============================================================================
// RegisterOAuthProvider
// ============================================================================

func TestRegisterOAuthProvider(t *testing.T) {
	svc := newTestAuthService()

	provider := &mockOAuthProvider{name: "github", enabled: true}
	svc.RegisterOAuthProvider("github", provider)

	svc.providerMu.RLock()
	if len(svc.oauthProviders) != 1 {
		t.Errorf("expected 1 OAuth provider, got %d", len(svc.oauthProviders))
	}
	p, ok := svc.oauthProviders["github"]
	svc.providerMu.RUnlock()

	if !ok {
		t.Fatal("expected 'github' provider to be registered")
	}
	if p.GetName() != "github" {
		t.Errorf("expected provider name 'github', got %q", p.GetName())
	}
}

func TestRegisterOAuthProvider_Overwrite(t *testing.T) {
	svc := newTestAuthService()

	svc.RegisterOAuthProvider("github", &mockOAuthProvider{name: "github-v1", enabled: true})
	svc.RegisterOAuthProvider("github", &mockOAuthProvider{name: "github-v2", enabled: true})

	svc.providerMu.RLock()
	if len(svc.oauthProviders) != 1 {
		t.Errorf("expected 1 OAuth provider after overwrite, got %d", len(svc.oauthProviders))
	}
	p := svc.oauthProviders["github"]
	svc.providerMu.RUnlock()

	if p.GetName() != "github-v2" {
		t.Errorf("expected overwritten provider 'github-v2', got %q", p.GetName())
	}
}

// ============================================================================
// GetOAuthAuthURL
// ============================================================================

func TestGetOAuthAuthURL_Success(t *testing.T) {
	svc := newTestAuthService()

	provider := &mockOAuthProvider{
		name:    "github",
		enabled: true,
		authURL: "https://github.com/login/oauth/authorize",
	}
	svc.RegisterOAuthProvider("github", provider)

	url, err := svc.GetOAuthAuthURL("github", "random-state")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if url != "https://github.com/login/oauth/authorize?state=random-state" {
		t.Errorf("unexpected URL: %q", url)
	}
}

func TestGetOAuthAuthURL_UnknownProvider(t *testing.T) {
	svc := newTestAuthService()

	_, err := svc.GetOAuthAuthURL("unknown", "state")
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

func TestGetOAuthAuthURL_DisabledProvider(t *testing.T) {
	svc := newTestAuthService()

	svc.RegisterOAuthProvider("github", &mockOAuthProvider{
		name:    "github",
		enabled: false,
		authURL: "https://github.com/login/oauth/authorize",
	})

	_, err := svc.GetOAuthAuthURL("github", "state")
	if err == nil {
		t.Fatal("expected error for disabled provider")
	}
}

// ============================================================================
// LDAPUser struct fields
// ============================================================================

func TestLDAPUser_Fields(t *testing.T) {
	user := LDAPUser{
		Username: "jdoe",
		Email:    "jdoe@corp.example",
		DN:       "cn=jdoe,ou=users,dc=corp,dc=example",
		Groups:   []string{"admins", "developers"},
		Role:     models.RoleAdmin,
	}

	if user.Username != "jdoe" {
		t.Errorf("Username: expected 'jdoe', got %q", user.Username)
	}
	if user.Email != "jdoe@corp.example" {
		t.Errorf("Email: expected 'jdoe@corp.example', got %q", user.Email)
	}
	if user.DN != "cn=jdoe,ou=users,dc=corp,dc=example" {
		t.Errorf("DN: expected full DN, got %q", user.DN)
	}
	if len(user.Groups) != 2 {
		t.Errorf("Groups: expected 2, got %d", len(user.Groups))
	}
	if user.Role != models.RoleAdmin {
		t.Errorf("Role: expected admin, got %q", user.Role)
	}
}

func TestLDAPUser_EmptyGroups(t *testing.T) {
	user := LDAPUser{Username: "nobody"}
	if user.Groups != nil {
		t.Error("expected nil Groups by default")
	}
}

// ============================================================================
// OAuthUser struct fields
// ============================================================================

func TestOAuthUser_Fields(t *testing.T) {
	user := OAuthUser{
		ID:       "gh-12345",
		Username: "octocat",
		Email:    "octocat@github.com",
		Name:     "Octo Cat",
		Provider: "github",
		Role:     models.RoleViewer,
	}

	if user.ID != "gh-12345" {
		t.Errorf("ID: expected 'gh-12345', got %q", user.ID)
	}
	if user.Username != "octocat" {
		t.Errorf("Username: expected 'octocat', got %q", user.Username)
	}
	if user.Email != "octocat@github.com" {
		t.Errorf("Email: expected 'octocat@github.com', got %q", user.Email)
	}
	if user.Name != "Octo Cat" {
		t.Errorf("Name: expected 'Octo Cat', got %q", user.Name)
	}
	if user.Provider != "github" {
		t.Errorf("Provider: expected 'github', got %q", user.Provider)
	}
	if user.Role != models.RoleViewer {
		t.Errorf("Role: expected viewer, got %q", user.Role)
	}
}

// ============================================================================
// LoginInput / LoginResult struct fields
// ============================================================================

func TestLoginInput_Fields(t *testing.T) {
	input := LoginInput{
		Username:  "admin",
		Password:  "secret",
		UserAgent: "Mozilla/5.0",
		IPAddress: "192.168.1.1",
	}

	if input.Username != "admin" {
		t.Errorf("Username: expected 'admin', got %q", input.Username)
	}
	if input.Password != "secret" {
		t.Errorf("Password: expected 'secret', got %q", input.Password)
	}
	if input.UserAgent != "Mozilla/5.0" {
		t.Errorf("UserAgent: expected 'Mozilla/5.0', got %q", input.UserAgent)
	}
	if input.IPAddress != "192.168.1.1" {
		t.Errorf("IPAddress: expected '192.168.1.1', got %q", input.IPAddress)
	}
}

func TestLoginResult_Fields(t *testing.T) {
	userID := uuid.New()
	sessionID := uuid.New()
	expiresAt := time.Now().Add(15 * time.Minute)

	result := LoginResult{
		User: &models.User{
			ID:       userID,
			Username: "testuser",
		},
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		ExpiresAt:    expiresAt,
		SessionID:    sessionID,
		RequiresTOTP: true,
	}

	if result.User.ID != userID {
		t.Errorf("User.ID mismatch")
	}
	if result.AccessToken != "access-token" {
		t.Errorf("AccessToken: expected 'access-token', got %q", result.AccessToken)
	}
	if result.RefreshToken != "refresh-token" {
		t.Errorf("RefreshToken: expected 'refresh-token', got %q", result.RefreshToken)
	}
	if !result.ExpiresAt.Equal(expiresAt) {
		t.Errorf("ExpiresAt mismatch")
	}
	if result.SessionID != sessionID {
		t.Errorf("SessionID mismatch")
	}
	if !result.RequiresTOTP {
		t.Error("expected RequiresTOTP=true")
	}
}

// ============================================================================
// CreateTokenValidator
// ============================================================================

func TestCreateTokenValidator_NoBlacklist(t *testing.T) {
	svc := newTestAuthService()
	validator := svc.CreateTokenValidator()

	err := validator(context.Background(), "token", "user-id", "jti-1", time.Now())
	if err != nil {
		t.Fatalf("expected nil error without blacklist, got %v", err)
	}
}

func TestCreateTokenValidator_BlacklistedJTI(t *testing.T) {
	svc := newTestAuthService()
	bl := newMockJWTBlacklist()
	bl.blacklisted["jti-revoked"] = true
	svc.SetJWTBlacklist(bl)

	validator := svc.CreateTokenValidator()

	err := validator(context.Background(), "token", "user-id", "jti-revoked", time.Now())
	if !errors.Is(err, ErrTokenRevoked) {
		t.Errorf("expected ErrTokenRevoked, got %v", err)
	}
}

func TestCreateTokenValidator_NotBlacklisted(t *testing.T) {
	svc := newTestAuthService()
	bl := newMockJWTBlacklist()
	svc.SetJWTBlacklist(bl)

	validator := svc.CreateTokenValidator()

	err := validator(context.Background(), "token", "user-id", "jti-clean", time.Now())
	if err != nil {
		t.Fatalf("expected nil error for non-blacklisted token, got %v", err)
	}
}

func TestCreateTokenValidator_UserBlacklisted(t *testing.T) {
	svc := newTestAuthService()
	bl := newMockJWTBlacklist()
	bl.userBlacklist["user-id"] = time.Now() // All tokens issued before now
	svc.SetJWTBlacklist(bl)

	validator := svc.CreateTokenValidator()

	// Token issued in the past (before blacklist cutoff)
	err := validator(context.Background(), "token", "user-id", "", time.Now().Add(-1*time.Hour))
	if !errors.Is(err, ErrTokenRevoked) {
		t.Errorf("expected ErrTokenRevoked for user-blacklisted token, got %v", err)
	}
}

func TestCreateTokenValidator_BlacklistError_FailsClosed(t *testing.T) {
	svc := newTestAuthService()
	bl := newMockJWTBlacklist()
	bl.isBlacklistedErr = errors.New("redis unavailable")
	svc.SetJWTBlacklist(bl)

	validator := svc.CreateTokenValidator()

	err := validator(context.Background(), "token", "user-id", "jti-1", time.Now())
	if err == nil {
		t.Fatal("expected error when blacklist check fails (fail closed)")
	}
}

// ============================================================================
// BlacklistToken / BlacklistUserTokens / IsTokenBlacklisted
// ============================================================================

func TestBlacklistToken_NoBlacklist(t *testing.T) {
	svc := newTestAuthService()

	// Should be a no-op, not an error
	err := svc.BlacklistToken(context.Background(), "any-token", "test")
	if err != nil {
		t.Fatalf("expected nil error without blacklist, got %v", err)
	}
}

func TestBlacklistUserTokens_NoBlacklist(t *testing.T) {
	svc := newTestAuthService()

	err := svc.BlacklistUserTokens(context.Background(), uuid.New(), "test")
	if err != nil {
		t.Fatalf("expected nil error without blacklist, got %v", err)
	}
}

func TestIsTokenBlacklisted_NoBlacklist(t *testing.T) {
	svc := newTestAuthService()

	blacklisted, err := svc.IsTokenBlacklisted(context.Background(), "any-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if blacklisted {
		t.Error("expected false without blacklist")
	}
}

// ============================================================================
// validatePassword / validatePasswordForUser
// ============================================================================

func TestValidatePassword_Valid(t *testing.T) {
	svc := newTestAuthService()
	err := svc.validatePassword("StrongP@ss1")
	if err != nil {
		t.Errorf("expected valid password, got error: %v", err)
	}
}

func TestValidatePassword_TooShort(t *testing.T) {
	svc := newTestAuthService()
	err := svc.validatePassword("Ab1")
	if err == nil {
		t.Fatal("expected error for short password")
	}
	if !errors.Is(err, ErrWeakPassword) {
		t.Errorf("expected ErrWeakPassword, got %v", err)
	}
}

func TestValidatePassword_MissingUppercase(t *testing.T) {
	svc := newTestAuthService()
	err := svc.validatePassword("lowercase1only")
	if err == nil {
		t.Fatal("expected error for missing uppercase")
	}
	if !errors.Is(err, ErrWeakPassword) {
		t.Errorf("expected ErrWeakPassword, got %v", err)
	}
}

func TestValidatePasswordForUser_ContainsUsername(t *testing.T) {
	svc := newTestAuthService()
	err := svc.validatePasswordForUser("Testuser1234", "testuser")
	if err == nil {
		t.Fatal("expected error when password contains username")
	}
	if !errors.Is(err, ErrWeakPassword) {
		t.Errorf("expected ErrWeakPassword, got %v", err)
	}
}

func TestValidatePasswordForUser_EmptyUsername(t *testing.T) {
	svc := newTestAuthService()
	// Empty username should not trigger the username-in-password check
	err := svc.validatePasswordForUser("StrongP@ss1", "")
	if err != nil {
		t.Errorf("expected valid password with empty username, got: %v", err)
	}
}

// ============================================================================
// Error variables
// ============================================================================

func TestErrorVariables(t *testing.T) {
	// Verify error variables are distinct and have useful messages
	errs := []struct {
		name string
		err  error
	}{
		{"ErrInvalidCredentials", ErrInvalidCredentials},
		{"ErrUserLocked", ErrUserLocked},
		{"ErrUserDisabled", ErrUserDisabled},
		{"ErrPasswordMismatch", ErrPasswordMismatch},
		{"ErrWeakPassword", ErrWeakPassword},
		{"ErrTokenRevoked", ErrTokenRevoked},
	}

	for i, e := range errs {
		if e.err == nil {
			t.Errorf("%s: expected non-nil error", e.name)
		}
		if e.err.Error() == "" {
			t.Errorf("%s: expected non-empty error message", e.name)
		}
		// Verify uniqueness
		for j := i + 1; j < len(errs); j++ {
			if errors.Is(e.err, errs[j].err) {
				t.Errorf("%s and %s should be distinct errors", e.name, errs[j].name)
			}
		}
	}
}

// ============================================================================
// RefreshInput / ChangePasswordInput struct fields
// ============================================================================

func TestRefreshInput_Fields(t *testing.T) {
	input := RefreshInput{
		RefreshToken: "refresh-token-value",
		UserAgent:    "curl/8.0",
		IPAddress:    "10.0.0.1",
	}

	if input.RefreshToken != "refresh-token-value" {
		t.Errorf("RefreshToken: expected 'refresh-token-value', got %q", input.RefreshToken)
	}
	if input.UserAgent != "curl/8.0" {
		t.Errorf("UserAgent: expected 'curl/8.0', got %q", input.UserAgent)
	}
	if input.IPAddress != "10.0.0.1" {
		t.Errorf("IPAddress: expected '10.0.0.1', got %q", input.IPAddress)
	}
}

func TestChangePasswordInput_Fields(t *testing.T) {
	uid := uuid.New()
	input := ChangePasswordInput{
		UserID:          uid,
		CurrentPassword: "old-pass",
		NewPassword:     "new-pass",
	}

	if input.UserID != uid {
		t.Error("UserID mismatch")
	}
	if input.CurrentPassword != "old-pass" {
		t.Errorf("CurrentPassword: expected 'old-pass', got %q", input.CurrentPassword)
	}
	if input.NewPassword != "new-pass" {
		t.Errorf("NewPassword: expected 'new-pass', got %q", input.NewPassword)
	}
}
