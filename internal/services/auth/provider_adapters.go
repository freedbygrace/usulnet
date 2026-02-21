// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package auth

import (
	"context"

	ldapsvc "github.com/fr4nsys/usulnet/internal/services/auth/ldap"
	oauthsvc "github.com/fr4nsys/usulnet/internal/services/auth/oauth"
)

// LDAPClientAdapter wraps an ldap.Client to satisfy the LDAPProvider interface,
// converting between the ldap package's User type and the auth package's LDAPUser type.
type LDAPClientAdapter struct {
	client *ldapsvc.Client
}

// NewLDAPClientAdapter creates an adapter that wraps an ldap.Client.
func NewLDAPClientAdapter(client *ldapsvc.Client) *LDAPClientAdapter {
	return &LDAPClientAdapter{client: client}
}

func (a *LDAPClientAdapter) Authenticate(ctx context.Context, username, password string) (*LDAPUser, error) {
	user, err := a.client.Authenticate(ctx, username, password)
	if err != nil {
		return nil, err
	}
	return &LDAPUser{
		Username: user.Username,
		Email:    user.Email,
		DN:       user.DN,
		Groups:   user.Groups,
		Role:     user.Role,
	}, nil
}

func (a *LDAPClientAdapter) GetName() string {
	return a.client.GetName()
}

func (a *LDAPClientAdapter) IsEnabled() bool {
	return a.client.IsEnabled()
}

// OAuthProviderAdapter wraps an oauth provider (GenericProvider or OIDCProvider)
// to satisfy the OAuthProvider interface, converting between the oauth package's
// User type and the auth package's OAuthUser type.
type OAuthProviderAdapter struct {
	provider oauthProviderInternal
}

// oauthProviderInternal is the interface that both GenericProvider and OIDCProvider satisfy.
type oauthProviderInternal interface {
	GetAuthURL(state string) string
	Exchange(ctx context.Context, code string) (*oauthsvc.User, error)
	GetName() string
	IsEnabled() bool
	AutoProvisionEnabled() bool
}

// NewOAuthProviderAdapter creates an adapter that wraps an OAuth provider.
func NewOAuthProviderAdapter(provider oauthProviderInternal) *OAuthProviderAdapter {
	return &OAuthProviderAdapter{provider: provider}
}

func (a *OAuthProviderAdapter) GetAuthURL(state string) string {
	return a.provider.GetAuthURL(state)
}

func (a *OAuthProviderAdapter) Exchange(ctx context.Context, code string) (*OAuthUser, error) {
	user, err := a.provider.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	return &OAuthUser{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
		Name:     user.Name,
		Provider: user.Provider,
		Role:     user.Role,
	}, nil
}

func (a *OAuthProviderAdapter) GetName() string {
	return a.provider.GetName()
}

func (a *OAuthProviderAdapter) IsEnabled() bool {
	return a.provider.IsEnabled()
}

func (a *OAuthProviderAdapter) AutoProvisionEnabled() bool {
	return a.provider.AutoProvisionEnabled()
}
