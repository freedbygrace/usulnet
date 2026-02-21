// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	authsvc "github.com/fr4nsys/usulnet/internal/services/auth"
)

type authAdapter struct {
	svc          *authsvc.Service
	sessionStore *WebSessionStore
}

// ValidateSession implements the AuthService interface required by middleware.
// It validates that the session exists AND that the user is still active.
// This ensures that admin-disabled or locked users are immediately rejected
// instead of being allowed to continue using existing sessions.
func (a *authAdapter) ValidateSession(ctx context.Context, sessionID string) (*UserContext, error) {
	// If we have a session store, we can look up the session data
	if a.sessionStore != nil && a.sessionStore.redisStore != nil {
		session, err := a.sessionStore.redisStore.Get(ctx, sessionID)
		if err != nil || session == nil {
			return nil, fmt.Errorf("session not found")
		}

		// Verify the user is still active in the database.
		// This catches admin-disabled accounts, locked users, or deleted users.
		if a.svc != nil {
			uid, parseErr := uuid.Parse(session.UserID)
			if parseErr != nil {
				return nil, fmt.Errorf("invalid user ID in session: %w", parseErr)
			}
			user, userErr := a.svc.GetUserByID(ctx, uid)
			if userErr != nil {
				return nil, fmt.Errorf("user not found: %w", userErr)
			}
			if !user.IsActive {
				return nil, fmt.Errorf("user account is disabled")
			}
			if user.IsLocked() {
				return nil, fmt.Errorf("user account is locked")
			}
			// Return fresh role from DB to pick up role changes
			return &UserContext{
				ID:       session.UserID,
				Username: session.Username,
				Role:     string(user.Role),
			}, nil
		}

		return &UserContext{
			ID:       session.UserID,
			Username: session.Username,
			Role:     session.Role,
		}, nil
	}

	// Fallback: if no session store, return error
	return nil, fmt.Errorf("session store not available")
}

// GetUserByID implements the AuthService interface required by middleware.
func (a *authAdapter) GetUserByID(ctx context.Context, userID string) (*UserContext, error) {
	if a.svc == nil {
		return nil, nil
	}

	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}

	user, err := a.svc.GetUserByID(ctx, uid)
	if err != nil {
		return nil, err
	}

	email := ""
	if user.Email != nil {
		email = *user.Email
	}

	return &UserContext{
		ID:       user.ID.String(),
		Username: user.Username,
		Email:    email,
		Role:     string(user.Role),
	}, nil
}

// Login performs user authentication.
func (a *authAdapter) Login(ctx context.Context, username, password, userAgent, ipAddress string) (*UserContext, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("auth service not available")
	}

	result, err := a.svc.Login(ctx, authsvc.LoginInput{
		Username:  username,
		Password:  password,
		UserAgent: userAgent,
		IPAddress: ipAddress,
	})
	if err != nil {
		return nil, err
	}

	email := ""
	if result.User.Email != nil {
		email = *result.User.Email
	}

	user := &UserContext{
		ID:       result.User.ID.String(),
		Username: result.User.Username,
		Email:    email,
		Role:     string(result.User.Role),
	}

	return user, nil
}

// VerifyCredentials checks username/password without creating a session (for 2FA first step).
func (a *authAdapter) VerifyCredentials(ctx context.Context, username, password, userAgent, ipAddress string) (*UserContext, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("auth service not available")
	}

	user, err := a.svc.VerifyCredentials(ctx, authsvc.LoginInput{
		Username:  username,
		Password:  password,
		UserAgent: userAgent,
		IPAddress: ipAddress,
	})
	if err != nil {
		return nil, err
	}

	email := ""
	if user.Email != nil {
		email = *user.Email
	}

	return &UserContext{
		ID:       user.ID.String(),
		Username: user.Username,
		Email:    email,
		Role:     string(user.Role),
	}, nil
}

// CreateSessionForUser creates a session for an already-authenticated user (after 2FA verification).
func (a *authAdapter) CreateSessionForUser(ctx context.Context, userID, userAgent, ipAddress string) (*UserContext, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("auth service not available")
	}

	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	user, err := a.svc.GetUserByID(ctx, uid)
	if err != nil {
		return nil, err
	}

	result, err := a.svc.CreateSessionForUser(ctx, user, authsvc.LoginInput{
		Username:  user.Username,
		UserAgent: userAgent,
		IPAddress: ipAddress,
	})
	if err != nil {
		return nil, err
	}

	email := ""
	if result.User.Email != nil {
		email = *result.User.Email
	}

	return &UserContext{
		ID:       result.User.ID.String(),
		Username: result.User.Username,
		Email:    email,
		Role:     string(result.User.Role),
	}, nil
}

// Logout ends a user session.
func (a *authAdapter) Logout(ctx context.Context, sessionID string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}

	sid, err := uuid.Parse(sessionID)
	if err != nil {
		return fmt.Errorf("parse session ID for logout: %w", err)
	}

	return a.svc.Logout(ctx, sid)
}

// OAuthGetAuthURL returns the authorization URL for an OAuth provider.
func (a *authAdapter) OAuthGetAuthURL(providerName, state string) (string, error) {
	if a.svc == nil {
		return "", fmt.Errorf("auth service not available")
	}
	return a.svc.GetOAuthAuthURL(providerName, state)
}

// OAuthCallback handles the OAuth callback by exchanging the code for user info and creating a session.
func (a *authAdapter) OAuthCallback(ctx context.Context, providerName, code, userAgent, ipAddress string) (*UserContext, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("auth service not available")
	}

	result, err := a.svc.OAuthCallback(ctx, providerName, code, authsvc.LoginInput{
		UserAgent: userAgent,
		IPAddress: ipAddress,
	})
	if err != nil {
		return nil, err
	}

	email := ""
	if result.User.Email != nil {
		email = *result.User.Email
	}

	return &UserContext{
		ID:           result.User.ID.String(),
		Username:     result.User.Username,
		Email:        email,
		Role:         string(result.User.Role),
		RequiresTOTP: result.RequiresTOTP,
	}, nil
}

// ValidateToken validates an access token.
func (a *authAdapter) ValidateToken(ctx context.Context, token string) (*UserContext, error) {
	if a.svc == nil {
		return nil, nil
	}

	claims, err := a.svc.ValidateAccessToken(token)
	if err != nil {
		return nil, err
	}

	return &UserContext{
		ID:       claims.UserID,
		Username: claims.Username,
		Email:    claims.Email,
		Role:     string(claims.Role),
	}, nil
}
