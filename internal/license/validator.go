// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package license

import (
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

//go:embed keys/public.pem
var publicKeyPEM []byte

type Claims struct {
	LicenseID string    `json:"lid"`
	EmailHash string    `json:"eml"`
	Edition   Edition   `json:"edition"`
	MaxNodes  int       `json:"nod"`
	MaxUsers  int       `json:"usr"`
	Features  []Feature `json:"features"`
	jwt.RegisteredClaims
}

type Validator struct {
	publicKey *rsa.PublicKey
}

func NewValidator() (*Validator, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("license: failed to decode embedded public key PEM")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("license: failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("license: embedded key is not RSA")
	}

	if rsaPub.N.BitLen() < 4096 {
		return nil, fmt.Errorf("license: RSA key is %d bits, minimum 4096 required", rsaPub.N.BitLen())
	}

	return &Validator{publicKey: rsaPub}, nil
}

func (v *Validator) Validate(licenseKey string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(licenseKey, &Claims{},
		func(token *jwt.Token) (interface{}, error) {
			if token.Method.Alg() != "RS512" {
				return nil, fmt.Errorf("license: unexpected signing algorithm %q, expected RS512", token.Method.Alg())
			}
			return v.publicKey, nil
		},
		jwt.WithValidMethods([]string{"RS512"}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		return nil, fmt.Errorf("license: invalid token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("license: invalid claims")
	}

	switch claims.Edition {
	case Business, Enterprise:
	default:
		return nil, fmt.Errorf("license: unknown edition %q", claims.Edition)
	}

	if len(claims.LicenseID) < 4 || claims.LicenseID[:4] != "USN-" {
		return nil, fmt.Errorf("license: invalid license ID format")
	}

	return claims, nil
}

func ClaimsToInfo(claims *Claims, instanceID string) *Info {
	info := &Info{
		Edition:    claims.Edition,
		Valid:      true,
		LicenseID:  claims.LicenseID,
		InstanceID: instanceID,
	}

	if claims.ExpiresAt != nil {
		t := claims.ExpiresAt.Time
		info.ExpiresAt = &t
		if time.Now().After(t) {
			info.Valid = false
		}
	}

	switch claims.Edition {
	case Business:
		info.Limits = BusinessDefaultLimits()
		if claims.MaxNodes > 0 {
			info.Limits.MaxNodes = claims.MaxNodes + CEBaseNodes
		}
		info.Limits.MaxUsers = claims.MaxUsers
		info.Features = resolveFeatures(claims.Features, AllBusinessFeatures())
	case Enterprise:
		info.Limits = EnterpriseLimits()
		info.Features = resolveFeatures(claims.Features, AllEnterpriseFeatures())
	}

	return info
}

type ReceiptLimits struct {
	MaxNodes                int `json:"nod"`
	MaxUsers                int `json:"usr"`
	MaxTeams                int `json:"tea"`
	MaxLDAPServers          int `json:"ldp"`
	MaxOAuthProviders       int `json:"oau"`
	MaxAPIKeys              int `json:"apk"`
	MaxGitConnections       int `json:"git"`
	MaxS3Connections        int `json:"s3c"`
	MaxBackupDestinations   int `json:"bkp"`
	MaxNotificationChannels int `json:"ntf"`
}

func (rl ReceiptLimits) ToLimits() Limits {
	return Limits{
		MaxNodes:                rl.MaxNodes,
		MaxUsers:                rl.MaxUsers,
		MaxTeams:                rl.MaxTeams,
		MaxLDAPServers:          rl.MaxLDAPServers,
		MaxOAuthProviders:       rl.MaxOAuthProviders,
		MaxAPIKeys:              rl.MaxAPIKeys,
		MaxGitConnections:       rl.MaxGitConnections,
		MaxS3Connections:        rl.MaxS3Connections,
		MaxBackupDestinations:   rl.MaxBackupDestinations,
		MaxNotificationChannels: rl.MaxNotificationChannels,
	}
}

type ReceiptClaims struct {
	LicenseID  string        `json:"lid"`
	InstanceID string        `json:"iid"`
	Edition    Edition       `json:"edt"`
	Limits     ReceiptLimits `json:"lim"`
	Features   []Feature     `json:"fts"`
	jwt.RegisteredClaims
}

func (v *Validator) ValidateReceipt(receiptJWT, expectedInstanceID string) (*ReceiptClaims, error) {
	token, err := jwt.ParseWithClaims(receiptJWT, &ReceiptClaims{},
		func(token *jwt.Token) (interface{}, error) {
			if token.Method.Alg() != "RS512" {
				return nil, fmt.Errorf("license: unexpected receipt algorithm %q, expected RS512", token.Method.Alg())
			}
			return v.publicKey, nil
		},
		jwt.WithValidMethods([]string{"RS512"}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		return nil, fmt.Errorf("license: invalid activation receipt: %w", err)
	}

	claims, ok := token.Claims.(*ReceiptClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("license: invalid activation receipt claims")
	}

	if claims.InstanceID != expectedInstanceID {
		return nil, fmt.Errorf("license: receipt instance mismatch (receipt bound to %q, this instance is %q)",
			claims.InstanceID, expectedInstanceID)
	}

	return claims, nil
}

func (v *Validator) ParseReceiptClaims(receiptJWT string) (*ReceiptClaims, error) {
	token, err := jwt.ParseWithClaims(receiptJWT, &ReceiptClaims{},
		func(token *jwt.Token) (interface{}, error) {
			if token.Method.Alg() != "RS512" {
				return nil, fmt.Errorf("license: unexpected receipt algorithm %q", token.Method.Alg())
			}
			return v.publicKey, nil
		},
		jwt.WithValidMethods([]string{"RS512"}),
	)
	if err != nil && !errors.Is(err, jwt.ErrTokenExpired) {
		return nil, fmt.Errorf("license: cannot parse receipt: %w", err)
	}

	claims, ok := token.Claims.(*ReceiptClaims)
	if !ok {
		return nil, fmt.Errorf("license: invalid receipt claims structure")
	}

	return claims, nil
}

func resolveFeatures(jwtFeatures []Feature, editionDefaults []Feature) []Feature {
	if len(jwtFeatures) == 0 {
		return editionDefaults
	}

	seen := make(map[Feature]struct{}, len(editionDefaults)+len(jwtFeatures))
	merged := make([]Feature, 0, len(editionDefaults)+len(jwtFeatures))

	for _, f := range editionDefaults {
		if _, ok := seen[f]; !ok {
			seen[f] = struct{}{}
			merged = append(merged, f)
		}
	}
	for _, f := range jwtFeatures {
		if _, ok := seen[f]; !ok {
			seen[f] = struct{}{}
			merged = append(merged, f)
		}
	}

	return merged
}
