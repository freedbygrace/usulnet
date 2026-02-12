// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package imagesign

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ---------------------------------------------------------------------------
// Mock repository
// ---------------------------------------------------------------------------

type mockRepo struct {
	signatures    []*models.ImageSignature
	attestations  []*models.ImageAttestation
	trustPolicies []*models.ImageTrustPolicy
}

func newMockRepo() *mockRepo {
	return &mockRepo{}
}

func (m *mockRepo) CreateSignature(_ context.Context, sig *models.ImageSignature) error {
	m.signatures = append(m.signatures, sig)
	return nil
}

func (m *mockRepo) GetSignaturesByDigest(_ context.Context, digest string) ([]*models.ImageSignature, error) {
	var result []*models.ImageSignature
	for _, s := range m.signatures {
		if s.ImageDigest == digest {
			result = append(result, s)
		}
	}
	return result, nil
}

func (m *mockRepo) GetSignaturesByRef(_ context.Context, imageRef string) ([]*models.ImageSignature, error) {
	var result []*models.ImageSignature
	for _, s := range m.signatures {
		if s.ImageRef == imageRef {
			result = append(result, s)
		}
	}
	return result, nil
}

func (m *mockRepo) UpdateVerification(_ context.Context, _ uuid.UUID, _ bool, _ *time.Time, _ string) error {
	return nil
}

func (m *mockRepo) CreateAttestation(_ context.Context, att *models.ImageAttestation) error {
	m.attestations = append(m.attestations, att)
	return nil
}

func (m *mockRepo) GetAttestationsByDigest(_ context.Context, digest string) ([]*models.ImageAttestation, error) {
	var result []*models.ImageAttestation
	for _, a := range m.attestations {
		if a.ImageDigest == digest {
			result = append(result, a)
		}
	}
	return result, nil
}

func (m *mockRepo) CreateTrustPolicy(_ context.Context, p *models.ImageTrustPolicy) error {
	m.trustPolicies = append(m.trustPolicies, p)
	return nil
}

func (m *mockRepo) GetTrustPolicy(_ context.Context, id uuid.UUID) (*models.ImageTrustPolicy, error) {
	for _, p := range m.trustPolicies {
		if p.ID == id {
			return p, nil
		}
	}
	return nil, fmt.Errorf("trust policy %s not found", id)
}

func (m *mockRepo) ListTrustPolicies(_ context.Context) ([]*models.ImageTrustPolicy, error) {
	return m.trustPolicies, nil
}

func (m *mockRepo) UpdateTrustPolicy(_ context.Context, _ *models.ImageTrustPolicy) error {
	return nil
}

func (m *mockRepo) DeleteTrustPolicy(_ context.Context, _ uuid.UUID) error {
	return nil
}

func (m *mockRepo) GetMatchingPolicies(_ context.Context, _ string) ([]*models.ImageTrustPolicy, error) {
	// Return all enabled policies as a simplification for tests.
	var matched []*models.ImageTrustPolicy
	for _, p := range m.trustPolicies {
		if p.IsEnabled {
			matched = append(matched, p)
		}
	}
	return matched, nil
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestNewService(t *testing.T) {
	repo := newMockRepo()
	cfg := DefaultConfig()
	log := logger.Nop()

	svc := NewService(repo, cfg, log)
	if svc == nil {
		t.Fatal("NewService returned nil")
	}
	if svc.repo != repo {
		t.Fatal("expected repo to be set")
	}
	if svc.config.CosignBinaryPath != "cosign" {
		t.Fatalf("expected default CosignBinaryPath to be 'cosign', got %q", svc.config.CosignBinaryPath)
	}
}

func TestGetImageSignatures_EmptyRef(t *testing.T) {
	repo := newMockRepo()
	svc := NewService(repo, DefaultConfig(), logger.Nop())

	_, err := svc.GetImageSignatures(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty image reference, got nil")
	}
}

func TestListTrustPolicies_Empty(t *testing.T) {
	repo := newMockRepo()
	svc := NewService(repo, DefaultConfig(), logger.Nop())

	policies, err := svc.ListTrustPolicies(context.Background())
	if err != nil {
		t.Fatalf("ListTrustPolicies returned unexpected error: %v", err)
	}
	if len(policies) != 0 {
		t.Fatalf("expected 0 trust policies, got %d", len(policies))
	}
}

func TestSeedDefaultPolicies(t *testing.T) {
	repo := newMockRepo()
	svc := NewService(repo, DefaultConfig(), logger.Nop())

	if err := svc.SeedDefaultPolicies(context.Background()); err != nil {
		t.Fatalf("SeedDefaultPolicies returned unexpected error: %v", err)
	}

	// The service seeds 3 default trust policies.
	if len(repo.trustPolicies) != 3 {
		t.Fatalf("expected 3 default trust policies, got %d", len(repo.trustPolicies))
	}

	expectedNames := map[string]bool{
		"internal-registry": false,
		"public-critical":   false,
		"default-warn":      false,
	}
	for _, p := range repo.trustPolicies {
		if _, ok := expectedNames[p.Name]; !ok {
			t.Errorf("unexpected trust policy name: %s", p.Name)
		}
		expectedNames[p.Name] = true
	}
	for name, found := range expectedNames {
		if !found {
			t.Errorf("trust policy %q was not created", name)
		}
	}

	// Calling seed again should not create duplicates.
	if err := svc.SeedDefaultPolicies(context.Background()); err != nil {
		t.Fatalf("second SeedDefaultPolicies returned unexpected error: %v", err)
	}
	if len(repo.trustPolicies) != 3 {
		t.Fatalf("expected 3 trust policies after second seed (no duplicates), got %d",
			len(repo.trustPolicies))
	}
}
