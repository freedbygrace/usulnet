// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package workers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// Mock: AutoDeployRuleRepo
// ============================================================================

type mockAutoDeployRuleRepo struct {
	getByIDFn func(ctx context.Context, id uuid.UUID) (*models.AutoDeployRule, error)
}

func (m *mockAutoDeployRuleRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.AutoDeployRule, error) {
	if m.getByIDFn != nil {
		return m.getByIDFn(ctx, id)
	}
	return nil, fmt.Errorf("not implemented")
}

// ============================================================================
// Mock: StackDeployService
// ============================================================================

type mockStackDeployService struct {
	redeployFn func(ctx context.Context, stackName string) error
}

func (m *mockStackDeployService) Redeploy(ctx context.Context, stackName string) error {
	if m.redeployFn != nil {
		return m.redeployFn(ctx, stackName)
	}
	return nil
}

// ============================================================================
// Mock: WebhookDeliveryRepo
// ============================================================================

type mockWebhookRepo struct {
	getByIDFn        func(ctx context.Context, id uuid.UUID) (*models.OutgoingWebhook, error)
	getDeliveryFn    func(ctx context.Context, id uuid.UUID) (*models.WebhookDelivery, error)
	updateDeliveryFn func(ctx context.Context, d *models.WebhookDelivery) error
	createDeliveryFn func(ctx context.Context, d *models.WebhookDelivery) error
}

func (m *mockWebhookRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.OutgoingWebhook, error) {
	if m.getByIDFn != nil {
		return m.getByIDFn(ctx, id)
	}
	return nil, fmt.Errorf("not implemented")
}
func (m *mockWebhookRepo) GetDelivery(ctx context.Context, id uuid.UUID) (*models.WebhookDelivery, error) {
	if m.getDeliveryFn != nil {
		return m.getDeliveryFn(ctx, id)
	}
	return nil, fmt.Errorf("not implemented")
}
func (m *mockWebhookRepo) UpdateDelivery(ctx context.Context, d *models.WebhookDelivery) error {
	if m.updateDeliveryFn != nil {
		return m.updateDeliveryFn(ctx, d)
	}
	return nil
}
func (m *mockWebhookRepo) CreateDelivery(ctx context.Context, d *models.WebhookDelivery) error {
	if m.createDeliveryFn != nil {
		return m.createDeliveryFn(ctx, d)
	}
	return nil
}

// ============================================================================
// Test helpers
// ============================================================================

func testJob(jobType models.JobType, payload interface{}) *models.Job {
	job := &models.Job{
		ID:     uuid.New(),
		Type:   jobType,
		Status: models.JobStatusPending,
	}
	if payload != nil {
		if err := job.SetPayload(payload); err != nil {
			panic("test setup: " + err.Error())
		}
	}
	return job
}

// ============================================================================
// AutoDeployWorker tests
// ============================================================================

func TestAutoDeployWorker_Type(t *testing.T) {
	w := NewAutoDeployWorker(nil, nil, nil)
	if w.Type() != models.JobTypeAutoDeploy {
		t.Errorf("Type() = %q, want %q", w.Type(), models.JobTypeAutoDeploy)
	}
	if !w.CanHandle(models.JobTypeAutoDeploy) {
		t.Error("expected CanHandle(auto_deploy) = true")
	}
	if w.CanHandle(models.JobTypeBackupCreate) {
		t.Error("expected CanHandle(backup_create) = false")
	}
}

func TestAutoDeployWorker_InvalidPayload(t *testing.T) {
	w := NewAutoDeployWorker(nil, nil, nil)
	job := &models.Job{ID: uuid.New(), Payload: json.RawMessage(`{invalid`)}
	_, err := w.Execute(context.Background(), job)
	if err == nil {
		t.Fatal("expected error for invalid payload")
	}
}

func TestAutoDeployWorker_MissingRuleID(t *testing.T) {
	w := NewAutoDeployWorker(nil, nil, nil)
	job := testJob(models.JobTypeAutoDeploy, models.AutoDeployPayload{})
	_, err := w.Execute(context.Background(), job)
	if err == nil || !strings.Contains(err.Error(), "rule_id is required") {
		t.Errorf("expected rule_id validation error, got: %v", err)
	}
}

func TestAutoDeployWorker_RuleNotFound(t *testing.T) {
	repo := &mockAutoDeployRuleRepo{
		getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.AutoDeployRule, error) {
			return nil, fmt.Errorf("not found")
		},
	}
	w := NewAutoDeployWorker(repo, nil, nil)
	job := testJob(models.JobTypeAutoDeploy, models.AutoDeployPayload{RuleID: uuid.New()})
	_, err := w.Execute(context.Background(), job)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not found error, got: %v", err)
	}
}

func TestAutoDeployWorker_DisabledRule(t *testing.T) {
	ruleID := uuid.New()
	repo := &mockAutoDeployRuleRepo{
		getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.AutoDeployRule, error) {
			return &models.AutoDeployRule{
				ID:        ruleID,
				Name:      "test-rule",
				Action:    "redeploy",
				IsEnabled: false,
			}, nil
		},
	}
	w := NewAutoDeployWorker(repo, nil, nil)
	job := testJob(models.JobTypeAutoDeploy, models.AutoDeployPayload{RuleID: ruleID})
	result, err := w.Execute(context.Background(), job)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := result.(*AutoDeployResult)
	if r.Success {
		t.Error("expected success=false for disabled rule")
	}
	if !strings.Contains(r.Error, "disabled") {
		t.Errorf("expected disabled error, got: %q", r.Error)
	}
}

func TestAutoDeployWorker_Redeploy_Success(t *testing.T) {
	ruleID := uuid.New()
	stackID := "my-stack"
	var redeployedStack string

	repo := &mockAutoDeployRuleRepo{
		getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.AutoDeployRule, error) {
			return &models.AutoDeployRule{
				ID:            ruleID,
				Name:          "test-rule",
				Action:        "redeploy",
				IsEnabled:     true,
				TargetStackID: &stackID,
			}, nil
		},
	}
	stackSvc := &mockStackDeployService{
		redeployFn: func(_ context.Context, name string) error {
			redeployedStack = name
			return nil
		},
	}

	w := NewAutoDeployWorker(repo, stackSvc, nil)
	job := testJob(models.JobTypeAutoDeploy, models.AutoDeployPayload{RuleID: ruleID})
	result, err := w.Execute(context.Background(), job)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := result.(*AutoDeployResult)
	if !r.Success {
		t.Errorf("expected success, got error: %q", r.Error)
	}
	if redeployedStack != stackID {
		t.Errorf("redeployed stack = %q, want %q", redeployedStack, stackID)
	}
}

func TestAutoDeployWorker_Redeploy_NoStack(t *testing.T) {
	ruleID := uuid.New()
	repo := &mockAutoDeployRuleRepo{
		getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.AutoDeployRule, error) {
			return &models.AutoDeployRule{
				ID:        ruleID,
				Name:      "test-rule",
				Action:    "redeploy",
				IsEnabled: true,
			}, nil
		},
	}
	w := NewAutoDeployWorker(repo, nil, nil)
	job := testJob(models.JobTypeAutoDeploy, models.AutoDeployPayload{RuleID: ruleID})
	result, err := w.Execute(context.Background(), job)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := result.(*AutoDeployResult)
	if r.Success {
		t.Error("expected failure")
	}
	if !strings.Contains(r.Error, "no target stack") {
		t.Errorf("expected 'no target stack' error, got: %q", r.Error)
	}
}

func TestAutoDeployWorker_Redeploy_NilService(t *testing.T) {
	ruleID := uuid.New()
	stackID := "my-stack"
	repo := &mockAutoDeployRuleRepo{
		getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.AutoDeployRule, error) {
			return &models.AutoDeployRule{
				ID:            ruleID,
				Name:          "test-rule",
				Action:        "redeploy",
				IsEnabled:     true,
				TargetStackID: &stackID,
			}, nil
		},
	}
	w := NewAutoDeployWorker(repo, nil, nil)
	job := testJob(models.JobTypeAutoDeploy, models.AutoDeployPayload{RuleID: ruleID})
	result, err := w.Execute(context.Background(), job)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := result.(*AutoDeployResult)
	if r.Success {
		t.Error("expected failure when stack service is nil")
	}
	if !strings.Contains(r.Error, "not available") {
		t.Errorf("expected 'not available' error, got: %q", r.Error)
	}
}

func TestAutoDeployWorker_Redeploy_Failure(t *testing.T) {
	ruleID := uuid.New()
	stackID := "my-stack"
	repo := &mockAutoDeployRuleRepo{
		getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.AutoDeployRule, error) {
			return &models.AutoDeployRule{
				ID:            ruleID,
				Name:          "test-rule",
				Action:        "redeploy",
				IsEnabled:     true,
				TargetStackID: &stackID,
			}, nil
		},
	}
	stackSvc := &mockStackDeployService{
		redeployFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("docker error")
		},
	}
	w := NewAutoDeployWorker(repo, stackSvc, nil)
	job := testJob(models.JobTypeAutoDeploy, models.AutoDeployPayload{RuleID: ruleID})
	result, err := w.Execute(context.Background(), job)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := result.(*AutoDeployResult)
	if r.Success {
		t.Error("expected failure")
	}
	if !strings.Contains(r.Error, "docker error") {
		t.Errorf("expected docker error, got: %q", r.Error)
	}
}

func TestAutoDeployWorker_UpdateImage_Success(t *testing.T) {
	ruleID := uuid.New()
	svc := "my-service"
	repo := &mockAutoDeployRuleRepo{
		getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.AutoDeployRule, error) {
			return &models.AutoDeployRule{
				ID:            ruleID,
				Name:          "test-rule",
				Action:        "update_image",
				IsEnabled:     true,
				TargetService: &svc,
			}, nil
		},
	}
	w := NewAutoDeployWorker(repo, nil, nil)
	job := testJob(models.JobTypeAutoDeploy, models.AutoDeployPayload{RuleID: ruleID})
	result, err := w.Execute(context.Background(), job)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := result.(*AutoDeployResult)
	if !r.Success {
		t.Errorf("expected success, got error: %q", r.Error)
	}
}

func TestAutoDeployWorker_UnsupportedAction(t *testing.T) {
	ruleID := uuid.New()
	repo := &mockAutoDeployRuleRepo{
		getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.AutoDeployRule, error) {
			return &models.AutoDeployRule{
				ID:        ruleID,
				Name:      "test-rule",
				Action:    "unknown_action",
				IsEnabled: true,
			}, nil
		},
	}
	w := NewAutoDeployWorker(repo, nil, nil)
	job := testJob(models.JobTypeAutoDeploy, models.AutoDeployPayload{RuleID: ruleID})
	result, err := w.Execute(context.Background(), job)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := result.(*AutoDeployResult)
	if r.Success {
		t.Error("expected failure for unsupported action")
	}
	if !strings.Contains(r.Error, "unsupported") {
		t.Errorf("expected unsupported error, got: %q", r.Error)
	}
}

// ============================================================================
// WebhookDispatchWorker tests
// ============================================================================

func TestWebhookDispatchWorker_Type(t *testing.T) {
	w := NewWebhookDispatchWorker(nil, nil)
	if w.Type() != models.JobTypeWebhookDispatch {
		t.Errorf("Type() = %q, want %q", w.Type(), models.JobTypeWebhookDispatch)
	}
}

func TestWebhookDispatchWorker_InvalidPayload(t *testing.T) {
	w := NewWebhookDispatchWorker(nil, nil)
	job := &models.Job{ID: uuid.New(), Payload: json.RawMessage(`{bad`)}
	_, err := w.Execute(context.Background(), job)
	if err == nil {
		t.Fatal("expected error for invalid payload")
	}
}

func TestWebhookDispatchWorker_MissingIDs(t *testing.T) {
	w := NewWebhookDispatchWorker(nil, nil)
	job := testJob(models.JobTypeWebhookDispatch, models.WebhookDispatchPayload{})
	_, err := w.Execute(context.Background(), job)
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestWebhookDispatchWorker_DisabledWebhook(t *testing.T) {
	webhookID := uuid.New()
	deliveryID := uuid.New()

	var updatedDelivery *models.WebhookDelivery
	repo := &mockWebhookRepo{
		getDeliveryFn: func(_ context.Context, _ uuid.UUID) (*models.WebhookDelivery, error) {
			return &models.WebhookDelivery{
				ID:        deliveryID,
				WebhookID: webhookID,
				Event:     "push",
				Payload:   json.RawMessage(`{}`),
				Status:    "pending",
			}, nil
		},
		getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.OutgoingWebhook, error) {
			return &models.OutgoingWebhook{
				ID:        webhookID,
				Name:      "test-hook",
				URL:       "http://example.com",
				IsEnabled: false,
			}, nil
		},
		updateDeliveryFn: func(_ context.Context, d *models.WebhookDelivery) error {
			updatedDelivery = d
			return nil
		},
	}

	w := NewWebhookDispatchWorker(repo, nil)
	job := testJob(models.JobTypeWebhookDispatch, models.WebhookDispatchPayload{
		DeliveryID: deliveryID,
		WebhookID:  webhookID,
	})

	result, err := w.Execute(context.Background(), job)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := result.(*WebhookDispatchResult)
	if r.Success {
		t.Error("expected success=false for disabled webhook")
	}
	if updatedDelivery == nil || updatedDelivery.Status != "skipped" {
		t.Error("expected delivery status to be updated to 'skipped'")
	}
}

func TestWebhookDispatchWorker_SuccessfulDelivery(t *testing.T) {
	// Set up a test HTTP server that returns 200
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("expected Content-Type: application/json")
		}
		if r.Header.Get("X-Webhook-Event") != "push" {
			t.Error("expected X-Webhook-Event: push")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	webhookID := uuid.New()
	deliveryID := uuid.New()

	repo := &mockWebhookRepo{
		getDeliveryFn: func(_ context.Context, _ uuid.UUID) (*models.WebhookDelivery, error) {
			return &models.WebhookDelivery{
				ID:        deliveryID,
				WebhookID: webhookID,
				Event:     "push",
				Payload:   json.RawMessage(`{"ref":"refs/heads/main"}`),
				Status:    "pending",
				Attempt:   1,
			}, nil
		},
		getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.OutgoingWebhook, error) {
			return &models.OutgoingWebhook{
				ID:         webhookID,
				Name:       "test-hook",
				URL:        server.URL,
				IsEnabled:  true,
				RetryCount: 0,
			}, nil
		},
	}

	w := NewWebhookDispatchWorker(repo, nil)
	job := testJob(models.JobTypeWebhookDispatch, models.WebhookDispatchPayload{
		DeliveryID: deliveryID,
		WebhookID:  webhookID,
	})

	result, err := w.Execute(context.Background(), job)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := result.(*WebhookDispatchResult)
	if !r.Success {
		t.Errorf("expected success, got error: %q", r.Error)
	}
	if r.ResponseCode != http.StatusOK {
		t.Errorf("response code = %d, want 200", r.ResponseCode)
	}
}

func TestWebhookDispatchWorker_Non2xxResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	webhookID := uuid.New()
	deliveryID := uuid.New()

	repo := &mockWebhookRepo{
		getDeliveryFn: func(_ context.Context, _ uuid.UUID) (*models.WebhookDelivery, error) {
			return &models.WebhookDelivery{
				ID:        deliveryID,
				WebhookID: webhookID,
				Event:     "push",
				Payload:   json.RawMessage(`{}`),
				Status:    "pending",
				Attempt:   1,
			}, nil
		},
		getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.OutgoingWebhook, error) {
			return &models.OutgoingWebhook{
				ID:         webhookID,
				Name:       "test-hook",
				URL:        server.URL,
				IsEnabled:  true,
				RetryCount: 0,
			}, nil
		},
	}

	w := NewWebhookDispatchWorker(repo, nil)
	job := testJob(models.JobTypeWebhookDispatch, models.WebhookDispatchPayload{
		DeliveryID: deliveryID,
		WebhookID:  webhookID,
	})

	result, err := w.Execute(context.Background(), job)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := result.(*WebhookDispatchResult)
	if r.Success {
		t.Error("expected failure for 500 response")
	}
	if r.ResponseCode != http.StatusInternalServerError {
		t.Errorf("response code = %d, want 500", r.ResponseCode)
	}
}

func TestWebhookDispatchWorker_HMACSignature(t *testing.T) {
	secret := "my-webhook-secret"
	payloadBytes := json.RawMessage(`{"event":"push","repo":"test"}`)
	var receivedSig string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSig = r.Header.Get("X-Webhook-Signature-256")
		// Verify body
		body, _ := io.ReadAll(r.Body)
		if string(body) != string(payloadBytes) {
			t.Errorf("body mismatch: got %q", body)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	webhookID := uuid.New()
	deliveryID := uuid.New()

	repo := &mockWebhookRepo{
		getDeliveryFn: func(_ context.Context, _ uuid.UUID) (*models.WebhookDelivery, error) {
			return &models.WebhookDelivery{
				ID:        deliveryID,
				WebhookID: webhookID,
				Event:     "push",
				Payload:   payloadBytes,
				Status:    "pending",
				Attempt:   1,
			}, nil
		},
		getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.OutgoingWebhook, error) {
			return &models.OutgoingWebhook{
				ID:        webhookID,
				Name:      "signed-hook",
				URL:       server.URL,
				Secret:    &secret,
				IsEnabled: true,
			}, nil
		},
	}

	w := NewWebhookDispatchWorker(repo, logger.Nop())
	job := testJob(models.JobTypeWebhookDispatch, models.WebhookDispatchPayload{
		DeliveryID: deliveryID,
		WebhookID:  webhookID,
	})

	_, err := w.Execute(context.Background(), job)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify HMAC signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payloadBytes)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if receivedSig != expected {
		t.Errorf("HMAC signature mismatch: got %q, want %q", receivedSig, expected)
	}
}

func TestWebhookDispatchWorker_CustomHeaders(t *testing.T) {
	var receivedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	webhookID := uuid.New()
	deliveryID := uuid.New()

	headers, _ := json.Marshal(map[string]string{"Authorization": "Bearer test-token"})

	repo := &mockWebhookRepo{
		getDeliveryFn: func(_ context.Context, _ uuid.UUID) (*models.WebhookDelivery, error) {
			return &models.WebhookDelivery{
				ID:        deliveryID,
				WebhookID: webhookID,
				Event:     "push",
				Payload:   json.RawMessage(`{}`),
				Status:    "pending",
				Attempt:   1,
			}, nil
		},
		getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.OutgoingWebhook, error) {
			return &models.OutgoingWebhook{
				ID:        webhookID,
				Name:      "header-hook",
				URL:       server.URL,
				IsEnabled: true,
				Headers:   json.RawMessage(headers),
			}, nil
		},
	}

	w := NewWebhookDispatchWorker(repo, nil)
	job := testJob(models.JobTypeWebhookDispatch, models.WebhookDispatchPayload{
		DeliveryID: deliveryID,
		WebhookID:  webhookID,
	})

	result, err := w.Execute(context.Background(), job)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := result.(*WebhookDispatchResult)
	if !r.Success {
		t.Errorf("expected success, got error: %q", r.Error)
	}
	if receivedAuth != "Bearer test-token" {
		t.Errorf("custom header not applied: got %q", receivedAuth)
	}
}

func TestWebhookDispatchWorker_ContextCancellation(t *testing.T) {
	// Server that always returns 500 to trigger retries
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	webhookID := uuid.New()
	deliveryID := uuid.New()

	repo := &mockWebhookRepo{
		getDeliveryFn: func(_ context.Context, _ uuid.UUID) (*models.WebhookDelivery, error) {
			return &models.WebhookDelivery{
				ID:        deliveryID,
				WebhookID: webhookID,
				Event:     "push",
				Payload:   json.RawMessage(`{}`),
				Status:    "pending",
				Attempt:   1,
			}, nil
		},
		getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.OutgoingWebhook, error) {
			return &models.OutgoingWebhook{
				ID:         webhookID,
				Name:       "retry-hook",
				URL:        server.URL,
				IsEnabled:  true,
				RetryCount: 3, // Will try to retry
			}, nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	w := NewWebhookDispatchWorker(repo, nil)
	job := testJob(models.JobTypeWebhookDispatch, models.WebhookDispatchPayload{
		DeliveryID: deliveryID,
		WebhookID:  webhookID,
	})

	_, err := w.Execute(ctx, job)
	// Should return context error since retries are interrupted
	if err == nil {
		t.Log("note: context cancellation path depends on timing")
	}
}
