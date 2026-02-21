// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package workers

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// WebhookDeliveryRepo defines the repository interface needed by the dispatch worker.
type WebhookDeliveryRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.OutgoingWebhook, error)
	GetDelivery(ctx context.Context, id uuid.UUID) (*models.WebhookDelivery, error)
	UpdateDelivery(ctx context.Context, d *models.WebhookDelivery) error
	CreateDelivery(ctx context.Context, d *models.WebhookDelivery) error
}

// WebhookDispatchWorker sends HTTP requests for pending webhook deliveries.
type WebhookDispatchWorker struct {
	BaseWorker
	repo   WebhookDeliveryRepo
	logger *logger.Logger
}

// NewWebhookDispatchWorker creates a new webhook dispatch worker.
func NewWebhookDispatchWorker(repo WebhookDeliveryRepo, log *logger.Logger) *WebhookDispatchWorker {
	if log == nil {
		log = logger.Nop()
	}
	return &WebhookDispatchWorker{
		BaseWorker: NewBaseWorker(models.JobTypeWebhookDispatch),
		repo:       repo,
		logger:     log.Named("webhook-dispatch"),
	}
}

// WebhookDispatchResult holds the result of a webhook dispatch.
type WebhookDispatchResult struct {
	DeliveryID   uuid.UUID     `json:"delivery_id"`
	WebhookID    uuid.UUID     `json:"webhook_id"`
	Success      bool          `json:"success"`
	ResponseCode int           `json:"response_code,omitempty"`
	Duration     time.Duration `json:"duration"`
	Attempt      int           `json:"attempt"`
	Error        string        `json:"error,omitempty"`
}

// Execute sends the HTTP request for a webhook delivery.
func (w *WebhookDispatchWorker) Execute(ctx context.Context, job *models.Job) (interface{}, error) {
	log := w.logger.With("job_id", job.ID)

	var payload models.WebhookDispatchPayload
	if err := job.GetPayload(&payload); err != nil {
		return nil, errors.Wrap(err, errors.CodeValidation, "failed to parse payload")
	}

	if payload.DeliveryID == uuid.Nil || payload.WebhookID == uuid.Nil {
		return nil, errors.New(errors.CodeValidation, "delivery_id and webhook_id are required")
	}

	// Get delivery record
	delivery, err := w.repo.GetDelivery(ctx, payload.DeliveryID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "delivery not found")
	}

	// Get webhook config
	webhook, err := w.repo.GetByID(ctx, payload.WebhookID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "webhook not found")
	}

	if !webhook.IsEnabled {
		delivery.Status = "skipped"
		now := time.Now()
		delivery.DeliveredAt = &now
		w.repo.UpdateDelivery(ctx, delivery)
		return &WebhookDispatchResult{
			DeliveryID: delivery.ID,
			WebhookID:  webhook.ID,
			Success:    false,
			Error:      "webhook is disabled",
		}, nil
	}

	log.Info("dispatching webhook",
		"webhook_id", webhook.ID,
		"webhook_name", webhook.Name,
		"url", webhook.URL,
		"event", delivery.Event,
		"attempt", delivery.Attempt,
	)

	// Perform HTTP request with retries
	maxAttempts := webhook.RetryCount + 1
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	var lastResult *WebhookDispatchResult

	for attempt := delivery.Attempt; attempt <= maxAttempts; attempt++ {
		delivery.Attempt = attempt
		result := w.sendHTTP(ctx, webhook, delivery)
		lastResult = result

		if result.Success {
			delivery.Status = "success"
			delivery.ResponseCode = &result.ResponseCode
			delivery.Duration = int(result.Duration.Milliseconds())
			now := time.Now()
			delivery.DeliveredAt = &now

			w.repo.UpdateDelivery(ctx, delivery)

			log.Info("webhook delivered",
				"webhook_name", webhook.Name,
				"response_code", result.ResponseCode,
				"duration_ms", delivery.Duration,
				"attempt", attempt,
			)
			return result, nil
		}

		// Failed - update delivery with error
		errStr := result.Error
		delivery.Error = &errStr
		if result.ResponseCode > 0 {
			delivery.ResponseCode = &result.ResponseCode
		}
		delivery.Duration = int(result.Duration.Milliseconds())

		// If not last attempt, wait before retrying
		if attempt < maxAttempts {
			log.Warn("webhook delivery failed, retrying",
				"webhook_name", webhook.Name,
				"attempt", attempt,
				"max_attempts", maxAttempts,
				"error", result.Error,
			)

			// Exponential backoff: 2s, 4s, 8s, 16s
			backoff := time.Duration(1<<uint(attempt)) * time.Second
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}

			select {
			case <-ctx.Done():
				delivery.Status = "failed"
				w.repo.UpdateDelivery(ctx, delivery)
				return lastResult, ctx.Err()
			case <-time.After(backoff):
			}
		}
	}

	// All retries exhausted
	delivery.Status = "failed"
	now := time.Now()
	delivery.DeliveredAt = &now
	w.repo.UpdateDelivery(ctx, delivery)

	log.Error("webhook delivery failed after all retries",
		"webhook_name", webhook.Name,
		"attempts", maxAttempts,
		"error", lastResult.Error,
	)

	return lastResult, nil
}

// sendHTTP performs a single HTTP POST to the webhook URL.
func (w *WebhookDispatchWorker) sendHTTP(ctx context.Context, webhook *models.OutgoingWebhook, delivery *models.WebhookDelivery) *WebhookDispatchResult {
	result := &WebhookDispatchResult{
		DeliveryID: delivery.ID,
		WebhookID:  webhook.ID,
		Attempt:    delivery.Attempt,
	}

	startTime := time.Now()

	// Build request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook.URL, bytes.NewReader(delivery.Payload))
	if err != nil {
		result.Duration = time.Since(startTime)
		result.Error = fmt.Sprintf("failed to create request: %s", err)
		return result
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "usulnet-webhook/1.0")
	req.Header.Set("X-Webhook-Event", delivery.Event)
	req.Header.Set("X-Webhook-Delivery", delivery.ID.String())

	// Apply HMAC signature if secret is set
	if webhook.Secret != nil && *webhook.Secret != "" {
		mac := hmac.New(sha256.New, []byte(*webhook.Secret))
		mac.Write(delivery.Payload)
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Webhook-Signature-256", "sha256="+sig)
	}

	// Apply custom headers
	if len(webhook.Headers) > 0 {
		var headers map[string]string
		if json.Unmarshal(webhook.Headers, &headers) == nil {
			for k, v := range headers {
				req.Header.Set(k, v)
			}
		}
	}

	// Execute request
	timeout := time.Duration(webhook.TimeoutSecs) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	client := &http.Client{Timeout: timeout}

	resp, err := client.Do(req)
	result.Duration = time.Since(startTime)

	if err != nil {
		result.Error = fmt.Sprintf("request failed: %s", err)
		return result
	}
	defer resp.Body.Close()

	result.ResponseCode = resp.StatusCode

	// Read response body (limit to 8KB)
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))

	// Consider 2xx as success
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		result.Success = true
	} else {
		result.Error = fmt.Sprintf("non-2xx response: %d %s", resp.StatusCode, string(respBody))
	}

	// Store truncated response body in delivery
	body := string(respBody)
	delivery.ResponseBody = &body

	return result
}
