// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/runbooks"
)

// RunbooksTempl renders the runbooks management page.
func (h *Handler) RunbooksTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Runbooks", "runbooks")
	tab := r.URL.Query().Get("tab")
	if tab == "" {
		tab = "runbooks"
	}

	var rbItems []runbooks.RunbookItem
	var execItems []runbooks.ExecutionItem

	if h.runbookRepo != nil {
		rbs, _, err := h.runbookRepo.List(r.Context(), models.RunbookListOptions{Limit: 100})
		if err != nil {
			slog.Error("Failed to list runbooks", "error", err)
		} else {
			// Build runbook name lookup for execution display
			rbNameMap := make(map[string]string) // runbook ID → name
			for _, rb := range rbs {
				rbNameMap[rb.ID.String()] = rb.Name

				var steps []models.RunbookStep
				if rb.Steps != nil {
					if err := json.Unmarshal(rb.Steps, &steps); err != nil {
						slog.Warn("Failed to parse runbook steps", "runbook", rb.Name, "error", err)
					}
				}

				rbItems = append(rbItems, runbooks.RunbookItem{
					ID:          rb.ID.String(),
					Name:        rb.Name,
					Description: rb.Description,
					Category:    rb.Category,
					StepCount:   len(steps),
					IsEnabled:   rb.IsEnabled,
					Version:     rb.Version,
					CreatedAt:   rb.CreatedAt.Format("2006-01-02 15:04"),
					UpdatedAt:   rb.UpdatedAt.Format("2006-01-02 15:04"),
				})
			}

			// Populate execution history
			if execs, execErr := h.runbookRepo.ListRecentExecutions(r.Context(), 50); execErr == nil {
				for _, e := range execs {
					item := runbooks.ExecutionItem{
						ID:        e.ID.String(),
						Status:    e.Status,
						Trigger:   e.Trigger,
						StartedAt: e.StartedAt.Format("2006-01-02 15:04:05"),
					}
					if name, ok := rbNameMap[e.RunbookID.String()]; ok {
						item.RunbookName = name
					} else {
						item.RunbookName = e.RunbookID.String()[:8]
					}
					if e.FinishedAt != nil {
						item.FinishedAt = e.FinishedAt.Format("2006-01-02 15:04:05")
						duration := e.FinishedAt.Sub(e.StartedAt)
						if duration < time.Second {
							item.Duration = fmt.Sprintf("%dms", duration.Milliseconds())
						} else {
							item.Duration = fmt.Sprintf("%.1fs", duration.Seconds())
						}
					}
					execItems = append(execItems, item)
				}
			} else {
				slog.Error("Failed to list executions", "error", execErr)
			}
		}
	}

	data := runbooks.RunbooksData{
		PageData:   pageData,
		Runbooks:   rbItems,
		Executions: execItems,
		Tab:        tab,
	}
	h.renderTempl(w, r, runbooks.List(data))
}

// RunbookCreate handles creation of a new runbook.
func (h *Handler) RunbookCreate(w http.ResponseWriter, r *http.Request) {
	if h.runbookRepo == nil {
		h.setFlash(w, r, "error", "Runbook service not configured")
		h.redirect(w, r, "/runbooks")
		return
	}

	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		h.redirect(w, r, "/runbooks")
		return
	}

	name := r.FormValue("name")
	if name == "" {
		h.setFlash(w, r, "error", "Runbook name is required")
		h.redirect(w, r, "/runbooks")
		return
	}

	stepsJSON := r.FormValue("steps")
	if stepsJSON == "" {
		stepsJSON = "[]"
	}

	rb := &models.Runbook{
		Name:        name,
		Description: r.FormValue("description"),
		Category:    r.FormValue("category"),
		Steps:       json.RawMessage(stepsJSON),
		IsEnabled:   r.FormValue("is_enabled") == "on",
		Version:     1,
	}

	if user := GetUserFromContext(r.Context()); user != nil {
		if uid, err := uuid.Parse(user.ID); err == nil {
			rb.CreatedBy = &uid
		}
	}

	if err := h.runbookRepo.Create(r.Context(), rb); err != nil {
		slog.Error("Failed to create runbook", "name", rb.Name, "error", err)
		h.setFlash(w, r, "error", "Failed to create runbook: "+err.Error())
		h.redirect(w, r, "/runbooks")
		return
	}

	h.setFlash(w, r, "success", "Runbook created successfully")
	h.redirect(w, r, "/runbooks")
}

// RunbookDelete handles deletion of a runbook.
func (h *Handler) RunbookDelete(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/runbooks")
		return
	}

	if h.runbookRepo != nil {
		if err := h.runbookRepo.Delete(r.Context(), id); err != nil {
			slog.Error("Failed to delete runbook", "id", id, "error", err)
			h.setFlash(w, r, "error", "Failed to delete runbook: "+err.Error())
			h.redirect(w, r, "/runbooks")
			return
		}
	}

	h.setFlash(w, r, "success", "Runbook deleted")
	h.redirect(w, r, "/runbooks")
}

// RunbookExecute triggers manual execution of a runbook.
func (h *Handler) RunbookExecute(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/runbooks")
		return
	}

	if h.runbookRepo == nil {
		h.redirect(w, r, "/runbooks")
		return
	}

	// Get the runbook definition
	rb, err := h.runbookRepo.GetByID(r.Context(), id)
	if err != nil {
		slog.Error("Runbook not found for execution", "id", id, "error", err)
		h.setFlash(w, r, "error", "Runbook not found")
		h.redirect(w, r, "/runbooks")
		return
	}

	if !rb.IsEnabled {
		slog.Warn("Attempted to execute disabled runbook", "id", id, "name", rb.Name)
		h.setFlash(w, r, "warning", "Cannot execute disabled runbook")
		h.redirect(w, r, "/runbooks")
		return
	}

	// Parse steps
	var steps []models.RunbookStep
	if rb.Steps != nil {
		if err := json.Unmarshal(rb.Steps, &steps); err != nil {
			slog.Error("Failed to parse runbook steps", "runbook", rb.Name, "error", err)
			h.setFlash(w, r, "error", "Invalid runbook step configuration")
			h.redirect(w, r, "/runbooks")
			return
		}
	}

	// Create execution record
	exec := &models.RunbookExecution{
		RunbookID: id,
		Status:    "running",
		Trigger:   "manual",
		StartedAt: time.Now(),
	}

	if user := GetUserFromContext(r.Context()); user != nil {
		if uid, err := uuid.Parse(user.ID); err == nil {
			exec.ExecutedBy = &uid
		}
	}

	// Execute steps sequentially
	stepResults := make([]map[string]interface{}, 0, len(steps))
	execStatus := "completed"
	hasStepFailures := false

	for _, step := range steps {
		stepStart := time.Now()
		result := map[string]interface{}{
			"order":      step.Order,
			"name":       step.Name,
			"type":       step.Type,
			"status":     "completed",
			"started_at": stepStart.Format(time.RFC3339),
		}

		switch step.Type {
		case "command", "docker_exec":
			var containerID, action string
			if step.Config != nil {
				containerID = step.Config["container_id"]
				action = step.Config["action"]
			}
			if containerID == "" {
				result["status"] = "skipped"
				result["error"] = "missing container_id in step config"
			} else {
				ctx := r.Context()
				var actionErr error
				switch action {
				case "start":
					actionErr = h.services.Containers().Start(ctx, containerID)
				case "stop":
					actionErr = h.services.Containers().Stop(ctx, containerID)
				case "restart":
					actionErr = h.services.Containers().Restart(ctx, containerID)
				default:
					// Default to restart for safety
					actionErr = h.services.Containers().Restart(ctx, containerID)
					result["note"] = "defaulted to restart action"
				}
				if actionErr != nil {
					result["status"] = "failed"
					result["error"] = actionErr.Error()
				} else {
					result["action"] = action
				}
			}

		case "wait":
			seconds := step.Timeout
			if seconds <= 0 {
				seconds = 5
			}
			if seconds > 60 {
				seconds = 60 // Cap at 60 seconds for safety
			}
			time.Sleep(time.Duration(seconds) * time.Second)
			result["waited_seconds"] = seconds

		case "notify":
			var channel, message string
			if step.Config != nil {
				channel = step.Config["channel"]
				message = step.Config["message"]
			}
			slog.Info("Runbook notification step executed",
				"runbook", rb.Name,
				"step", step.Name,
				"channel", channel,
				"message", message,
			)

		case "condition":
			result = h.executeConditionStep(r.Context(), step, result)

		case "api_call":
			result = h.executeAPICallStep(step, result)

		default:
			result["status"] = "skipped"
			result["note"] = "unsupported step type: " + step.Type
		}

		result["finished_at"] = time.Now().Format(time.RFC3339)
		stepResults = append(stepResults, result)

		// Track step failures
		if result["status"] == "failed" {
			hasStepFailures = true
			if step.OnFailure == "stop" {
				execStatus = "failed"
				break
			}
		}
	}

	// Finalize execution
	if hasStepFailures && execStatus != "failed" {
		execStatus = "partial_failure"
	}
	now := time.Now()
	exec.FinishedAt = &now
	exec.Status = execStatus

	if resultsJSON, err := json.Marshal(stepResults); err == nil {
		exec.StepResults = resultsJSON
	}

	if err := h.runbookRepo.CreateExecution(r.Context(), exec); err != nil {
		slog.Error("Failed to record runbook execution", "id", id, "error", err)
	}

	slog.Info("Runbook executed", "id", id, "name", rb.Name, "status", execStatus,
		"steps", len(steps), "results", len(stepResults))

	switch execStatus {
	case "completed":
		h.setFlash(w, r, "success", "Runbook '"+rb.Name+"' executed successfully")
	case "partial_failure":
		h.setFlash(w, r, "warning", "Runbook '"+rb.Name+"' completed with step failures")
	default:
		h.setFlash(w, r, "error", "Runbook '"+rb.Name+"' execution failed")
	}
	h.redirect(w, r, "/runbooks?tab=executions")
}

// ============================================================================
// Condition Step Evaluator
// ============================================================================

// executeConditionStep evaluates a condition step.
// Supported condition types:
//   - container_status: checks if a container is in the expected state
//   - compare: compares two string values with an operator (eq, neq, contains)
//
// Config keys:
//   - condition_type: "container_status" or "compare"
//   - container_id: (for container_status) the container to check
//   - expected_status: (for container_status) "running", "stopped", "exited", etc.
//   - left_value: (for compare) left operand
//   - operator: (for compare) "eq", "neq", "contains"
//   - right_value: (for compare) right operand
func (h *Handler) executeConditionStep(ctx context.Context, step models.RunbookStep, result map[string]interface{}) map[string]interface{} {
	if step.Config == nil {
		result["status"] = "failed"
		result["error"] = "condition step has no config"
		return result
	}

	condType := step.Config["condition_type"]
	switch condType {
	case "container_status":
		containerID := step.Config["container_id"]
		expectedStatus := step.Config["expected_status"]
		if containerID == "" || expectedStatus == "" {
			result["status"] = "failed"
			result["error"] = "container_id and expected_status are required"
			return result
		}

		container, err := h.services.Containers().Get(ctx, containerID)
		if err != nil {
			result["status"] = "failed"
			result["error"] = "failed to get container: " + err.Error()
			return result
		}

		actualStatus := strings.ToLower(container.State)
		expectedLower := strings.ToLower(expectedStatus)
		passed := actualStatus == expectedLower

		result["condition_type"] = "container_status"
		result["container_id"] = containerID
		result["actual_status"] = actualStatus
		result["expected_status"] = expectedLower
		result["passed"] = passed

		if passed {
			result["status"] = "completed"
		} else {
			result["status"] = "failed"
			result["error"] = fmt.Sprintf("container %s is '%s', expected '%s'", containerID, actualStatus, expectedLower)
		}

	case "compare":
		leftVal := step.Config["left_value"]
		operator := step.Config["operator"]
		rightVal := step.Config["right_value"]

		var passed bool
		switch operator {
		case "eq":
			passed = leftVal == rightVal
		case "neq":
			passed = leftVal != rightVal
		case "contains":
			passed = strings.Contains(leftVal, rightVal)
		default:
			result["status"] = "failed"
			result["error"] = "unsupported operator: " + operator
			return result
		}

		result["condition_type"] = "compare"
		result["left_value"] = leftVal
		result["operator"] = operator
		result["right_value"] = rightVal
		result["passed"] = passed

		if passed {
			result["status"] = "completed"
		} else {
			result["status"] = "failed"
			result["error"] = fmt.Sprintf("condition failed: '%s' %s '%s'", leftVal, operator, rightVal)
		}

	default:
		result["status"] = "failed"
		result["error"] = "unsupported condition_type: " + condType
	}

	return result
}

// ============================================================================
// API Call Step Executor
// ============================================================================

// executeAPICallStep performs an HTTP request to an external API.
//
// Config keys:
//   - url: (required) the URL to call
//   - method: HTTP method (GET, POST, PUT, DELETE). Default: GET
//   - body: request body for POST/PUT
//   - content_type: Content-Type header. Default: application/json
//   - auth_header: Authorization header value (e.g., "Bearer token123")
//   - expected_status: expected HTTP status code (e.g., "200"). Default: any 2xx
func (h *Handler) executeAPICallStep(step models.RunbookStep, result map[string]interface{}) map[string]interface{} {
	if step.Config == nil {
		result["status"] = "failed"
		result["error"] = "api_call step has no config"
		return result
	}

	apiURL := step.Config["url"]
	if apiURL == "" {
		result["status"] = "failed"
		result["error"] = "url is required for api_call step"
		return result
	}

	method := strings.ToUpper(step.Config["method"])
	if method == "" {
		method = "GET"
	}

	// Build request
	var bodyReader io.Reader
	if body := step.Config["body"]; body != "" && (method == "POST" || method == "PUT" || method == "PATCH") {
		bodyReader = strings.NewReader(body)
	}

	timeout := time.Duration(step.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if timeout > 30*time.Second {
		timeout = 30 * time.Second
	}

	client := &http.Client{Timeout: timeout}

	req, err := http.NewRequest(method, apiURL, bodyReader)
	if err != nil {
		result["status"] = "failed"
		result["error"] = "failed to create request: " + err.Error()
		return result
	}

	contentType := step.Config["content_type"]
	if contentType == "" {
		contentType = "application/json"
	}
	req.Header.Set("Content-Type", contentType)

	if authHeader := step.Config["auth_header"]; authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	req.Header.Set("User-Agent", "usulnet-runbook/1.0")

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		result["status"] = "failed"
		result["error"] = "request failed: " + err.Error()
		result["url"] = apiURL
		result["method"] = method
		return result
	}
	defer resp.Body.Close()

	// Read response body (limit to 4KB for safety)
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	result["url"] = apiURL
	result["method"] = method
	result["response_status"] = resp.StatusCode
	result["response_body"] = string(respBody)

	// Check expected status
	if expectedStatus := step.Config["expected_status"]; expectedStatus != "" {
		if fmt.Sprintf("%d", resp.StatusCode) != expectedStatus {
			result["status"] = "failed"
			result["error"] = fmt.Sprintf("expected status %s, got %d", expectedStatus, resp.StatusCode)
			return result
		}
	} else {
		// Default: any 2xx is success
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			result["status"] = "failed"
			result["error"] = fmt.Sprintf("request returned non-2xx status: %d", resp.StatusCode)
			return result
		}
	}

	result["status"] = "completed"
	return result
}
