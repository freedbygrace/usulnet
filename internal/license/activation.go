// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package license

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const activationServerURL = "https://api.usulnet.com"

type ActivationClient struct {
	baseURL    string
	httpClient *http.Client
}

func NewActivationClient() *ActivationClient {
	return &ActivationClient{
		baseURL:    activationServerURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

type activateRequest struct {
	InstanceID string `json:"instance_id"`
	Hostname   string `json:"hostname"`
}

type activateResponse struct {
	Receipt   string `json:"receipt"`
	ExpiresAt string `json:"expires_at"`
}

type activateConflictResponse struct {
	Error           string `json:"error"`
	BoundInstanceID string `json:"bound_instance_id"`
	BoundHostname   string `json:"bound_hostname"`
	BoundSince      string `json:"bound_since"`
}

type instanceRequest struct {
	InstanceID string `json:"instance_id"`
}

type checkinResponse struct {
	Receipt             string `json:"receipt"`
	DeactivationPending bool   `json:"deactivation_pending"`
	ExpiresAt           string `json:"expires_at"`
	Revoked             bool   `json:"revoked"`
}

type CheckinResult struct {
	Receipt             string
	DeactivationPending bool
	Revoked             bool
}

func (c *ActivationClient) ActivateOnServer(licenseID, instanceID, hostname string) (string, error) {
	reqBody, err := json.Marshal(activateRequest{InstanceID: instanceID, Hostname: hostname})
	if err != nil {
		return "", fmt.Errorf("activation: marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.baseURL+"/api/v1/licenses/"+licenseID+"/activate",
		"application/json",
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return "", fmt.Errorf("activation: cannot reach license server (%s). Internet connectivity is required to activate a license: %w", c.baseURL, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 409 {
		var conflict activateConflictResponse
		if json.Unmarshal(body, &conflict) == nil && conflict.BoundInstanceID != "" {
			return "", fmt.Errorf("activation: license is already active on instance %q (hostname: %s, since: %s). Deactivate it first from Settings or from id.usulnet.com",
				conflict.BoundInstanceID, conflict.BoundHostname, conflict.BoundSince)
		}
		return "", fmt.Errorf("activation: license is already active on another instance")
	}

	if resp.StatusCode != 200 {
		var errResp struct {
			Error string `json:"error"`
		}
		json.Unmarshal(body, &errResp)
		if errResp.Error != "" {
			return "", fmt.Errorf("activation: server error: %s", errResp.Error)
		}
		return "", fmt.Errorf("activation: server returned HTTP %d", resp.StatusCode)
	}

	var result activateResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("activation: failed to parse server response: %w", err)
	}
	if result.Receipt == "" {
		return "", fmt.Errorf("activation: server returned empty receipt")
	}

	return result.Receipt, nil
}

func (c *ActivationClient) DeactivateOnServer(licenseID, instanceID string) error {
	reqBody, err := json.Marshal(instanceRequest{InstanceID: instanceID})
	if err != nil {
		return fmt.Errorf("deactivation: marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.baseURL+"/api/v1/licenses/"+licenseID+"/deactivate",
		"application/json",
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return fmt.Errorf("deactivation: server unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		var errResp struct {
			Error string `json:"error"`
		}
		json.Unmarshal(body, &errResp)
		return fmt.Errorf("deactivation: server returned HTTP %d: %s", resp.StatusCode, errResp.Error)
	}

	return nil
}

func (c *ActivationClient) Checkin(licenseID, instanceID string) (*CheckinResult, error) {
	reqBody, err := json.Marshal(instanceRequest{InstanceID: instanceID})
	if err != nil {
		return nil, fmt.Errorf("checkin: marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.baseURL+"/api/v1/licenses/"+licenseID+"/checkin",
		"application/json",
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return nil, fmt.Errorf("checkin: server unreachable: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 403 {
		return &CheckinResult{Revoked: true}, nil
	}

	if resp.StatusCode != 200 {
		var errResp struct {
			Error string `json:"error"`
		}
		json.Unmarshal(body, &errResp)
		return nil, fmt.Errorf("checkin: server returned HTTP %d: %s", resp.StatusCode, errResp.Error)
	}

	var result checkinResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("checkin: failed to parse server response: %w", err)
	}

	return &CheckinResult{
		Receipt:             result.Receipt,
		DeactivationPending: result.DeactivationPending,
		Revoked:             result.Revoked,
	}, nil
}

func (c *ActivationClient) ConfirmDeactivation(licenseID, instanceID string) error {
	reqBody, err := json.Marshal(instanceRequest{InstanceID: instanceID})
	if err != nil {
		return fmt.Errorf("confirm-deactivate: marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.baseURL+"/api/v1/licenses/"+licenseID+"/confirm-deactivate",
		"application/json",
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return fmt.Errorf("confirm-deactivate: server unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		var errResp struct {
			Error string `json:"error"`
		}
		json.Unmarshal(body, &errResp)
		return fmt.Errorf("confirm-deactivate: server returned HTTP %d: %s", resp.StatusCode, errResp.Error)
	}

	return nil
}
