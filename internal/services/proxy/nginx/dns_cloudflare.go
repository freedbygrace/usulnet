// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package nginx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const cloudflareAPIBase = "https://api.cloudflare.com/client/v4"

// CloudflareDNSClient manages DNS TXT records via the Cloudflare API.
// Used for ACME DNS-01 challenges (wildcard certificates).
type CloudflareDNSClient struct {
	apiToken   string
	httpClient *http.Client
}

// NewCloudflareDNSClient creates a Cloudflare DNS client.
func NewCloudflareDNSClient(apiToken string) *CloudflareDNSClient {
	return &CloudflareDNSClient{
		apiToken: apiToken,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// cfResponse is the generic Cloudflare API response wrapper.
type cfResponse struct {
	Success  bool            `json:"success"`
	Errors   []cfError       `json:"errors"`
	Result   json.RawMessage `json:"result"`
	ResultInfo *cfResultInfo `json:"result_info,omitempty"`
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfResultInfo struct {
	TotalCount int `json:"total_count"`
}

type cfZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfDNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

// GetZoneID finds the Cloudflare zone ID for the given domain.
// It walks up the domain hierarchy to find the matching zone.
func (c *CloudflareDNSClient) GetZoneID(ctx context.Context, domain string) (string, error) {
	// Strip wildcard prefix
	domain = strings.TrimPrefix(domain, "*.")

	// Try increasingly broader domain suffixes
	parts := strings.Split(domain, ".")
	for i := range len(parts) - 1 {
		candidate := strings.Join(parts[i:], ".")
		zoneID, err := c.findZone(ctx, candidate)
		if err != nil {
			return "", err
		}
		if zoneID != "" {
			return zoneID, nil
		}
	}

	return "", fmt.Errorf("cloudflare: no zone found for domain %s", domain)
}

// CreateTXTRecord creates a TXT record for the ACME DNS-01 challenge.
func (c *CloudflareDNSClient) CreateTXTRecord(ctx context.Context, zoneID, fqdn, value string) (recordID string, err error) {
	payload := map[string]interface{}{
		"type":    "TXT",
		"name":    fqdn,
		"content": value,
		"ttl":     120,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("cloudflare: marshal request: %w", err)
	}

	resp, err := c.doRequest(ctx, "POST", fmt.Sprintf("/zones/%s/dns_records", zoneID), body)
	if err != nil {
		return "", fmt.Errorf("cloudflare: create TXT record: %w", err)
	}

	var record cfDNSRecord
	if err := json.Unmarshal(resp.Result, &record); err != nil {
		return "", fmt.Errorf("cloudflare: parse create response: %w", err)
	}

	return record.ID, nil
}

// DeleteTXTRecord removes a DNS record by ID.
func (c *CloudflareDNSClient) DeleteTXTRecord(ctx context.Context, zoneID, recordID string) error {
	_, err := c.doRequest(ctx, "DELETE", fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, recordID), nil)
	if err != nil {
		return fmt.Errorf("cloudflare: delete TXT record: %w", err)
	}
	return nil
}

// findZone looks up a zone by exact name match.
func (c *CloudflareDNSClient) findZone(ctx context.Context, name string) (string, error) {
	resp, err := c.doRequest(ctx, "GET", fmt.Sprintf("/zones?name=%s&status=active", name), nil)
	if err != nil {
		return "", err
	}

	var zones []cfZone
	if err := json.Unmarshal(resp.Result, &zones); err != nil {
		return "", fmt.Errorf("cloudflare: parse zones: %w", err)
	}

	for _, z := range zones {
		if z.Name == name {
			return z.ID, nil
		}
	}
	return "", nil
}

// doRequest performs an authenticated HTTP request to the Cloudflare API.
func (c *CloudflareDNSClient) doRequest(ctx context.Context, method, path string, body []byte) (*cfResponse, error) {
	url := cloudflareAPIBase + path

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: http request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: read response: %w", err)
	}

	var cfResp cfResponse
	if err := json.Unmarshal(respBody, &cfResp); err != nil {
		return nil, fmt.Errorf("cloudflare: parse response (status %d): %w", resp.StatusCode, err)
	}

	if !cfResp.Success {
		if len(cfResp.Errors) > 0 {
			return nil, fmt.Errorf("cloudflare: API error: %s (code %d)", cfResp.Errors[0].Message, cfResp.Errors[0].Code)
		}
		return nil, fmt.Errorf("cloudflare: API error (status %d)", resp.StatusCode)
	}

	return &cfResp, nil
}
