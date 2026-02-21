// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package executor

import (
	"encoding/json"
	"testing"

	"github.com/fr4nsys/usulnet/internal/gateway/protocol"
)

// ============================================================================
// decodeParams Tests
// ============================================================================

func TestDecodeParams(t *testing.T) {
	t.Run("decode SecurityScanRequest from params", func(t *testing.T) {
		p := protocol.CommandParams{
			ContainerID: "abc123",
			All:         true,
		}

		var req SecurityScanRequest
		if err := decodeParams(p, &req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if req.ContainerID != "abc123" {
			t.Errorf("expected ContainerID 'abc123', got %q", req.ContainerID)
		}
		// Note: All maps to scan_all only if the JSON tag matches.
		// CommandParams.All has json tag "all", SecurityScanRequest.ScanAll has "scan_all"
		// So ScanAll should NOT be set from CommandParams.All
		if req.ScanAll {
			t.Error("expected ScanAll false (JSON tag mismatch: 'all' vs 'scan_all')")
		}
	})

	t.Run("decode into empty struct", func(t *testing.T) {
		p := protocol.CommandParams{}

		var req SecurityScanRequest
		if err := decodeParams(p, &req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if req.ContainerID != "" {
			t.Errorf("expected empty ContainerID, got %q", req.ContainerID)
		}
		if req.ScanAll {
			t.Error("expected ScanAll false")
		}
		if req.IncludeCVE {
			t.Error("expected IncludeCVE false")
		}
	})

	t.Run("decode arbitrary struct", func(t *testing.T) {
		p := protocol.CommandParams{
			ImageRef: "nginx:latest",
			Force:    true,
		}

		type custom struct {
			ImageRef string `json:"image_ref"`
			Force    bool   `json:"force"`
		}

		var c custom
		if err := decodeParams(p, &c); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if c.ImageRef != "nginx:latest" {
			t.Errorf("expected ImageRef 'nginx:latest', got %q", c.ImageRef)
		}
		if !c.Force {
			t.Error("expected Force true")
		}
	})

	t.Run("decode with nil target panics", func(t *testing.T) {
		p := protocol.CommandParams{}

		// Passing nil to json.Unmarshal returns error
		err := decodeParams(p, nil)
		if err == nil {
			t.Error("expected error when decoding into nil")
		}
	})
}

// ============================================================================
// failedResult Tests
// ============================================================================

func TestFailedResult(t *testing.T) {
	t.Run("basic message", func(t *testing.T) {
		result := failedResult("something went wrong")

		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Status != protocol.CommandStatusFailed {
			t.Errorf("expected status %q, got %q", protocol.CommandStatusFailed, result.Status)
		}
		if result.Error == nil {
			t.Fatal("expected non-nil error")
		}
		if result.Error.Code != "SCAN_ERROR" {
			t.Errorf("expected error code 'SCAN_ERROR', got %q", result.Error.Code)
		}
		if result.Error.Message != "something went wrong" {
			t.Errorf("expected message 'something went wrong', got %q", result.Error.Message)
		}
		if result.Data != nil {
			t.Error("expected nil Data in failed result")
		}
	})

	t.Run("empty message", func(t *testing.T) {
		result := failedResult("")

		if result.Error.Message != "" {
			t.Errorf("expected empty message, got %q", result.Error.Message)
		}
		if result.Error.Code != "SCAN_ERROR" {
			t.Errorf("expected error code 'SCAN_ERROR', got %q", result.Error.Code)
		}
	})
}

// ============================================================================
// Struct Types Tests
// ============================================================================

func TestSecurityScanRequestJSON(t *testing.T) {
	req := SecurityScanRequest{
		ContainerID: "abc123",
		ScanAll:     true,
		IncludeCVE:  true,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded SecurityScanRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.ContainerID != "abc123" {
		t.Errorf("expected ContainerID 'abc123', got %q", decoded.ContainerID)
	}
	if !decoded.ScanAll {
		t.Error("expected ScanAll true")
	}
	if !decoded.IncludeCVE {
		t.Error("expected IncludeCVE true")
	}
}

func TestSecurityScanRequestJSONOmitEmpty(t *testing.T) {
	req := SecurityScanRequest{}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	// All fields have omitempty, so empty struct should produce "{}"
	if string(data) != "{}" {
		t.Errorf("expected '{}' for zero-value struct, got %q", string(data))
	}
}

func TestSecurityScanResponseJSON(t *testing.T) {
	resp := SecurityScanResponse{
		Scans: []ContainerScanData{
			{
				ContainerID:   "id1",
				ContainerName: "/web",
				Image:         "nginx:latest",
			},
		},
		Warnings: []string{"could not inspect container x"},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded SecurityScanResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if len(decoded.Scans) != 1 {
		t.Fatalf("expected 1 scan, got %d", len(decoded.Scans))
	}
	if decoded.Scans[0].ContainerID != "id1" {
		t.Errorf("expected ContainerID 'id1', got %q", decoded.Scans[0].ContainerID)
	}
	if decoded.Scans[0].ContainerName != "/web" {
		t.Errorf("expected ContainerName '/web', got %q", decoded.Scans[0].ContainerName)
	}
	if decoded.Scans[0].Image != "nginx:latest" {
		t.Errorf("expected Image 'nginx:latest', got %q", decoded.Scans[0].Image)
	}
	if len(decoded.Warnings) != 1 || decoded.Warnings[0] != "could not inspect container x" {
		t.Errorf("unexpected warnings: %v", decoded.Warnings)
	}
}

func TestContainerScanDataJSON(t *testing.T) {
	scan := ContainerScanData{
		ContainerID:   "abc",
		ContainerName: "/test",
		Image:         "alpine:3.18",
	}

	data, err := json.Marshal(scan)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded ContainerScanData
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.ContainerID != "abc" {
		t.Errorf("expected ContainerID 'abc', got %q", decoded.ContainerID)
	}
	if decoded.ContainerName != "/test" {
		t.Errorf("expected ContainerName '/test', got %q", decoded.ContainerName)
	}
	if decoded.Image != "alpine:3.18" {
		t.Errorf("expected Image 'alpine:3.18', got %q", decoded.Image)
	}
}
