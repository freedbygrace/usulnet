// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

import (
	"net/http/httptest"
	"testing"
)

func TestWebSocketUpgrader_CheckOrigin(t *testing.T) {
	tests := []struct {
		name   string
		origin string
		want   bool
	}{
		{name: "empty origin denied", origin: "", want: false},
		{name: "invalid origin denied", origin: "://bad-origin", want: false},
		{name: "non-http scheme denied", origin: "ws://app.example.com", want: false},
		{name: "different host denied", origin: "https://evil.example.com", want: false},
		{name: "same host allowed", origin: "https://app.example.com", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "https://app.example.com/api/v1/ws/containers/host/abc/logs", nil)
			req.Host = "app.example.com"
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}

			got := WebSocketUpgrader.CheckOrigin(req)
			if got != tt.want {
				t.Fatalf("CheckOrigin() = %v, want %v", got, tt.want)
			}
		})
	}
}
