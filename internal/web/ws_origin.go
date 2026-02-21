// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

func isAllowedWebSocketOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	// Browsers always send Origin for WebSocket connections; reject clients that omit it.
	if origin == "" {
		return false
	}

	u, err := url.Parse(origin)
	if err != nil {
		return false
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}

	// Compare only hostnames (ignoring ports). r.URL.Hostname() is empty for
	// server-side requests; use r.Host (the HTTP Host header) instead.
	originHost := u.Hostname()
	serverHost := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		serverHost = h
	}

	if strings.EqualFold(originHost, serverHost) {
		return true
	}

	// Fallback: check X-Forwarded-Host (set by well-configured reverse proxies).
	// In reverse proxy deployments the backend r.Host may be 127.0.0.1:8080 while
	// the browser's origin uses the public hostname (e.g., app.example.com).
	if fwdHost := r.Header.Get("X-Forwarded-Host"); fwdHost != "" {
		fwdHostname := fwdHost
		if h, _, err := net.SplitHostPort(fwdHost); err == nil {
			fwdHostname = h
		}
		if strings.EqualFold(originHost, fwdHostname) {
			return true
		}
	}

	return false
}
