// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

func isAllowedWebSocketOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	// Allow connections without an Origin header (non-browser clients, internal
	// automation tools, CLI tools). Browsers always send Origin for WebSocket
	// connections, so this only relaxes access for programmatic clients.
	if origin == "" {
		return true
	}

	u, err := url.Parse(origin)
	if err != nil {
		return false
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}

	originHost := u.Hostname()

	// Determine the effective server host. In reverse proxy deployments the
	// X-Forwarded-Host header contains the public hostname the browser used,
	// while r.Host may contain the backend address (e.g., 127.0.0.1:8080).
	// We check both to avoid false rejections behind Nginx/Caddy/Traefik.
	serverHost := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		serverHost = h
	}

	if strings.EqualFold(originHost, serverHost) {
		return true
	}

	// Fallback: check X-Forwarded-Host (set by well-configured reverse proxies).
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
