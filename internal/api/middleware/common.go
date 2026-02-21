// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package middleware

import (
	"net"
	"net/http"
	"strings"
)

// ============================================================================
// IP extraction helpers
// ============================================================================

// getRealIP extracts the real client IP from the request.
// It uses RemoteAddr as primary source, then checks X-Real-IP (typically set
// by the closest reverse proxy) as a fallback. X-Forwarded-For is used last
// and takes the rightmost non-private IP to mitigate client-side spoofing.
func getRealIP(r *http.Request) string {
	// Primary: RemoteAddr is set by the HTTP server and is not client-spoofable
	remoteIP := r.RemoteAddr
	if ip, _, err := net.SplitHostPort(remoteIP); err == nil {
		remoteIP = ip
	}

	// If behind a trusted reverse proxy, X-Real-IP is set by the proxy itself
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return strings.TrimSpace(xrip)
	}

	// X-Forwarded-For: take the rightmost non-private IP (the one appended by
	// the closest trusted proxy, not the leftmost client-controlled value)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(parts[i])
			if ip != "" && !isPrivateIP(ip) {
				return ip
			}
		}
		// All IPs are private — use the rightmost one
		if len(parts) > 0 {
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}

	return remoteIP
}

// isPrivateIP checks if an IP string is in a private/reserved range.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
	}
	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// ============================================================================
// Header constants
// ============================================================================

const (
	// HeaderRealIP is the header name for real IP (from proxy)
	HeaderRealIP = "X-Real-IP"

	// HeaderForwardedFor is the header name for forwarded IPs
	HeaderForwardedFor = "X-Forwarded-For"

	// HeaderForwardedProto is the header for forwarded protocol
	HeaderForwardedProto = "X-Forwarded-Proto"

	// HeaderAuthorization is the authorization header
	HeaderAuthorization = "Authorization"

	// HeaderContentType is the content type header
	HeaderContentType = "Content-Type"

	// HeaderAccept is the accept header
	HeaderAccept = "Accept"
)

// ============================================================================
// Response type helpers
// ============================================================================

// isJSON checks if the request accepts JSON responses
func isJSON(r *http.Request) bool {
	accept := r.Header.Get(HeaderAccept)
	return strings.Contains(accept, "application/json") || accept == "*/*" || accept == ""
}

// wantsJSON is an alias for isJSON for readability
func wantsJSON(r *http.Request) bool {
	return isJSON(r)
}
