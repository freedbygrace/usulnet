// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package logger

import (
	"strings"
)

// ============================================================================
// Log Sanitisation
// ============================================================================

// sensitiveKeys lists field names that must never appear in log output with
// their real values. Keys are matched case-insensitively.
var sensitiveKeys = map[string]bool{
	"password":              true,
	"passwd":                true,
	"secret":                true,
	"token":                 true,
	"jwt":                   true,
	"jwt_secret":            true,
	"api_key":               true,
	"apikey":                true,
	"access_key":            true,
	"secret_key":            true,
	"authorization":         true,
	"cookie":                true,
	"set-cookie":            true,
	"x-api-key":             true,
	"credential":            true,
	"credentials":           true,
	"private_key":           true,
	"encryption_key":        true,
	"config_encryption_key": true,
	"bind_password":         true,
	"client_secret":         true,
}

const redactedValue = "[REDACTED]"

// IsSensitiveKey returns true if the given key name refers to a sensitive
// field that should be redacted in logs.
func IsSensitiveKey(key string) bool {
	return sensitiveKeys[strings.ToLower(key)]
}

// RedactValue returns the redacted placeholder string.
func RedactValue() string {
	return redactedValue
}

// SanitizeField returns the value as-is if the key is not sensitive,
// or "[REDACTED]" if the key is sensitive.
func SanitizeField(key string, value interface{}) interface{} {
	if IsSensitiveKey(key) {
		return redactedValue
	}
	return value
}

// SanitizeMap creates a copy of the input map with sensitive values redacted.
// Non-string values are left unchanged unless their key is sensitive.
func SanitizeMap(m map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(m))
	for k, v := range m {
		result[k] = SanitizeField(k, v)
	}
	return result
}

// SanitizeStringMap creates a copy of the input map with sensitive values redacted.
func SanitizeStringMap(m map[string]string) map[string]string {
	result := make(map[string]string, len(m))
	for k, v := range m {
		if IsSensitiveKey(k) {
			result[k] = redactedValue
		} else {
			result[k] = v
		}
	}
	return result
}
