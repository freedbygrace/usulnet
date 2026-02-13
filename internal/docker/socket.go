// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package docker

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"
)

// DetectSocketPath attempts to find the Docker daemon socket automatically.
// Detection order:
//  1. DOCKER_HOST env var (if it points to a unix socket)
//  2. Standard path: /var/run/docker.sock
//  3. Rootless paths: $XDG_RUNTIME_DIR/docker.sock, /run/user/<UID>/docker.sock
//  4. docker context inspect (parses the active context endpoint)
//  5. Falls back to /var/run/docker.sock (may produce a warning if absent)
func DetectSocketPath() string {
	// 1. Check DOCKER_HOST env var
	if host := os.Getenv("DOCKER_HOST"); host != "" {
		if path, ok := parseUnixSocket(host); ok {
			if socketExists(path) {
				return path
			}
		}
	}

	// 2. Standard path
	if socketExists(DefaultLocalSocketPath) {
		return DefaultLocalSocketPath
	}

	// 3. Rootless Docker paths
	if path := detectRootlessSocket(); path != "" {
		return path
	}

	// 4. docker context inspect
	if path := detectFromDockerContext(); path != "" {
		return path
	}

	// 5. Final fallback — return the standard path even if absent,
	//    so the existing warning ("Docker socket not found") is shown.
	return DefaultLocalSocketPath
}

// detectRootlessSocket checks common rootless Docker socket locations.
func detectRootlessSocket() string {
	// Try $XDG_RUNTIME_DIR/docker.sock first
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		path := xdg + "/docker.sock"
		if socketExists(path) {
			return path
		}
	}

	// Try /run/user/<UID>/docker.sock
	if u, err := user.Current(); err == nil {
		path := "/run/user/" + u.Uid + "/docker.sock"
		if socketExists(path) {
			return path
		}
	}

	return ""
}

// detectFromDockerContext runs `docker context inspect` and extracts the socket
// path from the active context. Returns empty string on any failure.
func detectFromDockerContext() string {
	cmd := exec.Command("docker", "context", "inspect")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}

	// Output is a JSON array: [{"Name":"default","Endpoints":{"docker":{"Host":"unix:///..."}}}]
	var contexts []dockerContextInfo
	if err := json.Unmarshal(out, &contexts); err != nil {
		return ""
	}
	if len(contexts) == 0 {
		return ""
	}

	host := contexts[0].Endpoints.Docker.Host
	if path, ok := parseUnixSocket(host); ok {
		if socketExists(path) {
			return path
		}
	}

	return ""
}

// dockerContextInfo is a minimal representation of `docker context inspect` output.
type dockerContextInfo struct {
	Endpoints struct {
		Docker struct {
			Host string `json:"Host"`
		} `json:"docker"`
	} `json:"Endpoints"`
}

// parseUnixSocket extracts the filesystem path from a unix:// URI.
// Returns the path and true if the URI is a unix socket, or ("", false) otherwise.
func parseUnixSocket(host string) (string, bool) {
	if strings.HasPrefix(host, "unix://") {
		return strings.TrimPrefix(host, "unix://"), true
	}
	return "", false
}

// socketExists checks whether a Unix socket file exists at the given path.
func socketExists(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fi.Mode().Type()&os.ModeSocket != 0
}

// FormatDetectedSocket returns a human-readable message about how the socket was found.
func FormatDetectedSocket(path string) string {
	if path == DefaultLocalSocketPath {
		return fmt.Sprintf("Using default Docker socket: %s", path)
	}
	return fmt.Sprintf("Auto-detected Docker socket: %s", path)
}
