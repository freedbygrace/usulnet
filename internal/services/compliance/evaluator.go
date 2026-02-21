// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package compliance

import (
	"context"
	"fmt"
	"strings"

	"github.com/docker/docker/api/types"
)

// DockerInspector provides read-only Docker container inspection for compliance checks.
type DockerInspector interface {
	ListRunningContainers(ctx context.Context) ([]types.Container, error)
	InspectContainer(ctx context.Context, id string) (types.ContainerJSON, error)
}

// checkFunc evaluates a single compliance check across all running containers.
// Returns pass/fail status and a human-readable details string.
type checkFunc func(ctx context.Context, containers []types.ContainerJSON) (status string, details string)

// dockerChecks maps CheckQuery strings to their evaluation functions.
var dockerChecks = map[string]checkFunc{
	"containers_not_running_as_root":  checkNotRunningAsRoot,
	"containers_readonly_rootfs":      checkReadonlyRootfs,
	"containers_no_new_privileges":    checkNoNewPrivileges,
	"containers_capabilities_dropped": checkCapabilitiesDropped,
	"containers_not_privileged":       checkNotPrivileged,
	"containers_have_resource_limits": checkResourceLimits,
	"containers_no_host_namespaces":   checkNoHostNamespaces,
	"containers_network_segmented":    checkNetworkSegmented,
	"images_use_specific_tags":        checkSpecificTags,
}

// runDockerCheck executes a registered Docker-based compliance check.
// Returns "", "" if the checkQuery has no registered handler.
func runDockerCheck(ctx context.Context, inspector DockerInspector, checkQuery string) (status, details string, handled bool) {
	fn, ok := dockerChecks[checkQuery]
	if !ok {
		return "", "", false
	}

	containers, err := inspector.ListRunningContainers(ctx)
	if err != nil {
		return "fail", fmt.Sprintf("failed to list containers: %v", err), true
	}

	if len(containers) == 0 {
		return "pass", "No running containers to evaluate", true
	}

	// Inspect all containers
	var inspected []types.ContainerJSON
	for _, c := range containers {
		insp, err := inspector.InspectContainer(ctx, c.ID)
		if err != nil {
			continue // skip containers that can't be inspected
		}
		inspected = append(inspected, insp)
	}

	if len(inspected) == 0 {
		return "pass", "No containers could be inspected", true
	}

	s, d := fn(ctx, inspected)
	return s, d, true
}

// --- Check implementations ---

func checkNotRunningAsRoot(_ context.Context, containers []types.ContainerJSON) (string, string) {
	var violations []string
	for _, c := range containers {
		user := ""
		if c.Config != nil {
			user = c.Config.User
		}
		if user == "" || user == "0" || user == "root" {
			violations = append(violations, containerName(c))
		}
	}
	return summarize(violations, len(containers), "running as root")
}

func checkReadonlyRootfs(_ context.Context, containers []types.ContainerJSON) (string, string) {
	var violations []string
	for _, c := range containers {
		if c.HostConfig == nil || !c.HostConfig.ReadonlyRootfs {
			violations = append(violations, containerName(c))
		}
	}
	return summarize(violations, len(containers), "without read-only root filesystem")
}

func checkNoNewPrivileges(_ context.Context, containers []types.ContainerJSON) (string, string) {
	var violations []string
	for _, c := range containers {
		if c.HostConfig == nil {
			violations = append(violations, containerName(c))
			continue
		}
		found := false
		for _, opt := range c.HostConfig.SecurityOpt {
			if opt == "no-new-privileges" || opt == "no-new-privileges:true" || opt == "no-new-privileges=true" {
				found = true
				break
			}
		}
		if !found {
			violations = append(violations, containerName(c))
		}
	}
	return summarize(violations, len(containers), "without no-new-privileges")
}

func checkCapabilitiesDropped(_ context.Context, containers []types.ContainerJSON) (string, string) {
	var violations []string
	for _, c := range containers {
		if c.HostConfig == nil {
			violations = append(violations, containerName(c))
			continue
		}
		dropped := false
		for _, cap := range c.HostConfig.CapDrop {
			if strings.EqualFold(cap, "ALL") {
				dropped = true
				break
			}
		}
		if !dropped {
			violations = append(violations, containerName(c))
		}
	}
	return summarize(violations, len(containers), "without ALL capabilities dropped")
}

func checkNotPrivileged(_ context.Context, containers []types.ContainerJSON) (string, string) {
	var violations []string
	for _, c := range containers {
		if c.HostConfig != nil && c.HostConfig.Privileged {
			violations = append(violations, containerName(c))
		}
	}
	return summarize(violations, len(containers), "running in privileged mode")
}

func checkResourceLimits(_ context.Context, containers []types.ContainerJSON) (string, string) {
	var violations []string
	for _, c := range containers {
		if c.HostConfig == nil {
			violations = append(violations, containerName(c))
			continue
		}
		hasMemory := c.HostConfig.Memory > 0
		hasCPU := c.HostConfig.NanoCPUs > 0 || c.HostConfig.CPUQuota > 0 || c.HostConfig.CPUShares > 0
		if !hasMemory || !hasCPU {
			violations = append(violations, containerName(c))
		}
	}
	return summarize(violations, len(containers), "without resource limits (memory+CPU)")
}

func checkNoHostNamespaces(_ context.Context, containers []types.ContainerJSON) (string, string) {
	var violations []string
	for _, c := range containers {
		if c.HostConfig == nil {
			continue
		}
		var reasons []string
		if c.HostConfig.PidMode.IsHost() {
			reasons = append(reasons, "pid=host")
		}
		if c.HostConfig.NetworkMode.IsHost() {
			reasons = append(reasons, "network=host")
		}
		if c.HostConfig.IpcMode.IsHost() {
			reasons = append(reasons, "ipc=host")
		}
		if len(reasons) > 0 {
			violations = append(violations, fmt.Sprintf("%s (%s)", containerName(c), strings.Join(reasons, ", ")))
		}
	}
	return summarize(violations, len(containers), "using host namespaces")
}

func checkNetworkSegmented(_ context.Context, containers []types.ContainerJSON) (string, string) {
	var violations []string
	for _, c := range containers {
		if c.NetworkSettings == nil || len(c.NetworkSettings.Networks) == 0 {
			continue
		}
		for netName := range c.NetworkSettings.Networks {
			if netName == "bridge" {
				violations = append(violations, containerName(c))
				break
			}
		}
	}
	return summarize(violations, len(containers), "on default bridge network")
}

func checkSpecificTags(_ context.Context, containers []types.ContainerJSON) (string, string) {
	var violations []string
	for _, c := range containers {
		if c.Config == nil {
			continue
		}
		image := c.Config.Image
		// No tag specified or using :latest
		if !strings.Contains(image, ":") || strings.HasSuffix(image, ":latest") {
			violations = append(violations, fmt.Sprintf("%s (image: %s)", containerName(c), image))
		}
	}
	return summarize(violations, len(containers), "using :latest or untagged images")
}

// --- Helpers ---

func containerName(c types.ContainerJSON) string {
	if c.Name != "" {
		return strings.TrimPrefix(c.Name, "/")
	}
	if len(c.ID) > 12 {
		return c.ID[:12]
	}
	return c.ID
}

func summarize(violations []string, total int, issue string) (string, string) {
	if len(violations) == 0 {
		return "pass", fmt.Sprintf("All %d containers pass: none %s", total, issue)
	}

	maxShow := 5
	shown := violations
	suffix := ""
	if len(violations) > maxShow {
		shown = violations[:maxShow]
		suffix = fmt.Sprintf(" (+%d more)", len(violations)-maxShow)
	}

	return "fail", fmt.Sprintf("%d/%d containers %s: %s%s",
		len(violations), total, issue,
		strings.Join(shown, ", "), suffix)
}
