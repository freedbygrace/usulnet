// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/fr4nsys/usulnet/internal/gateway/protocol"
)

// FirewallDetectResponse contains the detected firewall backend info.
type FirewallDetectResponse struct {
	Backend string `json:"backend"` // iptables, nftables, unknown
	Version string `json:"version"`
	Path    string `json:"path"`
}

// FirewallApplyRequest contains the rules to apply.
type FirewallApplyRequest struct {
	Backend string              `json:"backend"`
	Rules   []FirewallApplyRule `json:"rules"`
}

// FirewallApplyRule represents a single rule to apply.
type FirewallApplyRule struct {
	Chain         string `json:"chain"`
	Protocol      string `json:"protocol"`
	Source        string `json:"source"`
	Destination   string `json:"destination"`
	SrcPort       string `json:"src_port"`
	DstPort       string `json:"dst_port"`
	Action        string `json:"action"`
	InterfaceName string `json:"interface_name"`
	Comment       string `json:"comment"`
	Position      int    `json:"position"`
}

// FirewallSyncResponse contains the current host firewall state.
type FirewallSyncResponse struct {
	Backend string `json:"backend"`
	Output  string `json:"output"`
}

// registerFirewallHandlers registers firewall-related command handlers.
func (e *Executor) registerFirewallHandlers() {
	e.handlers[protocol.CmdFirewallDetect] = e.handleFirewallDetect
	e.handlers[protocol.CmdFirewallApply] = e.handleFirewallApply
	e.handlers[protocol.CmdFirewallSync] = e.handleFirewallSync
}

// handleFirewallDetect detects the available firewall backend on the host.
func (e *Executor) handleFirewallDetect(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	// Try iptables first (most common)
	if path, err := exec.LookPath("iptables"); err == nil {
		out, verErr := exec.CommandContext(ctx, "iptables", "--version").CombinedOutput()
		version := strings.TrimSpace(string(out))
		if verErr != nil {
			version = "unknown"
		}
		return e.successResult(FirewallDetectResponse{
			Backend: "iptables",
			Version: version,
			Path:    path,
		})
	}

	// Try nftables
	if path, err := exec.LookPath("nft"); err == nil {
		out, verErr := exec.CommandContext(ctx, "nft", "--version").CombinedOutput()
		version := strings.TrimSpace(string(out))
		if verErr != nil {
			version = "unknown"
		}
		return e.successResult(FirewallDetectResponse{
			Backend: "nftables",
			Version: version,
			Path:    path,
		})
	}

	return e.successResult(FirewallDetectResponse{
		Backend: "unknown",
		Version: "",
		Path:    "",
	})
}

// handleFirewallApply applies firewall rules from the DB to the host.
// Safety: NEVER flushes DOCKER or DOCKER-USER chains entirely.
// Only appends/inserts rules into specified chains.
func (e *Executor) handleFirewallApply(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	rulesJSON := cmd.Params.FirewallRules
	if rulesJSON == "" {
		return e.invalidParamsResult("firewall_rules is required")
	}

	var req FirewallApplyRequest
	if err := json.Unmarshal([]byte(rulesJSON), &req); err != nil {
		return e.invalidParamsResult(fmt.Sprintf("invalid firewall_rules JSON: %v", err))
	}

	if req.Backend == "" {
		req.Backend = "iptables"
	}

	var applied int
	var warnings []string

	for _, rule := range req.Rules {
		var cmdArgs []string

		switch req.Backend {
		case "iptables":
			cmdArgs = buildIptablesArgs(rule)
		case "nftables":
			// nftables support is detection-only for now; rules use iptables-compat
			cmdArgs = buildIptablesArgs(rule)
		default:
			warnings = append(warnings, fmt.Sprintf("unsupported backend: %s", req.Backend))
			continue
		}

		e.log.Debug("Applying firewall rule", "args", cmdArgs)

		out, err := exec.CommandContext(ctx, "iptables", cmdArgs...).CombinedOutput()
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("rule %s/%s:%s→%s failed: %s (%v)",
				rule.Chain, rule.Protocol, rule.DstPort, rule.Action,
				strings.TrimSpace(string(out)), err))
			continue
		}
		applied++
	}

	return e.successResult(map[string]interface{}{
		"applied":  applied,
		"total":    len(req.Rules),
		"warnings": warnings,
	})
}

// handleFirewallSync reads the current firewall state from the host.
func (e *Executor) handleFirewallSync(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	backend := cmd.Params.FirewallBackend
	if backend == "" {
		backend = "iptables"
	}

	var cmdName string
	var cmdArgs []string

	switch backend {
	case "iptables":
		cmdName = "iptables-save"
	case "nftables":
		cmdName = "nft"
		cmdArgs = []string{"list", "ruleset"}
	default:
		return e.invalidParamsResult(fmt.Sprintf("unsupported backend: %s", backend))
	}

	out, err := exec.CommandContext(ctx, cmdName, cmdArgs...).CombinedOutput()
	if err != nil {
		return e.errorResult(fmt.Errorf("firewall sync (%s): %s: %w", backend, strings.TrimSpace(string(out)), err))
	}

	return e.successResult(FirewallSyncResponse{
		Backend: backend,
		Output:  string(out),
	})
}

// buildIptablesArgs builds iptables command arguments from a rule.
// Uses -A (append) to add rules. Never flushes chains.
func buildIptablesArgs(rule FirewallApplyRule) []string {
	args := []string{"-A", rule.Chain}

	if rule.Protocol != "" && rule.Protocol != "all" {
		args = append(args, "-p", rule.Protocol)
	}

	if rule.Source != "" {
		args = append(args, "-s", rule.Source)
	}

	if rule.Destination != "" {
		args = append(args, "-d", rule.Destination)
	}

	if rule.InterfaceName != "" {
		args = append(args, "-i", rule.InterfaceName)
	}

	if rule.SrcPort != "" && rule.Protocol != "" && rule.Protocol != "all" && rule.Protocol != "icmp" {
		args = append(args, "--sport", rule.SrcPort)
	}

	if rule.DstPort != "" && rule.Protocol != "" && rule.Protocol != "all" && rule.Protocol != "icmp" {
		args = append(args, "--dport", rule.DstPort)
	}

	if rule.Comment != "" {
		args = append(args, "-m", "comment", "--comment", rule.Comment)
	}

	args = append(args, "-j", rule.Action)

	return args
}
