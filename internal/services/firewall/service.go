// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package firewall provides visual iptables/nftables management.
package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/gateway/protocol"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// RuleRepository defines persistence for firewall rules.
type RuleRepository interface {
	Create(ctx context.Context, rule *models.FirewallRule) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.FirewallRule, error)
	List(ctx context.Context, hostID uuid.UUID) ([]models.FirewallRule, error)
	Update(ctx context.Context, rule *models.FirewallRule) error
	Delete(ctx context.Context, id uuid.UUID) error
	MarkApplied(ctx context.Context, hostID uuid.UUID) error
	NextPosition(ctx context.Context, hostID uuid.UUID, chain string) (int, error)
}

// AuditRepository defines persistence for firewall audit logs.
type AuditRepository interface {
	Create(ctx context.Context, entry *models.FirewallAuditLog) error
	List(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]models.FirewallAuditLog, int, error)
}

// CommandSender sends commands to remote agents.
type CommandSender interface {
	SendCommand(ctx context.Context, hostID uuid.UUID, cmd *protocol.Command) (*protocol.CommandResult, error)
}

// Service implements firewall management business logic.
type Service struct {
	rules  RuleRepository
	audit  AuditRepository
	sender CommandSender
	logger *logger.Logger
}

// NewService creates a new firewall service.
func NewService(rules RuleRepository, audit AuditRepository, log *logger.Logger) *Service {
	return &Service{
		rules:  rules,
		audit:  audit,
		logger: log.Named("firewall"),
	}
}

// SetCommandSender configures the gateway for sending commands to agents.
func (s *Service) SetCommandSender(sender CommandSender) {
	s.sender = sender
}

// ============================================================================
// CRUD
// ============================================================================

// ListRules returns all firewall rules for a host.
func (s *Service) ListRules(ctx context.Context, hostID uuid.UUID) ([]models.FirewallRule, error) {
	return s.rules.List(ctx, hostID)
}

// GetRule returns a firewall rule by ID.
func (s *Service) GetRule(ctx context.Context, id uuid.UUID) (*models.FirewallRule, error) {
	return s.rules.GetByID(ctx, id)
}

// CreateRule creates a new firewall rule.
func (s *Service) CreateRule(ctx context.Context, hostID uuid.UUID, input models.CreateFirewallRuleInput, userID *uuid.UUID) (*models.FirewallRule, error) {
	pos, err := s.rules.NextPosition(ctx, hostID, string(input.Chain))
	if err != nil {
		return nil, fmt.Errorf("next position: %w", err)
	}

	rule := &models.FirewallRule{
		ID:            uuid.New(),
		HostID:        hostID,
		Name:          input.Name,
		Description:   input.Description,
		Chain:         input.Chain,
		Protocol:      input.Protocol,
		Source:        input.Source,
		Destination:   input.Destination,
		SrcPort:       input.SrcPort,
		DstPort:       input.DstPort,
		Action:        input.Action,
		Direction:     input.Direction,
		InterfaceName: input.InterfaceName,
		Position:      pos,
		Enabled:       input.Enabled,
		ContainerID:   input.ContainerID,
		NetworkName:   input.NetworkName,
		Comment:       input.Comment,
		CreatedBy:     userID,
	}

	if err := s.rules.Create(ctx, rule); err != nil {
		return nil, err
	}

	s.logAudit(ctx, hostID, userID, "create", &rule.ID,
		fmt.Sprintf("%s %s %s %s:%s → %s", rule.Chain, rule.Protocol, rule.Source, rule.Destination, rule.DstPort, rule.Action), "")

	return rule, nil
}

// UpdateRule updates an existing firewall rule.
func (s *Service) UpdateRule(ctx context.Context, id uuid.UUID, input models.UpdateFirewallRuleInput, userID *uuid.UUID) (*models.FirewallRule, error) {
	rule, err := s.rules.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Apply partial updates
	if input.Name != nil {
		rule.Name = *input.Name
	}
	if input.Description != nil {
		rule.Description = *input.Description
	}
	if input.Chain != nil {
		rule.Chain = *input.Chain
	}
	if input.Protocol != nil {
		rule.Protocol = *input.Protocol
	}
	if input.Source != nil {
		rule.Source = *input.Source
	}
	if input.Destination != nil {
		rule.Destination = *input.Destination
	}
	if input.SrcPort != nil {
		rule.SrcPort = *input.SrcPort
	}
	if input.DstPort != nil {
		rule.DstPort = *input.DstPort
	}
	if input.Action != nil {
		rule.Action = *input.Action
	}
	if input.Direction != nil {
		rule.Direction = *input.Direction
	}
	if input.InterfaceName != nil {
		rule.InterfaceName = *input.InterfaceName
	}
	if input.ContainerID != nil {
		rule.ContainerID = *input.ContainerID
	}
	if input.NetworkName != nil {
		rule.NetworkName = *input.NetworkName
	}
	if input.Comment != nil {
		rule.Comment = *input.Comment
	}
	if input.Enabled != nil {
		rule.Enabled = *input.Enabled
	}

	if err := s.rules.Update(ctx, rule); err != nil {
		return nil, err
	}

	s.logAudit(ctx, rule.HostID, userID, "update", &rule.ID,
		fmt.Sprintf("%s %s %s:%s → %s", rule.Chain, rule.Protocol, rule.Destination, rule.DstPort, rule.Action), "")

	return rule, nil
}

// DeleteRule deletes a firewall rule.
func (s *Service) DeleteRule(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error {
	rule, err := s.rules.GetByID(ctx, id)
	if err != nil {
		return err
	}

	if err := s.rules.Delete(ctx, id); err != nil {
		return err
	}

	s.logAudit(ctx, rule.HostID, userID, "delete", &rule.ID,
		fmt.Sprintf("%s %s %s:%s → %s", rule.Chain, rule.Protocol, rule.Destination, rule.DstPort, rule.Action), "")

	return nil
}

// ============================================================================
// Agent commands
// ============================================================================

// DetectBackend detects the firewall backend on a host via the agent.
func (s *Service) DetectBackend(ctx context.Context, hostID uuid.UUID) (*models.FirewallHostStatus, error) {
	if s.sender == nil {
		return &models.FirewallHostStatus{Backend: models.FirewallBackendUnknown}, nil
	}

	cmd := &protocol.Command{
		ID:       uuid.NewString(),
		Type:     protocol.CmdFirewallDetect,
		HostID:   hostID.String(),
		Priority: protocol.PriorityNormal,
		Timeout:  15 * time.Second,
		Params:   protocol.CommandParams{},
	}

	result, err := s.sender.SendCommand(ctx, hostID, cmd)
	if err != nil {
		return nil, fmt.Errorf("detect backend: %w", err)
	}
	if result.Error != nil {
		return nil, fmt.Errorf("detect backend: %s", result.Error.Message)
	}

	// Parse response
	data, err := json.Marshal(result.Data)
	if err != nil {
		return nil, fmt.Errorf("marshal detect result: %w", err)
	}

	var resp struct {
		Backend string `json:"backend"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal detect result: %w", err)
	}

	status := &models.FirewallHostStatus{
		Backend: models.FirewallBackend(resp.Backend),
		Version: resp.Version,
	}

	// Count rules
	rules, listErr := s.rules.List(ctx, hostID)
	if listErr == nil {
		for _, r := range rules {
			if r.Enabled {
				status.ActiveRules++
			}
			status.ManagedRules++
		}
	}

	return status, nil
}

// ApplyRules pushes all enabled rules for a host to the agent.
func (s *Service) ApplyRules(ctx context.Context, hostID uuid.UUID, userID *uuid.UUID) error {
	if s.sender == nil {
		return fmt.Errorf("command sender not configured")
	}

	rules, err := s.rules.List(ctx, hostID)
	if err != nil {
		return fmt.Errorf("list rules: %w", err)
	}

	// Filter enabled rules
	type applyRule struct {
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

	var applyRules []applyRule
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		applyRules = append(applyRules, applyRule{
			Chain:         string(r.Chain),
			Protocol:      r.Protocol,
			Source:        r.Source,
			Destination:   r.Destination,
			SrcPort:       r.SrcPort,
			DstPort:       r.DstPort,
			Action:        string(r.Action),
			InterfaceName: r.InterfaceName,
			Comment:       r.Comment,
			Position:      r.Position,
		})
	}

	if len(applyRules) == 0 {
		return nil
	}

	// Detect backend first
	status, detectErr := s.DetectBackend(ctx, hostID)
	backend := "iptables"
	if detectErr == nil && status.Backend != models.FirewallBackendUnknown {
		backend = string(status.Backend)
	}

	payload := struct {
		Backend string      `json:"backend"`
		Rules   []applyRule `json:"rules"`
	}{
		Backend: backend,
		Rules:   applyRules,
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal rules: %w", err)
	}

	cmd := &protocol.Command{
		ID:       uuid.NewString(),
		Type:     protocol.CmdFirewallApply,
		HostID:   hostID.String(),
		Priority: protocol.PriorityHigh,
		Timeout:  2 * time.Minute,
		Params: protocol.CommandParams{
			FirewallRules: string(payloadJSON),
		},
	}

	result, err := s.sender.SendCommand(ctx, hostID, cmd)
	if err != nil {
		return fmt.Errorf("apply rules: %w", err)
	}
	if result.Error != nil {
		return fmt.Errorf("apply rules: %s", result.Error.Message)
	}

	// Mark rules as applied
	if err := s.rules.MarkApplied(ctx, hostID); err != nil {
		s.logger.Error("failed to mark rules as applied", "error", err)
	}

	s.logAudit(ctx, hostID, userID, "apply", nil,
		fmt.Sprintf("Applied %d rules to host", len(applyRules)), "")

	return nil
}

// SyncFromHost reads current firewall state from the host.
func (s *Service) SyncFromHost(ctx context.Context, hostID uuid.UUID, userID *uuid.UUID) (string, error) {
	if s.sender == nil {
		return "", fmt.Errorf("command sender not configured")
	}

	cmd := &protocol.Command{
		ID:       uuid.NewString(),
		Type:     protocol.CmdFirewallSync,
		HostID:   hostID.String(),
		Priority: protocol.PriorityNormal,
		Timeout:  2 * time.Minute,
		Params:   protocol.CommandParams{},
	}

	result, err := s.sender.SendCommand(ctx, hostID, cmd)
	if err != nil {
		return "", fmt.Errorf("sync from host: %w", err)
	}
	if result.Error != nil {
		return "", fmt.Errorf("sync from host: %s", result.Error.Message)
	}

	data, err := json.Marshal(result.Data)
	if err != nil {
		return "", fmt.Errorf("marshal sync result: %w", err)
	}

	var resp struct {
		Output string `json:"output"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", fmt.Errorf("unmarshal sync result: %w", err)
	}

	s.logAudit(ctx, hostID, userID, "sync", nil,
		"Synced firewall state from host", "")

	return resp.Output, nil
}

// ============================================================================
// Audit
// ============================================================================

// ListAuditLogs returns paginated audit logs for a host.
func (s *Service) ListAuditLogs(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]models.FirewallAuditLog, int, error) {
	return s.audit.List(ctx, hostID, limit, offset)
}

func (s *Service) logAudit(ctx context.Context, hostID uuid.UUID, userID *uuid.UUID, action string, ruleID *uuid.UUID, summary, details string) {
	entry := &models.FirewallAuditLog{
		HostID:      hostID,
		UserID:      userID,
		Action:      action,
		RuleID:      ruleID,
		RuleSummary: summary,
		Details:     details,
	}
	if err := s.audit.Create(ctx, entry); err != nil {
		s.logger.Error("failed to create audit log", "error", err)
	}
}
