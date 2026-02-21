// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package workers

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// TrackedVulnRepository is the subset of the vuln repo the SLA worker needs.
type TrackedVulnRepository interface {
	ListSLABreached(ctx context.Context) ([]*models.TrackedVulnRecord, error)
}

// SLABreachWorker checks for vulnerabilities that have exceeded their SLA
// deadline and dispatches notifications to assignees and admins.
type SLABreachWorker struct {
	BaseWorker
	vulnRepo            TrackedVulnRepository
	notificationService NotificationService
	logger              *logger.Logger
}

// NewSLABreachWorker creates a new SLA breach detection worker.
func NewSLABreachWorker(
	vulnRepo TrackedVulnRepository,
	notificationService NotificationService,
	log *logger.Logger,
) *SLABreachWorker {
	if log == nil {
		log = logger.Nop()
	}
	return &SLABreachWorker{
		BaseWorker:          NewBaseWorker(models.JobTypeSLABreach),
		vulnRepo:            vulnRepo,
		notificationService: notificationService,
		logger:              log.Named("sla-breach-worker"),
	}
}

// Execute finds breached-SLA vulnerabilities and sends notifications.
func (w *SLABreachWorker) Execute(ctx context.Context, job *models.Job) (interface{}, error) {
	log := w.logger.With("job_id", job.ID)
	log.Info("checking SLA breaches")

	breached, err := w.vulnRepo.ListSLABreached(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing SLA-breached vulns: %w", err)
	}

	if len(breached) == 0 {
		log.Info("no SLA breaches found")
		return &SLABreachResult{Checked: true}, nil
	}

	result := &SLABreachResult{
		Checked:       true,
		BreachedCount: len(breached),
		StartedAt:     time.Now(),
		Notified:      make([]SLABreachItem, 0, len(breached)),
	}

	// Group by severity for the summary notification
	bySeverity := make(map[string]int)
	for _, v := range breached {
		bySeverity[v.Severity]++
	}

	// Build summary message
	summaryMsg := fmt.Sprintf("SLA Breach Alert: %d vulnerabilities have exceeded their remediation deadline.\n", len(breached))
	for sev, count := range bySeverity {
		summaryMsg += fmt.Sprintf("  - %s: %d\n", sev, count)
	}

	// Send summary notification to admins via configured channels
	if w.notificationService != nil {
		notification := &Notification{
			ID:       uuid.New(),
			Channel:  "slack",
			Subject:  fmt.Sprintf("[SLA Breach] %d vulnerabilities overdue", len(breached)),
			Message:  summaryMsg,
			Priority: "critical",
			Data: map[string]interface{}{
				"alert_type":     "sla_breach",
				"breached_count": len(breached),
				"by_severity":    bySeverity,
			},
			CreatedAt: time.Now(),
		}

		if err := w.notificationService.Send(ctx, notification); err != nil {
			log.Warn("failed to send SLA breach summary notification", "error", err)
			result.Errors = append(result.Errors, "summary: "+err.Error())
		} else {
			result.SummaryNotified = true
		}
	}

	// Record per-vulnerability breach details
	for _, v := range breached {
		item := SLABreachItem{
			VulnID:   v.ID,
			CVEID:    v.CVEID,
			Severity: v.Severity,
			Assignee: v.Assignee,
		}
		if v.SLADeadline != nil {
			item.Deadline = *v.SLADeadline
			item.OverdueDays = int(time.Since(*v.SLADeadline).Hours() / 24)
		}
		result.Notified = append(result.Notified, item)
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(result.StartedAt)

	log.Info("SLA breach check completed",
		"breached", result.BreachedCount,
		"duration", result.Duration,
	)

	return result, nil
}

// SLABreachResult holds the outcome of an SLA breach check.
type SLABreachResult struct {
	Checked         bool            `json:"checked"`
	BreachedCount   int             `json:"breached_count"`
	SummaryNotified bool            `json:"summary_notified"`
	Notified        []SLABreachItem `json:"notified,omitempty"`
	StartedAt       time.Time       `json:"started_at"`
	CompletedAt     time.Time       `json:"completed_at"`
	Duration        time.Duration   `json:"duration"`
	Errors          []string        `json:"errors,omitempty"`
}

// SLABreachItem represents a single breached vulnerability.
type SLABreachItem struct {
	VulnID      uuid.UUID `json:"vuln_id"`
	CVEID       string    `json:"cve_id"`
	Severity    string    `json:"severity"`
	Assignee    string    `json:"assignee"`
	Deadline    time.Time `json:"deadline"`
	OverdueDays int       `json:"overdue_days"`
}
