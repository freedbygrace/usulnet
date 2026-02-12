// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	vulntmpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/vulnmgmt"
)

// VulnMgmtTempl renders the vulnerability management page.
func (h *Handler) VulnMgmtTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Vulnerability Management", "vulnerabilities")

	// Build container risk data from current state
	var containerRisk []vulntmpl.VulnContainerView
	containerSvc := h.services.Containers()
	if containerSvc != nil {
		if containers, err := containerSvc.List(ctx, nil); err == nil {
			for _, c := range containers {
				if c.SecurityScore > 0 || c.SecurityGrade != "" {
					risk := "low"
					if c.SecurityScore < 30 {
						risk = "critical"
					} else if c.SecurityScore < 50 {
						risk = "high"
					} else if c.SecurityScore < 70 {
						risk = "medium"
					}
					containerRisk = append(containerRisk, vulntmpl.VulnContainerView{
						ContainerID:   c.ID,
						ContainerName: c.Name,
						Image:         c.Image,
						RiskScore:     risk,
					})
				}
			}
		}
	}

	// Build vulnerability views and stats
	var vulns []vulntmpl.VulnerabilityView
	stats := vulntmpl.VulnStats{}
	now := time.Now()

	if h.trackedVulnRepo != nil {
		dbVulns, err := h.trackedVulnRepo.List(ctx)
		if err == nil {
			for _, v := range dbVulns {
				vv := vulntmpl.VulnerabilityView{
					ID:             v.ID.String(),
					CVEID:          v.CVEID,
					Title:          v.Title,
					Description:    v.Description,
					Severity:       v.Severity,
					CVSSScore:      v.CVSSScore,
					Package:        v.Package,
					InstalledVer:   v.InstalledVer,
					FixedVer:       v.FixedVer,
					AffectedImages: v.AffectedImages,
					ContainerCount: v.ContainerCount,
					Status:         v.Status,
					Priority:       v.Priority,
					Assignee:       v.Assignee,
					Notes:          v.Notes,
					DetectedAt:     v.DetectedAt.Format("Jan 02 15:04"),
				}
				if v.SLADeadline != nil {
					vv.SLADeadline = v.SLADeadline.Format("Jan 02 2006")
					if now.After(*v.SLADeadline) && v.Status != "resolved" && v.Status != "accepted_risk" {
						vv.SLABreached = true
						stats.SLABreached++
					}
				}
				if v.ResolvedAt != nil {
					vv.ResolvedAt = v.ResolvedAt.Format("Jan 02 15:04")
					if now.Sub(*v.ResolvedAt) < 7*24*time.Hour {
						stats.ResolvedThisWeek++
					}
				}
				vulns = append(vulns, vv)
				stats.TotalVulns++
				switch v.Severity {
				case "critical":
					stats.CriticalVulns++
				case "high":
					stats.HighVulns++
				case "medium":
					stats.MediumVulns++
				case "low":
					stats.LowVulns++
				}
			}
		}
	}

	if stats.ResolvedThisWeek > 0 {
		stats.MeanTimeToFix = "< 7d"
	} else {
		stats.MeanTimeToFix = "N/A"
	}

	// Populate vulnerability counts on containers from tracked vulns
	for i := range containerRisk {
		for _, v := range vulns {
			for _, img := range v.AffectedImages {
				if strings.Contains(containerRisk[i].Image, img) {
					switch v.Severity {
					case "critical":
						containerRisk[i].CriticalCount++
					case "high":
						containerRisk[i].HighCount++
					case "medium":
						containerRisk[i].MediumCount++
					case "low":
						containerRisk[i].LowCount++
					}
					containerRisk[i].TotalCount++
				}
			}
		}
	}

	data := vulntmpl.VulnMgmtData{
		PageData:        pageData,
		Vulnerabilities: vulns,
		Containers:      containerRisk,
		Stats:           stats,
		ActiveTab:       r.URL.Query().Get("tab"),
	}

	h.renderTempl(w, r, vulntmpl.VulnManagement(data))
}

// VulnScan triggers a vulnerability scan using the existing security service.
func (h *Handler) VulnScan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	secSvc := h.services.Security()
	if secSvc == nil {
		h.setFlash(w, r, "error", "Security service unavailable")
		http.Redirect(w, r, "/vulnerabilities", http.StatusSeeOther)
		return
	}

	// Trigger scan on all containers
	if err := secSvc.ScanAll(ctx); err != nil {
		h.setFlash(w, r, "error", "Scan failed: "+err.Error())
		http.Redirect(w, r, "/vulnerabilities", http.StatusSeeOther)
		return
	}

	// Get issues from the security service and import as tracked vulns
	issues, err := secSvc.ListIssues(ctx)
	if err == nil && h.trackedVulnRepo != nil {
		imported := 0
		for _, issue := range issues {
			if issue.CVEID == "" {
				continue
			}
			// Check if this CVE is already tracked
			exists, _ := h.trackedVulnRepo.ExistsByCVE(ctx, issue.CVEID)
			if !exists {
				sla := vulnSLADays(issue.Severity)
				deadline := time.Now().Add(time.Duration(sla) * 24 * time.Hour)
				priority := vulnPriorityFromSeverity(issue.Severity)
				v := &TrackedVulnRecord{
					ID:          uuid.New(),
					CVEID:       issue.CVEID,
					Title:       issue.Title,
					Description: issue.Message,
					Severity:    issue.Severity,
					CVSSScore:   fmt.Sprintf("%.1f", issue.CVSSScore),
					Status:      "open",
					Priority:    priority,
					SLADeadline: &deadline,
					DetectedAt:  time.Now(),
				}
				if err := h.trackedVulnRepo.Create(ctx, v); err == nil {
					imported++
				}
			}
		}

		h.setFlash(w, r, "success", fmt.Sprintf("Vulnerability scan complete: %d new CVEs imported", imported))
	} else if err != nil {
		h.setFlash(w, r, "warning", "Scan triggered but failed to import results: "+err.Error())
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/vulnerabilities")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/vulnerabilities", http.StatusSeeOther)
}

// VulnAcknowledge starts working on a vulnerability.
func (h *Handler) VulnAcknowledge(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	h.updateTrackedVulnStatus(r, id, "in_progress")
	h.setFlash(w, r, "success", "Vulnerability marked as in progress")
	redirectVulns(w, r)
}

// VulnResolve marks a vulnerability as resolved.
func (h *Handler) VulnResolve(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	h.updateTrackedVulnStatus(r, id, "resolved")
	h.setFlash(w, r, "success", "Vulnerability marked as resolved")
	redirectVulns(w, r)
}

// VulnAcceptRisk marks a vulnerability as accepted risk.
func (h *Handler) VulnAcceptRisk(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	h.updateTrackedVulnStatus(r, id, "accepted_risk")
	h.setFlash(w, r, "success", "Risk accepted for vulnerability")
	redirectVulns(w, r)
}

func (h *Handler) updateTrackedVulnStatus(r *http.Request, id, status string) {
	if h.trackedVulnRepo != nil {
		uid, err := uuid.Parse(id)
		if err == nil {
			h.trackedVulnRepo.UpdateStatus(r.Context(), uid, status)
		}
	}
}

func redirectVulns(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/vulnerabilities")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/vulnerabilities", http.StatusSeeOther)
}

// vulnSLADays returns SLA deadline in days based on severity.
func vulnSLADays(severity string) int {
	switch severity {
	case "critical":
		return 7
	case "high":
		return 30
	case "medium":
		return 90
	case "low":
		return 180
	default:
		return 90
	}
}

// vulnPriorityFromSeverity maps severity to priority.
func vulnPriorityFromSeverity(severity string) string {
	switch severity {
	case "critical":
		return "p0"
	case "high":
		return "p1"
	case "medium":
		return "p2"
	default:
		return "p3"
	}
}
