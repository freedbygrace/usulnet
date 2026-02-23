// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"bufio"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/models"
	swarmtpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/swarm"
)

// SwarmClusterTempl renders the Swarm cluster page.
func (h *Handler) SwarmClusterTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Swarm Cluster", "swarm")

	hostID := h.resolveHostID(r)

	data := swarmtpl.ClusterData{
		PageData: pageData,
		HostID:   hostID.String(),
	}

	// Detect if the active host is an agent node — Swarm ops require the master
	masterHostID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	if hostID != masterHostID {
		host, hostErr := h.services.Hosts().Get(ctx, hostID.String())
		if hostErr == nil && host.EndpointType == "agent" {
			data.IsAgentHost = true
			data.MasterHostID = masterHostID.String()
		}
	}

	if h.swarmService == nil {
		h.renderTempl(w, r, swarmtpl.Cluster(data))
		return
	}

	// Skip Swarm API call for agent nodes — it will always fail
	if data.IsAgentHost {
		h.renderTempl(w, r, swarmtpl.Cluster(data))
		return
	}

	info, err := h.swarmService.GetClusterInfo(ctx, hostID)
	if err != nil {
		h.logger.Warn("Failed to get Swarm info", "error", err)
		h.renderTempl(w, r, swarmtpl.Cluster(data))
		return
	}

	data.Active = info.Active
	data.ClusterID = info.ClusterID
	data.ManagerNodes = info.ManagerNodes
	data.WorkerNodes = info.WorkerNodes
	data.TotalNodes = info.TotalNodes
	data.ServiceCount = info.ServiceCount
	data.JoinTokenWorker = info.JoinTokenWorker
	data.JoinTokenManager = info.JoinTokenManager
	data.ManagerAddr = info.ManagerAddr

	for _, n := range info.Nodes {
		data.Nodes = append(data.Nodes, swarmtpl.NodeItem{
			ID:            n.ID,
			Hostname:      n.Hostname,
			Role:          n.Role,
			Status:        n.Status,
			Availability:  n.Availability,
			EngineVersion: n.EngineVersion,
			Address:       n.Address,
			IsLeader:      n.IsLeader,
			NCPU:          n.NCPU,
			MemoryMB:      n.MemoryBytes / (1024 * 1024),
		})
	}

	// Get services
	services, svcErr := h.swarmService.ListServices(ctx, hostID)
	if svcErr == nil {
		for _, svc := range services {
			portsStr := ""
			for i, p := range svc.Ports {
				if i > 0 {
					portsStr += ", "
				}
				portsStr += fmt.Sprintf("%d:%d/%s", p.PublishedPort, p.TargetPort, p.Protocol)
			}
			data.Services = append(data.Services, swarmtpl.ServiceItem{
				ID:              svc.ID,
				Name:            svc.Name,
				Image:           svc.Image,
				Mode:            svc.Mode,
				ReplicasDesired: svc.ReplicasDesired,
				ReplicasRunning: svc.ReplicasRunning,
				Ports:           portsStr,
			})
		}
	}

	h.renderTempl(w, r, swarmtpl.Cluster(data))
}

// SwarmInitTempl handles POST /swarm/init - initializes Docker Swarm.
func (h *Handler) SwarmInitTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := h.resolveHostID(r)

	if h.swarmService == nil {
		h.setFlash(w, r, "error", "Swarm service not available")
		http.Redirect(w, r, "/swarm", http.StatusSeeOther)
		return
	}

	input := &models.SwarmInitInput{
		AdvertiseAddr: r.FormValue("advertise_addr"),
		ListenAddr:    r.FormValue("listen_addr"),
	}

	_, err := h.swarmService.InitSwarm(ctx, hostID, input)
	if err != nil {
		h.setFlash(w, r, "error", "Failed to initialize Swarm: "+err.Error())
		http.Redirect(w, r, "/swarm", http.StatusSeeOther)
		return
	}

	h.setFlash(w, r, "success", "Swarm cluster initialized successfully")
	http.Redirect(w, r, "/swarm", http.StatusSeeOther)
}

// SwarmLeaveTempl handles POST /swarm/leave - leaves the Swarm cluster.
func (h *Handler) SwarmLeaveTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := h.resolveHostID(r)

	if h.swarmService == nil {
		h.setFlash(w, r, "error", "Swarm service not available")
		http.Redirect(w, r, "/swarm", http.StatusSeeOther)
		return
	}

	if err := h.swarmService.LeaveSwarm(ctx, hostID, true); err != nil {
		h.setFlash(w, r, "error", "Failed to leave Swarm: "+err.Error())
		http.Redirect(w, r, "/swarm", http.StatusSeeOther)
		return
	}

	h.setFlash(w, r, "success", "Left Swarm cluster successfully")
	http.Redirect(w, r, "/swarm", http.StatusSeeOther)
}

// SwarmNodeRemoveTempl handles DELETE /swarm/nodes/{nodeID}.
func (h *Handler) SwarmNodeRemoveTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := h.resolveHostID(r)
	nodeID := chi.URLParam(r, "nodeID")

	if h.swarmService == nil {
		http.Error(w, "Swarm service not available", http.StatusServiceUnavailable)
		return
	}

	if err := h.swarmService.RemoveNode(ctx, hostID, nodeID, true); err != nil {
		h.setFlash(w, r, "error", "Failed to remove node: "+err.Error())
		http.Redirect(w, r, "/swarm", http.StatusSeeOther)
		return
	}

	h.setFlash(w, r, "success", "Node removed from cluster")
	http.Redirect(w, r, "/swarm", http.StatusSeeOther)
}

// SwarmServiceCreateFormTempl renders the create service form.
func (h *Handler) SwarmServiceCreateFormTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Create Swarm Service", "swarm")
	data := swarmtpl.ServiceCreateData{
		PageData: pageData,
	}
	h.renderTempl(w, r, swarmtpl.ServiceCreateForm(data))
}

// SwarmServiceCreateTempl handles POST /swarm/services/create.
func (h *Handler) SwarmServiceCreateTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := h.resolveHostID(r)

	if h.swarmService == nil {
		h.setFlash(w, r, "error", "Swarm service not available")
		http.Redirect(w, r, "/swarm", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		http.Redirect(w, r, "/swarm/services/new", http.StatusSeeOther)
		return
	}

	replicas, _ := strconv.Atoi(r.FormValue("replicas"))
	if replicas < 1 {
		replicas = 1
	}

	input := &models.CreateSwarmServiceInput{
		Name:     r.FormValue("name"),
		Image:    r.FormValue("image"),
		Replicas: replicas,
	}

	// Parse ports
	publishedPort, _ := strconv.ParseUint(r.FormValue("published_port"), 10, 32)
	targetPort, _ := strconv.ParseUint(r.FormValue("target_port"), 10, 32)
	if publishedPort > 0 && targetPort > 0 {
		input.Ports = []models.SwarmPort{{
			Protocol:      "tcp",
			TargetPort:    uint32(targetPort),
			PublishedPort: uint32(publishedPort),
			PublishMode:   "ingress",
		}}
	}

	// Parse env
	envStr := strings.TrimSpace(r.FormValue("env"))
	if envStr != "" {
		for _, line := range strings.Split(envStr, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && strings.Contains(line, "=") {
				input.Env = append(input.Env, line)
			}
		}
	}

	_, err := h.swarmService.CreateService(ctx, hostID, input)
	if err != nil {
		h.setFlash(w, r, "error", "Failed to create service: "+err.Error())
		http.Redirect(w, r, "/swarm/services/new", http.StatusSeeOther)
		return
	}

	h.setFlash(w, r, "success", fmt.Sprintf("Service '%s' created with %d replicas", input.Name, replicas))
	http.Redirect(w, r, "/swarm", http.StatusSeeOther)
}

// SwarmServiceRemoveTempl handles DELETE /swarm/services/{serviceID}.
func (h *Handler) SwarmServiceRemoveTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := h.resolveHostID(r)
	serviceID := chi.URLParam(r, "serviceID")

	if h.swarmService == nil {
		http.Error(w, "Swarm service not available", http.StatusServiceUnavailable)
		return
	}

	if err := h.swarmService.RemoveService(ctx, hostID, serviceID); err != nil {
		h.setFlash(w, r, "error", "Failed to remove service: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Service removed")
	}

	http.Redirect(w, r, "/swarm", http.StatusSeeOther)
}

// SwarmServiceScaleTempl handles POST /swarm/services/{serviceID}/scale.
func (h *Handler) SwarmServiceScaleTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := h.resolveHostID(r)
	serviceID := chi.URLParam(r, "serviceID")

	if h.swarmService == nil {
		http.Error(w, "Swarm service not available", http.StatusServiceUnavailable)
		return
	}

	replicas, _ := strconv.Atoi(r.FormValue("replicas"))
	if replicas < 0 {
		replicas = 0
	}

	if err := h.swarmService.ScaleService(ctx, hostID, serviceID, replicas); err != nil {
		h.setFlash(w, r, "error", "Failed to scale service: "+err.Error())
	} else {
		h.setFlash(w, r, "success", fmt.Sprintf("Service scaled to %d replicas", replicas))
	}

	http.Redirect(w, r, "/swarm", http.StatusSeeOther)
}

// SwarmConvertContainerTempl handles POST /swarm/convert - converts container to HA service.
func (h *Handler) SwarmConvertContainerTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := h.resolveHostID(r)

	if h.swarmService == nil {
		h.setFlash(w, r, "error", "Swarm service not available")
		http.Redirect(w, r, "/swarm", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		http.Redirect(w, r, "/swarm", http.StatusSeeOther)
		return
	}

	replicas, _ := strconv.Atoi(r.FormValue("replicas"))
	if replicas < 1 {
		replicas = 2
	}

	input := &models.ConvertToServiceInput{
		ContainerID: r.FormValue("container_id"),
		Replicas:    replicas,
		ServiceName: r.FormValue("service_name"),
	}

	_, err := h.swarmService.ConvertContainerToService(ctx, hostID, input)
	if err != nil {
		h.setFlash(w, r, "error", "Failed to convert container: "+err.Error())
		http.Redirect(w, r, "/containers", http.StatusSeeOther)
		return
	}

	h.setFlash(w, r, "success", fmt.Sprintf("Container converted to Swarm service with %d replicas", replicas))
	http.Redirect(w, r, "/swarm", http.StatusSeeOther)
}

// SwarmNodeUpdateTempl handles POST /swarm/nodes/{nodeID}/update — promote/demote/drain.
func (h *Handler) SwarmNodeUpdateTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := h.resolveHostID(r)
	nodeID := chi.URLParam(r, "nodeID")

	if h.swarmService == nil {
		h.setFlash(w, r, "error", "Swarm service not available")
		http.Redirect(w, r, "/swarm", http.StatusSeeOther)
		return
	}

	role := r.FormValue("role")                 // "manager", "worker", or ""
	availability := r.FormValue("availability") // "active", "drain", "pause", or ""

	if role == "" && availability == "" {
		h.setFlash(w, r, "error", "No changes specified")
		http.Redirect(w, r, "/swarm", http.StatusSeeOther)
		return
	}

	if err := h.swarmService.UpdateNode(ctx, hostID, nodeID, role, availability); err != nil {
		h.setFlash(w, r, "error", "Failed to update node: "+err.Error())
	} else {
		action := "updated"
		if role == "manager" {
			action = "promoted to manager"
		} else if role == "worker" {
			action = "demoted to worker"
		} else if availability == "drain" {
			action = "set to drain"
		} else if availability == "active" {
			action = "set to active"
		} else if availability == "pause" {
			action = "paused"
		}
		h.setFlash(w, r, "success", fmt.Sprintf("Node %s", action))
	}

	http.Redirect(w, r, "/swarm", http.StatusSeeOther)
}

// SwarmJoinTempl handles POST /swarm/join — joins this host to an existing cluster.
func (h *Handler) SwarmJoinTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := h.resolveHostID(r)

	if h.swarmService == nil {
		h.setFlash(w, r, "error", "Swarm service not available")
		http.Redirect(w, r, "/swarm", http.StatusSeeOther)
		return
	}

	input := &models.SwarmJoinInput{
		RemoteAddr: strings.TrimSpace(r.FormValue("remote_addr")),
		JoinToken:  strings.TrimSpace(r.FormValue("join_token")),
		ListenAddr: strings.TrimSpace(r.FormValue("listen_addr")),
	}

	if input.RemoteAddr == "" || input.JoinToken == "" {
		h.setFlash(w, r, "error", "Manager address and join token are required")
		http.Redirect(w, r, "/swarm", http.StatusSeeOther)
		return
	}

	if err := h.swarmService.JoinSwarm(ctx, hostID, input); err != nil {
		h.setFlash(w, r, "error", "Failed to join Swarm: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Successfully joined Swarm cluster")
	}

	http.Redirect(w, r, "/swarm", http.StatusSeeOther)
}

// SwarmServiceDetailTempl renders the service detail page.
func (h *Handler) SwarmServiceDetailTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := h.resolveHostID(r)
	serviceID := chi.URLParam(r, "serviceID")

	pageData := h.prepareTemplPageData(r, "Service Detail", "swarm")

	if h.swarmService == nil {
		h.setFlash(w, r, "error", "Swarm service not available")
		http.Redirect(w, r, "/swarm", http.StatusSeeOther)
		return
	}

	svc, err := h.swarmService.GetService(ctx, hostID, serviceID)
	if err != nil {
		h.setFlash(w, r, "error", "Service not found: "+err.Error())
		http.Redirect(w, r, "/swarm", http.StatusSeeOther)
		return
	}

	tasks, _ := h.swarmService.ListTasks(ctx, hostID, serviceID)

	data := swarmtpl.ServiceDetailData{
		PageData:  pageData,
		Service:   *svc,
		Tasks:     tasks,
		ServiceID: serviceID,
	}

	h.renderTempl(w, r, swarmtpl.ServiceDetail(data))
}

// SwarmServiceUpdateTempl handles POST /swarm/services/{serviceID}/update.
func (h *Handler) SwarmServiceUpdateTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := h.resolveHostID(r)
	serviceID := chi.URLParam(r, "serviceID")

	if h.swarmService == nil {
		h.setFlash(w, r, "error", "Swarm service not available")
		http.Redirect(w, r, "/swarm/services/"+serviceID, http.StatusSeeOther)
		return
	}

	opts := docker.SwarmServiceUpdateOptions{}

	if img := strings.TrimSpace(r.FormValue("image")); img != "" {
		opts.Image = &img
	}

	if replicasStr := r.FormValue("replicas"); replicasStr != "" {
		if replicas, err := strconv.ParseUint(replicasStr, 10, 64); err == nil {
			opts.Replicas = &replicas
		}
	}

	if envStr := strings.TrimSpace(r.FormValue("env")); envStr != "" {
		for _, line := range strings.Split(envStr, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && strings.Contains(line, "=") {
				opts.Env = append(opts.Env, line)
			}
		}
	}

	if err := h.swarmService.UpdateService(ctx, hostID, serviceID, opts); err != nil {
		h.setFlash(w, r, "error", "Failed to update service: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Service updated successfully")
	}

	http.Redirect(w, r, "/swarm/services/"+serviceID, http.StatusSeeOther)
}

// SwarmServiceRollbackTempl handles POST /swarm/services/{serviceID}/rollback.
func (h *Handler) SwarmServiceRollbackTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := h.resolveHostID(r)
	serviceID := chi.URLParam(r, "serviceID")

	if h.swarmService == nil {
		h.setFlash(w, r, "error", "Swarm service not available")
		http.Redirect(w, r, "/swarm/services/"+serviceID, http.StatusSeeOther)
		return
	}

	if err := h.swarmService.RollbackService(ctx, hostID, serviceID); err != nil {
		h.setFlash(w, r, "error", "Failed to rollback service: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Service rolled back to previous version")
	}

	http.Redirect(w, r, "/swarm/services/"+serviceID, http.StatusSeeOther)
}

// SwarmServiceLogsTempl streams service logs as plain text.
func (h *Handler) SwarmServiceLogsTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := h.resolveHostID(r)
	serviceID := chi.URLParam(r, "serviceID")

	if h.swarmService == nil {
		http.Error(w, "Swarm service not available", http.StatusServiceUnavailable)
		return
	}

	tail := r.URL.Query().Get("tail")
	if tail == "" {
		tail = "100"
	}

	reader, err := h.swarmService.ServiceLogs(ctx, hostID, serviceID, tail, false)
	if err != nil {
		http.Error(w, "Failed to get logs: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer reader.Close()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Bytes()
		// Docker multiplexed logs have 8-byte header; strip it if present
		if len(line) > 8 {
			line = line[8:]
		}
		w.Write(line)
		w.Write([]byte("\n"))
	}
}

// resolveHostID gets the current active host UUID from context or query parameter.
func (h *Handler) resolveHostID(r *http.Request) uuid.UUID {
	// First check explicit query parameter
	if hostIDStr := r.URL.Query().Get("host_id"); hostIDStr != "" {
		if id, err := uuid.Parse(hostIDStr); err == nil {
			return id
		}
	}

	// Check session-based active host (set by host selector in the UI)
	if activeHostID := GetActiveHostIDFromContext(r.Context()); activeHostID != "" {
		if id, err := uuid.Parse(activeHostID); err == nil {
			return id
		}
	}

	// Default to local host sentinel
	return uuid.MustParse("00000000-0000-0000-0000-000000000001")
}
