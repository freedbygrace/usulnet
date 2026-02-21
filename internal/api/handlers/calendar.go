// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/calendar"
)

// CalendarHandler handles calendar API requests.
type CalendarHandler struct {
	BaseHandler
	calendarService *calendar.Service
}

// NewCalendarHandler creates a new calendar handler.
func NewCalendarHandler(calendarService *calendar.Service, log *logger.Logger) *CalendarHandler {
	return &CalendarHandler{
		BaseHandler:     NewBaseHandler(log),
		calendarService: calendarService,
	}
}

// Routes registers calendar API routes.
func (h *CalendarHandler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.RequireAuth)

	// Events
	r.Route("/events", func(r chi.Router) {
		r.Get("/", h.ListEvents)
		r.Post("/", h.CreateEvent)
		r.Put("/{id}", h.UpdateEvent)
		r.Delete("/{id}", h.DeleteEvent)
	})

	// Tasks
	r.Route("/tasks", func(r chi.Router) {
		r.Get("/", h.ListTasks)
		r.Post("/", h.CreateTask)
		r.Put("/{id}", h.UpdateTask)
		r.Patch("/{id}/toggle", h.ToggleTask)
		r.Delete("/{id}", h.DeleteTask)
	})

	// Notes
	r.Route("/notes", func(r chi.Router) {
		r.Get("/", h.ListNotes)
		r.Post("/", h.CreateNote)
		r.Put("/{id}", h.UpdateNote)
		r.Delete("/{id}", h.DeleteNote)
	})

	// Checklists
	r.Route("/checklists", func(r chi.Router) {
		r.Get("/", h.ListChecklists)
		r.Post("/", h.CreateChecklist)
		r.Put("/{id}", h.UpdateChecklist)
		r.Delete("/{id}", h.DeleteChecklist)
	})

	return r
}

// ============================================================================
// Event Handlers
// ============================================================================

// ListEvents returns events for a given year/month.
func (h *CalendarHandler) ListEvents(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	year := h.QueryParamInt(r, "year", 0)
	month := h.QueryParamInt(r, "month", 0)
	if year == 0 || month == 0 {
		h.BadRequest(w, "year and month query parameters are required")
		return
	}

	events, err := h.calendarService.ListEventsByMonth(r.Context(), userID, year, month)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if events == nil {
		events = []*models.CalendarEvent{}
	}
	h.OK(w, events)
}

// createEventRequest represents the request body for creating an event.
type createEventRequest struct {
	Title       string     `json:"title" validate:"required,min=1,max=255"`
	Description string     `json:"description" validate:"max=4096"`
	EventDate   string     `json:"event_date" validate:"required"`
	EventTime   string     `json:"event_time"`
	Color       string     `json:"color" validate:"omitempty,max=20"`
	IsShared    bool       `json:"is_shared"`
	TeamID      *uuid.UUID `json:"team_id" validate:"omitempty"`
}

// CreateEvent creates a new calendar event.
func (h *CalendarHandler) CreateEvent(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req createEventRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	ev := &models.CalendarEvent{
		UserID:      userID,
		TeamID:      req.TeamID,
		Title:       req.Title,
		Description: req.Description,
		EventDate:   req.EventDate,
		EventTime:   req.EventTime,
		Color:       req.Color,
		IsShared:    req.IsShared,
	}

	if err := h.calendarService.CreateEvent(r.Context(), ev); err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, ev)
}

// updateEventRequest represents the request body for updating an event.
type updateEventRequest struct {
	Title       string     `json:"title" validate:"required,min=1,max=255"`
	Description string     `json:"description" validate:"max=4096"`
	EventDate   string     `json:"event_date" validate:"required"`
	EventTime   string     `json:"event_time"`
	Color       string     `json:"color" validate:"omitempty,max=20"`
	IsShared    bool       `json:"is_shared"`
	TeamID      *uuid.UUID `json:"team_id" validate:"omitempty"`
}

// UpdateEvent updates a calendar event.
func (h *CalendarHandler) UpdateEvent(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req updateEventRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	ev := &models.CalendarEvent{
		ID:          id,
		UserID:      userID,
		TeamID:      req.TeamID,
		Title:       req.Title,
		Description: req.Description,
		EventDate:   req.EventDate,
		EventTime:   req.EventTime,
		Color:       req.Color,
		IsShared:    req.IsShared,
	}

	if err := h.calendarService.UpdateEvent(r.Context(), ev); err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, ev)
}

// DeleteEvent deletes a calendar event.
func (h *CalendarHandler) DeleteEvent(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.calendarService.DeleteEvent(r.Context(), id, userID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// ============================================================================
// Task Handlers
// ============================================================================

// ListTasks returns tasks with optional filter.
func (h *CalendarHandler) ListTasks(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	filter := h.QueryParam(r, "filter")
	if filter == "" {
		filter = "all"
	}

	tasks, err := h.calendarService.ListTasks(r.Context(), userID, filter)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if tasks == nil {
		tasks = []*models.CalendarTask{}
	}
	h.OK(w, tasks)
}

// createTaskRequest represents the request body for creating a task.
type createTaskRequest struct {
	Text     string     `json:"text" validate:"required,min=1,max=1024"`
	Priority string     `json:"priority" validate:"omitempty,oneof=low normal medium high urgent"`
	DueDate  *string    `json:"due_date"`
	IsShared bool       `json:"is_shared"`
	TeamID   *uuid.UUID `json:"team_id" validate:"omitempty"`
}

// CreateTask creates a new calendar task.
func (h *CalendarHandler) CreateTask(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req createTaskRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	t := &models.CalendarTask{
		UserID:   userID,
		TeamID:   req.TeamID,
		Text:     req.Text,
		Priority: req.Priority,
		DueDate:  req.DueDate,
		IsShared: req.IsShared,
	}

	if err := h.calendarService.CreateTask(r.Context(), t); err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, t)
}

// updateTaskRequest represents the request body for updating a task.
type updateTaskRequest struct {
	Text     string     `json:"text" validate:"required,min=1,max=1024"`
	Priority string     `json:"priority" validate:"omitempty,oneof=low normal medium high urgent"`
	DueDate  *string    `json:"due_date"`
	Done     bool       `json:"done"`
	IsShared bool       `json:"is_shared"`
	TeamID   *uuid.UUID `json:"team_id" validate:"omitempty"`
}

// UpdateTask updates a calendar task.
func (h *CalendarHandler) UpdateTask(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req updateTaskRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	t := &models.CalendarTask{
		ID:       id,
		UserID:   userID,
		TeamID:   req.TeamID,
		Text:     req.Text,
		Priority: req.Priority,
		DueDate:  req.DueDate,
		Done:     req.Done,
		IsShared: req.IsShared,
	}

	if err := h.calendarService.UpdateTask(r.Context(), t); err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, t)
}

// ToggleTask toggles the done status of a task.
func (h *CalendarHandler) ToggleTask(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.calendarService.ToggleTask(r.Context(), id, userID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// DeleteTask deletes a calendar task.
func (h *CalendarHandler) DeleteTask(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.calendarService.DeleteTask(r.Context(), id, userID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// ============================================================================
// Note Handlers
// ============================================================================

// ListNotes returns notes for the current user.
func (h *CalendarHandler) ListNotes(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	notes, err := h.calendarService.ListNotes(r.Context(), userID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if notes == nil {
		notes = []*models.CalendarNote{}
	}
	h.OK(w, notes)
}

// createNoteRequest represents the request body for creating a note.
type createNoteRequest struct {
	Title    string     `json:"title" validate:"required,min=1,max=255"`
	Content  string     `json:"content" validate:"max=65536"`
	IsShared bool       `json:"is_shared"`
	TeamID   *uuid.UUID `json:"team_id" validate:"omitempty"`
}

// CreateNote creates a new calendar note.
func (h *CalendarHandler) CreateNote(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req createNoteRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	n := &models.CalendarNote{
		UserID:   userID,
		TeamID:   req.TeamID,
		Title:    req.Title,
		Content:  req.Content,
		IsShared: req.IsShared,
	}

	if err := h.calendarService.CreateNote(r.Context(), n); err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, n)
}

// updateNoteRequest represents the request body for updating a note.
type updateNoteRequest struct {
	Title    string     `json:"title" validate:"required,min=1,max=255"`
	Content  string     `json:"content" validate:"max=65536"`
	IsShared bool       `json:"is_shared"`
	TeamID   *uuid.UUID `json:"team_id" validate:"omitempty"`
}

// UpdateNote updates a calendar note.
func (h *CalendarHandler) UpdateNote(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req updateNoteRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	n := &models.CalendarNote{
		ID:       id,
		UserID:   userID,
		TeamID:   req.TeamID,
		Title:    req.Title,
		Content:  req.Content,
		IsShared: req.IsShared,
	}

	if err := h.calendarService.UpdateNote(r.Context(), n); err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, n)
}

// DeleteNote deletes a calendar note.
func (h *CalendarHandler) DeleteNote(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.calendarService.DeleteNote(r.Context(), id, userID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// ============================================================================
// Checklist Handlers
// ============================================================================

// ListChecklists returns checklists for the current user.
func (h *CalendarHandler) ListChecklists(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	checklists, err := h.calendarService.ListChecklists(r.Context(), userID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if checklists == nil {
		checklists = []*models.CalendarChecklist{}
	}
	h.OK(w, checklists)
}

// createChecklistRequest represents the request body for creating a checklist.
type createChecklistRequest struct {
	Title    string          `json:"title" validate:"required,min=1,max=255"`
	Items    json.RawMessage `json:"items" validate:"required"`
	IsShared bool            `json:"is_shared"`
	TeamID   *uuid.UUID      `json:"team_id" validate:"omitempty"`
}

// CreateChecklist creates a new calendar checklist.
func (h *CalendarHandler) CreateChecklist(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req createChecklistRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	cl := &models.CalendarChecklist{
		UserID:   userID,
		TeamID:   req.TeamID,
		Title:    req.Title,
		Items:    req.Items,
		IsShared: req.IsShared,
	}

	if err := h.calendarService.CreateChecklist(r.Context(), cl); err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, cl)
}

// updateChecklistRequest represents the request body for updating a checklist.
type updateChecklistRequest struct {
	Title    string          `json:"title" validate:"required,min=1,max=255"`
	Items    json.RawMessage `json:"items" validate:"required"`
	IsShared bool            `json:"is_shared"`
	TeamID   *uuid.UUID      `json:"team_id" validate:"omitempty"`
}

// UpdateChecklist updates a calendar checklist.
func (h *CalendarHandler) UpdateChecklist(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req updateChecklistRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	cl := &models.CalendarChecklist{
		ID:       id,
		UserID:   userID,
		TeamID:   req.TeamID,
		Title:    req.Title,
		Items:    req.Items,
		IsShared: req.IsShared,
	}

	if err := h.calendarService.UpdateChecklist(r.Context(), cl); err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, cl)
}

// DeleteChecklist deletes a calendar checklist.
func (h *CalendarHandler) DeleteChecklist(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.calendarService.DeleteChecklist(r.Context(), id, userID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}
