// Package api implements the HTTP handler layer for the Cyber Audit Tool.
// It follows the standard library net/http handler pattern (no third-party router).
package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/emgogalileo/cyber-security-audit-tool/internal/audit"
)

// Handler wires together the store and analyzer and exposes HTTP handlers.
type Handler struct {
	store    audit.Store
	analyzer *audit.Analyzer
}

// NewHandler constructs a Handler with its dependencies.
func NewHandler(store audit.Store, analyzer *audit.Analyzer) *Handler {
	return &Handler{store: store, analyzer: analyzer}
}

// RegisterRoutes attaches all routes to the given ServeMux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/health", h.handleHealth)
	mux.HandleFunc("/api/events", h.handleEvents)
	mux.HandleFunc("/api/threats", h.handleThreats)
	mux.HandleFunc("/api/report", h.handleReport)
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// GET /api/health
func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	respond(w, http.StatusOK, map[string]string{
		"status":    "ok",
		"service":   "cyber-security-audit-tool",
		"version":   "1.0.0",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// GET  /api/events  → list all events
// POST /api/events  → ingest a new security event
func (h *Handler) handleEvents(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		events := h.store.ListAll()
		respond(w, http.StatusOK, map[string]any{
			"total":  len(events),
			"events": events,
		})

	case http.MethodPost:
		var event audit.SecurityEvent
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
			return
		}
		if event.SourceIP == "" {
			respondError(w, http.StatusBadRequest, "'source_ip' is required.")
			return
		}
		// Auto-fill server-side fields
		event.ID = uuid.New().String()
		event.Timestamp = time.Now().UTC()
		if event.Severity == "" {
			event.Severity = audit.SeverityInfo
		}

		h.store.Save(event)
		log.Printf("[EVENT] %s from %s — %s", event.Type, event.SourceIP, event.Severity)
		respond(w, http.StatusCreated, event)

	default:
		methodNotAllowed(w)
	}
}

// GET /api/threats — run threat analysis and return active alerts
func (h *Handler) handleThreats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	threats := h.analyzer.DetectThreats()
	respond(w, http.StatusOK, map[string]any{
		"total":   len(threats),
		"threats": threats,
	})
}

// GET /api/report — full audit report
func (h *Handler) handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	report := h.analyzer.BuildReport()
	respond(w, http.StatusOK, report)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func respond(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("[ERROR] json encode: %v", err)
	}
}

func respondError(w http.ResponseWriter, status int, msg string) {
	respond(w, status, map[string]string{"error": msg})
}

func methodNotAllowed(w http.ResponseWriter) {
	respondError(w, http.StatusMethodNotAllowed, fmt.Sprintf("Method not allowed."))
}
