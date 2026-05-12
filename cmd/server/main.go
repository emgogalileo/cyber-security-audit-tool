// Package main — Cyber Security Audit Tool
//
// A lightweight HTTP server written in Go that:
//   - Collects structured security events (log entries)
//   - Analyses them to detect potential threats (brute force, port scans)
//   - Exposes a REST API to query audit results
//
// Run:
//
//	go run ./cmd/server
//
// Build:
//
//	go build -o bin/cyber-audit ./cmd/server
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/emgogalileo/cyber-security-audit-tool/internal/api"
	"github.com/emgogalileo/cyber-security-audit-tool/internal/audit"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9000"
	}

	// Dependency wiring (manual DI — no frameworks needed for this scope)
	store := audit.NewInMemoryStore()
	analyzer := audit.NewAnalyzer(store)
	handler := api.NewHandler(store, analyzer)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	addr := ":" + port
	log.Printf("🛡️  Cyber Security Audit Tool listening on http://localhost%s", addr)
	log.Printf("   Routes:")
	log.Printf("     GET  /api/health")
	log.Printf("     POST /api/events")
	log.Printf("     GET  /api/events")
	log.Printf("     GET  /api/threats")
	log.Printf("     GET  /api/report")

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
