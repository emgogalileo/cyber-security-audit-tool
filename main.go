package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type AuditLog struct {
	EventID   string    `json:"event_id"`
	Timestamp time.Time `json:"timestamp"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	SourceIP  string    `json:"source_ip"`
}

var auditLogs []AuditLog

func logHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var newLog AuditLog
		if err := json.NewDecoder(r.Body).Decode(&newLog); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		newLog.Timestamp = time.Now()
		auditLogs = append(auditLogs, newLog)
		log.Printf("Received audit log: %s", newLog.EventID)
		w.WriteHeader(http.StatusCreated)
		return
	} else if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(auditLogs)
		return
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Cyber Security Audit Log Collector is running. Collected %d logs.", len(auditLogs))
}

func main() {
	http.HandleFunc("/api/logs", logHandler)
	http.HandleFunc("/api/status", statusHandler)
	
	port := ":8080"
	log.Printf("Starting Cyber Security Audit server on port %s", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
