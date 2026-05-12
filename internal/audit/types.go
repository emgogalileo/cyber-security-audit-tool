// Package audit defines domain types for the cyber security audit engine.
package audit

import "time"

// Severity represents the criticality level of a security event.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityWarning  Severity = "WARNING"
	SeverityCritical Severity = "CRITICAL"
)

// EventType classifies the kind of security event observed.
type EventType string

const (
	EventTypeLogin       EventType = "LOGIN_ATTEMPT"
	EventTypePortScan    EventType = "PORT_SCAN"
	EventTypeFileAccess  EventType = "FILE_ACCESS"
	EventTypeDNSQuery    EventType = "DNS_QUERY"
	EventTypeHTTPRequest EventType = "HTTP_REQUEST"
)

// SecurityEvent is a structured log entry received from a client or agent.
type SecurityEvent struct {
	ID        string    `json:"id"`
	Type      EventType `json:"type"`
	SourceIP  string    `json:"source_ip"`
	TargetIP  string    `json:"target_ip,omitempty"`
	Port      int       `json:"port,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	Payload   string    `json:"payload,omitempty"`
	Severity  Severity  `json:"severity"`
	Timestamp time.Time `json:"timestamp"`
}

// ThreatAlert is raised by the Analyzer when a pattern of events
// suggests malicious intent.
type ThreatAlert struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`        // e.g. "BRUTE_FORCE", "PORT_SCAN"
	SourceIP    string    `json:"source_ip"`   // offending IP address
	EventCount  int       `json:"event_count"` // number of triggering events
	Description string    `json:"description"`
	Severity    Severity  `json:"severity"`
	DetectedAt  time.Time `json:"detected_at"`
}

// AuditReport is a summary of all collected events and threats.
type AuditReport struct {
	GeneratedAt    time.Time     `json:"generated_at"`
	TotalEvents    int           `json:"total_events"`
	BySeverity     map[string]int `json:"by_severity"`
	ActiveThreats  int           `json:"active_threats"`
	TopOffenders   []string      `json:"top_offenders"` // top 5 source IPs
	RecentThreats  []ThreatAlert `json:"recent_threats"`
}
