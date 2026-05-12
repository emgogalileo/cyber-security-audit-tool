// Package audit provides threat detection heuristics for security events.
//
// Detection rules (configurable thresholds):
//   - BRUTE_FORCE  : >10 LOGIN_ATTEMPT events from same IP within 60 s
//   - PORT_SCAN    : >5  PORT_SCAN events from same IP
package audit

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Thresholds — adjust to match your security policy.
const (
	bruteForceThreshold = 10
	portScanThreshold   = 5
)

// Analyzer inspects stored events and generates ThreatAlerts.
type Analyzer struct {
	store Store
}

// NewAnalyzer creates an Analyzer backed by the given Store.
func NewAnalyzer(store Store) *Analyzer {
	return &Analyzer{store: store}
}

// DetectThreats scans all stored events and returns active ThreatAlerts.
// This is a full scan; in production, use streaming or incremental analysis.
func (a *Analyzer) DetectThreats() []ThreatAlert {
	events := a.store.ListAll()
	alerts := []ThreatAlert{}

	// Index events by type and source IP for fast grouping
	loginAttempts := groupByIP(events, EventTypeLogin)
	portScans := groupByIP(events, EventTypePortScan)

	// ── Brute Force Detection ─────────────────────────────────────────────────
	for ip, evs := range loginAttempts {
		recent := filterRecent(evs, 60*time.Second)
		if len(recent) >= bruteForceThreshold {
			alerts = append(alerts, ThreatAlert{
				ID:          uuid.New().String(),
				Type:        "BRUTE_FORCE",
				SourceIP:    ip,
				EventCount:  len(recent),
				Description: fmt.Sprintf("IP %s made %d login attempts in the last 60 seconds.", ip, len(recent)),
				Severity:    SeverityCritical,
				DetectedAt:  time.Now().UTC(),
			})
		}
	}

	// ── Port Scan Detection ───────────────────────────────────────────────────
	for ip, evs := range portScans {
		if len(evs) >= portScanThreshold {
			alerts = append(alerts, ThreatAlert{
				ID:          uuid.New().String(),
				Type:        "PORT_SCAN",
				SourceIP:    ip,
				EventCount:  len(evs),
				Description: fmt.Sprintf("IP %s triggered %d port scan events.", ip, len(evs)),
				Severity:    SeverityWarning,
				DetectedAt:  time.Now().UTC(),
			})
		}
	}

	return alerts
}

// BuildReport computes an AuditReport from all stored events.
func (a *Analyzer) BuildReport() AuditReport {
	events := a.store.ListAll()
	threats := a.DetectThreats()

	bySeverity := map[string]int{
		string(SeverityInfo):     0,
		string(SeverityWarning):  0,
		string(SeverityCritical): 0,
	}
	for _, e := range events {
		bySeverity[string(e.Severity)]++
	}

	// Keep only the 5 most recent threats in the report
	recent := threats
	if len(recent) > 5 {
		recent = recent[len(recent)-5:]
	}

	return AuditReport{
		GeneratedAt:   time.Now().UTC(),
		TotalEvents:   len(events),
		BySeverity:    bySeverity,
		ActiveThreats: len(threats),
		TopOffenders:  a.store.TopIPs(5),
		RecentThreats: recent,
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func groupByIP(events []SecurityEvent, eventType EventType) map[string][]SecurityEvent {
	result := make(map[string][]SecurityEvent)
	for _, e := range events {
		if e.Type == eventType {
			result[e.SourceIP] = append(result[e.SourceIP], e)
		}
	}
	return result
}

func filterRecent(events []SecurityEvent, window time.Duration) []SecurityEvent {
	cutoff := time.Now().UTC().Add(-window)
	var recent []SecurityEvent
	for _, e := range events {
		if e.Timestamp.After(cutoff) {
			recent = append(recent, e)
		}
	}
	return recent
}
