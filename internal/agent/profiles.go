package agent

import "time"

// ScanProfile defines a named collection of scan settings.
type ScanProfile struct {
	Name           string
	Description    string
	Specialists    []string // subset of specialist IDs to enable
	MaxDepth       int
	Timeout        time.Duration
	Aggressiveness int // 1-5
}

// DefaultProfiles is the built-in library of scan profiles.
var DefaultProfiles = map[string]ScanProfile{
	"quick": {
		Name:        "quick",
		Description: "Fast recon plus top 5 vulnerability checks",
		Specialists: []string{
			"assetdiscovery", "gospider", "urlmaster",
			"xss", "sqli", "lfi", "openredirect", "nuclei",
		},
		MaxDepth:       2,
		Timeout:        30 * time.Minute,
		Aggressiveness: 2,
	},
	"owasp": {
		Name:        "owasp",
		Description: "All OWASP Top 10 checks",
		Specialists: []string{
			"assetdiscovery", "gospider", "urlmaster", "authdiscovery",
			"xss", "sqli", "sqli", "lfi", "rce", "xxe", "idor",
			"ssrf", "massassignment", "jwt", "fileupload", "nuclei",
			"headerinjection", "validation",
		},
		MaxDepth:       4,
		Timeout:        90 * time.Minute,
		Aggressiveness: 3,
	},
	"api": {
		Name:        "api",
		Description: "API security focused checks",
		Specialists: []string{
			"apisecurity", "authdiscovery", "idor", "massassignment",
			"jwt", "ssrf", "rce", "sqli", "xxe", "nuclei", "validation",
		},
		MaxDepth:       3,
		Timeout:        60 * time.Minute,
		Aggressiveness: 3,
	},
	"pci": {
		Name:        "pci",
		Description: "PCI-DSS relevant checks",
		Specialists: []string{
			"assetdiscovery", "authdiscovery", "xss", "sqli", "sqlmap",
			"lfi", "rce", "ssrf", "headerinjection", "nuclei",
			"apisecurity", "validation", "consolidation",
		},
		MaxDepth:       4,
		Timeout:        120 * time.Minute,
		Aggressiveness: 3,
	},
	"stealth": {
		Name:        "stealth",
		Description: "Low-noise, slow checks designed to evade detection",
		Specialists: []string{
			"assetdiscovery", "gospider", "urlmaster",
			"xss", "sqli", "lfi", "idor", "validation",
		},
		MaxDepth:       2,
		Timeout:        180 * time.Minute,
		Aggressiveness: 1,
	},
	"full": {
		Name:        "full",
		Description: "All specialists at maximum aggressiveness",
		Specialists: []string{
			"apisecurity", "assetdiscovery", "authdiscovery", "businesslogic",
			"chaindiscovery", "cloudhunter", "consolidation", "csti",
			"dastysast", "fileupload", "gospider", "header_injection",
			"idor", "jwt", "lfi", "massassignment", "nuclei", "openredirect",
			"postexploit", "protopollution", "rce", "reporting", "resourcehunter",
			"sqli", "sqlmap", "ssrf", "urlmaster", "validation", "visualcrawler",
			"wafevasion", "xss", "xxe",
		},
		MaxDepth:       6,
		Timeout:        240 * time.Minute,
		Aggressiveness: 5,
	},
}

// GetProfile looks up a profile by name, returning the profile and whether it was found.
func GetProfile(name string) (ScanProfile, bool) {
	p, ok := DefaultProfiles[name]
	return p, ok
}
