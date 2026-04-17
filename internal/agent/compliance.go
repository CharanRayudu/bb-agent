package agent

import "strings"

// ComplianceTag maps a vuln type to CWE, OWASP Top 10 2021, and NIST 800-53 controls.
type ComplianceTag struct {
	CWE     []string
	OWASP   []string // e.g. "A03:2021-Injection"
	NIST    []string // e.g. "SI-10", "SC-8"
	PCI_DSS []string // e.g. "6.3.1"
}

// complianceTable maps normalized vuln type keys to ComplianceTag entries.
var complianceTable = map[string]ComplianceTag{
	"xss": {
		CWE:     []string{"CWE-79"},
		OWASP:   []string{"A03:2021-Injection"},
		NIST:    []string{"SI-10", "SC-18", "SI-15"},
		PCI_DSS: []string{"6.2.4", "6.3.2"},
	},
	"sqli": {
		CWE:     []string{"CWE-89"},
		OWASP:   []string{"A03:2021-Injection"},
		NIST:    []string{"SI-10", "AC-3", "SC-28"},
		PCI_DSS: []string{"6.2.4", "6.3.1"},
	},
	"sql injection": {
		CWE:     []string{"CWE-89"},
		OWASP:   []string{"A03:2021-Injection"},
		NIST:    []string{"SI-10", "AC-3", "SC-28"},
		PCI_DSS: []string{"6.2.4", "6.3.1"},
	},
	"ssrf": {
		CWE:     []string{"CWE-918"},
		OWASP:   []string{"A10:2021-Server-Side Request Forgery"},
		NIST:    []string{"SC-7", "AC-4", "SI-3"},
		PCI_DSS: []string{"6.2.4", "1.3.2"},
	},
	"lfi": {
		CWE:     []string{"CWE-22", "CWE-73"},
		OWASP:   []string{"A01:2021-Broken Access Control"},
		NIST:    []string{"AC-3", "SI-10", "CM-7"},
		PCI_DSS: []string{"6.2.4", "7.1"},
	},
	"local file inclusion": {
		CWE:     []string{"CWE-22", "CWE-73"},
		OWASP:   []string{"A01:2021-Broken Access Control"},
		NIST:    []string{"AC-3", "SI-10", "CM-7"},
		PCI_DSS: []string{"6.2.4", "7.1"},
	},
	"rce": {
		CWE:     []string{"CWE-78", "CWE-94"},
		OWASP:   []string{"A03:2021-Injection"},
		NIST:    []string{"SI-10", "CM-7", "SC-39"},
		PCI_DSS: []string{"6.2.4", "6.3.3"},
	},
	"remote code execution": {
		CWE:     []string{"CWE-78", "CWE-94"},
		OWASP:   []string{"A03:2021-Injection"},
		NIST:    []string{"SI-10", "CM-7", "SC-39"},
		PCI_DSS: []string{"6.2.4", "6.3.3"},
	},
	"jwt": {
		CWE:     []string{"CWE-347", "CWE-327"},
		OWASP:   []string{"A02:2021-Cryptographic Failures", "A07:2021-Identification and Authentication Failures"},
		NIST:    []string{"IA-5", "SC-8", "SC-13"},
		PCI_DSS: []string{"6.2.4", "8.3.6"},
	},
	"jwt vulnerability": {
		CWE:     []string{"CWE-347", "CWE-327"},
		OWASP:   []string{"A02:2021-Cryptographic Failures", "A07:2021-Identification and Authentication Failures"},
		NIST:    []string{"IA-5", "SC-8", "SC-13"},
		PCI_DSS: []string{"6.2.4", "8.3.6"},
	},
	"idor": {
		CWE:     []string{"CWE-639", "CWE-284"},
		OWASP:   []string{"A01:2021-Broken Access Control"},
		NIST:    []string{"AC-3", "AC-4", "AC-6"},
		PCI_DSS: []string{"6.2.4", "7.1", "7.2"},
	},
	"insecure direct object reference": {
		CWE:     []string{"CWE-639", "CWE-284"},
		OWASP:   []string{"A01:2021-Broken Access Control"},
		NIST:    []string{"AC-3", "AC-4", "AC-6"},
		PCI_DSS: []string{"6.2.4", "7.1", "7.2"},
	},
	"ssti": {
		CWE:     []string{"CWE-94"},
		OWASP:   []string{"A03:2021-Injection"},
		NIST:    []string{"SI-10", "CM-7"},
		PCI_DSS: []string{"6.2.4"},
	},
	"csti": {
		CWE:     []string{"CWE-94", "CWE-79"},
		OWASP:   []string{"A03:2021-Injection"},
		NIST:    []string{"SI-10", "CM-7"},
		PCI_DSS: []string{"6.2.4"},
	},
	"server-side template injection": {
		CWE:     []string{"CWE-94"},
		OWASP:   []string{"A03:2021-Injection"},
		NIST:    []string{"SI-10", "CM-7"},
		PCI_DSS: []string{"6.2.4"},
	},
	"xxe": {
		CWE:     []string{"CWE-611"},
		OWASP:   []string{"A05:2021-Security Misconfiguration"},
		NIST:    []string{"SI-10", "CM-6", "CM-7"},
		PCI_DSS: []string{"6.2.4", "6.3.1"},
	},
	"xml external entity": {
		CWE:     []string{"CWE-611"},
		OWASP:   []string{"A05:2021-Security Misconfiguration"},
		NIST:    []string{"SI-10", "CM-6", "CM-7"},
		PCI_DSS: []string{"6.2.4", "6.3.1"},
	},
	"cors": {
		CWE:     []string{"CWE-942", "CWE-346"},
		OWASP:   []string{"A01:2021-Broken Access Control", "A05:2021-Security Misconfiguration"},
		NIST:    []string{"AC-3", "SC-8", "CM-6"},
		PCI_DSS: []string{"6.2.4", "6.3.2"},
	},
	"cors misconfiguration": {
		CWE:     []string{"CWE-942", "CWE-346"},
		OWASP:   []string{"A01:2021-Broken Access Control", "A05:2021-Security Misconfiguration"},
		NIST:    []string{"AC-3", "SC-8", "CM-6"},
		PCI_DSS: []string{"6.2.4", "6.3.2"},
	},
	"file upload": {
		CWE:     []string{"CWE-434"},
		OWASP:   []string{"A04:2021-Insecure Design"},
		NIST:    []string{"SI-3", "CM-7", "SC-28"},
		PCI_DSS: []string{"6.2.4", "6.3.3"},
	},
	"unrestricted file upload": {
		CWE:     []string{"CWE-434"},
		OWASP:   []string{"A04:2021-Insecure Design"},
		NIST:    []string{"SI-3", "CM-7", "SC-28"},
		PCI_DSS: []string{"6.2.4", "6.3.3"},
	},
	"open redirect": {
		CWE:     []string{"CWE-601"},
		OWASP:   []string{"A01:2021-Broken Access Control"},
		NIST:    []string{"SI-10", "SC-8"},
		PCI_DSS: []string{"6.2.4"},
	},
	"deserialization": {
		CWE:     []string{"CWE-502"},
		OWASP:   []string{"A08:2021-Software and Data Integrity Failures"},
		NIST:    []string{"SI-10", "CM-7", "SC-39"},
		PCI_DSS: []string{"6.2.4", "6.3.3"},
	},
	"insecure deserialization": {
		CWE:     []string{"CWE-502"},
		OWASP:   []string{"A08:2021-Software and Data Integrity Failures"},
		NIST:    []string{"SI-10", "CM-7", "SC-39"},
		PCI_DSS: []string{"6.2.4", "6.3.3"},
	},
	"log4shell": {
		CWE:     []string{"CWE-917", "CWE-502"},
		OWASP:   []string{"A06:2021-Vulnerable and Outdated Components"},
		NIST:    []string{"SI-2", "SI-3", "CM-8"},
		PCI_DSS: []string{"6.3.3", "6.2.4"},
	},
	"csrf": {
		CWE:     []string{"CWE-352"},
		OWASP:   []string{"A01:2021-Broken Access Control"},
		NIST:    []string{"SC-8", "SI-10", "AC-3"},
		PCI_DSS: []string{"6.2.4", "6.3.2"},
	},
	"cross-site request forgery": {
		CWE:     []string{"CWE-352"},
		OWASP:   []string{"A01:2021-Broken Access Control"},
		NIST:    []string{"SC-8", "SI-10", "AC-3"},
		PCI_DSS: []string{"6.2.4", "6.3.2"},
	},
	"host header injection": {
		CWE:     []string{"CWE-116", "CWE-20"},
		OWASP:   []string{"A03:2021-Injection", "A05:2021-Security Misconfiguration"},
		NIST:    []string{"SI-10", "SC-8", "CM-6"},
		PCI_DSS: []string{"6.2.4"},
	},
	"header injection": {
		CWE:     []string{"CWE-113", "CWE-116"},
		OWASP:   []string{"A03:2021-Injection"},
		NIST:    []string{"SI-10", "SC-8"},
		PCI_DSS: []string{"6.2.4"},
	},
	"cache poisoning": {
		CWE:     []string{"CWE-345", "CWE-20"},
		OWASP:   []string{"A05:2021-Security Misconfiguration"},
		NIST:    []string{"SC-8", "SI-10", "CM-6"},
		PCI_DSS: []string{"6.2.4", "6.3.2"},
	},
	"web cache poisoning": {
		CWE:     []string{"CWE-345", "CWE-20"},
		OWASP:   []string{"A05:2021-Security Misconfiguration"},
		NIST:    []string{"SC-8", "SI-10", "CM-6"},
		PCI_DSS: []string{"6.2.4", "6.3.2"},
	},
	"oauth": {
		CWE:     []string{"CWE-601", "CWE-287"},
		OWASP:   []string{"A07:2021-Identification and Authentication Failures", "A01:2021-Broken Access Control"},
		NIST:    []string{"IA-2", "IA-5", "AC-3"},
		PCI_DSS: []string{"8.3.6", "6.2.4"},
	},
	"oauth misconfiguration": {
		CWE:     []string{"CWE-601", "CWE-287"},
		OWASP:   []string{"A07:2021-Identification and Authentication Failures", "A01:2021-Broken Access Control"},
		NIST:    []string{"IA-2", "IA-5", "AC-3"},
		PCI_DSS: []string{"8.3.6", "6.2.4"},
	},
	"prototype pollution": {
		CWE:     []string{"CWE-1321"},
		OWASP:   []string{"A08:2021-Software and Data Integrity Failures"},
		NIST:    []string{"SI-10", "CM-7"},
		PCI_DSS: []string{"6.2.4"},
	},
	"business logic": {
		CWE:     []string{"CWE-840", "CWE-284"},
		OWASP:   []string{"A01:2021-Broken Access Control", "A04:2021-Insecure Design"},
		NIST:    []string{"AC-3", "AC-6", "SI-10"},
		PCI_DSS: []string{"6.2.4", "7.1"},
	},
}

// defaultComplianceTag is returned for unrecognized vulnerability types.
var defaultComplianceTag = ComplianceTag{
	CWE:     []string{"CWE-693"},
	OWASP:   []string{"A05:2021-Security Misconfiguration"},
	NIST:    []string{"SI-10", "CM-6"},
	PCI_DSS: []string{"6.2.4"},
}

// ComplianceTags returns the compliance mapping for a given vulnerability type.
func ComplianceTags(vulnType string) ComplianceTag {
	key := strings.ToLower(strings.TrimSpace(vulnType))

	if tag, ok := complianceTable[key]; ok {
		return tag
	}

	// Fuzzy match: check if the key contains a known type substring or vice versa.
	for k, tag := range complianceTable {
		if strings.Contains(key, k) || strings.Contains(k, key) {
			return tag
		}
	}

	return defaultComplianceTag
}
