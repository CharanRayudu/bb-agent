package threatintel

import "strings"

// Technique represents a single MITRE ATT&CK technique or subtechnique.
type Technique struct {
	ID       string `json:"id"`        // T1190, T1059.004, …
	Name     string `json:"name"`
	Tactic   string `json:"tactic"`    // Initial Access, Execution, …
	TacticID string `json:"tactic_id"` // TA0001, …
	URL      string `json:"url"`
}

// FindingTechniqueMap holds ATT&CK techniques for one finding type.
type FindingTechniqueMap struct {
	FindingType string      `json:"finding_type"`
	Techniques  []Technique `json:"techniques"`
}

// ATTCKCoverage is the full coverage report for a set of finding types.
type ATTCKCoverage struct {
	FindingCount   int                    `json:"finding_count"`
	TechniqueCount int                    `json:"technique_count"`
	TacticCount    int                    `json:"tactic_count"`
	Mappings       []FindingTechniqueMap  `json:"mappings"`
	TacticMatrix   map[string][]Technique `json:"tactic_matrix"` // tactic → techniques observed
}

func t(id, name, tactic, tacticID string) Technique {
	base := "https://attack.mitre.org/techniques/"
	return Technique{
		ID:       id,
		Name:     name,
		Tactic:   tactic,
		TacticID: tacticID,
		URL:      base + strings.ReplaceAll(id, ".", "/") + "/",
	}
}

// findingTechniques maps Mirage finding type prefixes/exact IDs to ATT&CK techniques.
var findingTechniques = map[string][]Technique{
	// ── Web exploitation ─────────────────────────────────────────────────────
	"XSS": {
		t("T1189", "Drive-by Compromise", "Initial Access", "TA0001"),
		t("T1059.007", "JavaScript", "Execution", "TA0002"),
		t("T1185", "Browser Session Hijacking", "Collection", "TA0009"),
	},
	"Reflected XSS": {
		t("T1189", "Drive-by Compromise", "Initial Access", "TA0001"),
		t("T1059.007", "JavaScript", "Execution", "TA0002"),
	},
	"Stored XSS": {
		t("T1189", "Drive-by Compromise", "Initial Access", "TA0001"),
		t("T1059.007", "JavaScript", "Execution", "TA0002"),
		t("T1185", "Browser Session Hijacking", "Collection", "TA0009"),
	},
	"SQLi": {
		t("T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001"),
		t("T1005", "Data from Local System", "Collection", "TA0009"),
		t("T1083", "File and Directory Discovery", "Discovery", "TA0007"),
	},
	"SQL Injection": {
		t("T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001"),
		t("T1005", "Data from Local System", "Collection", "TA0009"),
	},
	"SAST-SQLi-001": {
		t("T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001"),
		t("T1005", "Data from Local System", "Collection", "TA0009"),
	},
	"SAST-SQLi-002": {
		t("T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001"),
		t("T1005", "Data from Local System", "Collection", "TA0009"),
	},
	"SSRF": {
		t("T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001"),
		t("T1552.005", "Cloud Instance Metadata API", "Credential Access", "TA0006"),
		t("T1018", "Remote System Discovery", "Discovery", "TA0007"),
		t("T1090", "Proxy", "Command and Control", "TA0011"),
	},
	"LFI": {
		t("T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001"),
		t("T1083", "File and Directory Discovery", "Discovery", "TA0007"),
		t("T1005", "Data from Local System", "Collection", "TA0009"),
		t("T1552.001", "Credentials in Files", "Credential Access", "TA0006"),
	},
	"RCE": {
		t("T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001"),
		t("T1059", "Command and Scripting Interpreter", "Execution", "TA0002"),
		t("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", "TA0004"),
	},
	"SSTI": {
		t("T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001"),
		t("T1059", "Command and Scripting Interpreter", "Execution", "TA0002"),
	},
	"SAST-SSTI-001": {
		t("T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001"),
		t("T1059", "Command and Scripting Interpreter", "Execution", "TA0002"),
	},
	"XXE": {
		t("T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001"),
		t("T1005", "Data from Local System", "Collection", "TA0009"),
		t("T1552.001", "Credentials in Files", "Credential Access", "TA0006"),
	},
	"SAST-XXE-001": {
		t("T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001"),
		t("T1005", "Data from Local System", "Collection", "TA0009"),
	},
	"CMDi":          {{ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "Execution", TacticID: "TA0002", URL: "https://attack.mitre.org/techniques/T1059/"}},
	"SAST-CMDi-001": {{ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "Execution", TacticID: "TA0002", URL: "https://attack.mitre.org/techniques/T1059/"}},
	"SAST-CMDi-002": {{ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "Execution", TacticID: "TA0002", URL: "https://attack.mitre.org/techniques/T1059/"}},
	"Path Traversal": {
		t("T1083", "File and Directory Discovery", "Discovery", "TA0007"),
		t("T1005", "Data from Local System", "Collection", "TA0009"),
	},
	"SAST-PTrav-001": {
		t("T1083", "File and Directory Discovery", "Discovery", "TA0007"),
		t("T1005", "Data from Local System", "Collection", "TA0009"),
	},
	"Open Redirect": {
		t("T1566.002", "Spearphishing Link", "Initial Access", "TA0001"),
		t("T1550.001", "Application Access Token", "Defense Evasion", "TA0005"),
	},
	"SAST-OpenRedirect-001": {
		t("T1566.002", "Spearphishing Link", "Initial Access", "TA0001"),
	},
	"CORS": {
		t("T1185", "Browser Session Hijacking", "Collection", "TA0009"),
		t("T1550.001", "Application Access Token", "Defense Evasion", "TA0005"),
	},
	"CSRF": {
		t("T1185", "Browser Session Hijacking", "Collection", "TA0009"),
	},
	"Deserialization": {
		t("T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001"),
		t("T1059", "Command and Scripting Interpreter", "Execution", "TA0002"),
	},
	"SAST-Deser-001": {
		t("T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001"),
		t("T1059", "Command and Scripting Interpreter", "Execution", "TA0002"),
	},
	"SAST-Deser-002": {
		t("T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001"),
		t("T1059.007", "JavaScript", "Execution", "TA0002"),
	},
	"Prototype Pollution": {
		t("T1059.007", "JavaScript", "Execution", "TA0002"),
		t("T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001"),
	},
	"GraphQL Injection": {
		t("T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001"),
		t("T1005", "Data from Local System", "Collection", "TA0009"),
	},

	// ── Auth/Session ─────────────────────────────────────────────────────────
	"IDOR": {
		t("T1078", "Valid Accounts", "Initial Access", "TA0001"),
		t("T1005", "Data from Local System", "Collection", "TA0009"),
	},
	"JWT": {
		t("T1550.001", "Application Access Token", "Defense Evasion", "TA0005"),
		t("T1078", "Valid Accounts", "Initial Access", "TA0001"),
	},
	"JWT Algorithm None": {
		t("T1550.001", "Application Access Token", "Defense Evasion", "TA0005"),
		t("T1078", "Valid Accounts", "Initial Access", "TA0001"),
	},
	"SAML": {
		t("T1550.001", "Application Access Token", "Defense Evasion", "TA0005"),
		t("T1606", "Forge Web Credentials", "Credential Access", "TA0006"),
	},
	"OAuth": {
		t("T1550.001", "Application Access Token", "Defense Evasion", "TA0005"),
		t("T1606", "Forge Web Credentials", "Credential Access", "TA0006"),
	},
	"Auth Bypass": {
		t("T1078", "Valid Accounts", "Initial Access", "TA0001"),
		t("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation", "TA0004"),
	},
	"Mass Assignment": {
		t("T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001"),
		t("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation", "TA0004"),
	},

	// ── Network & Infra ───────────────────────────────────────────────────────
	"Open Port": {
		t("T1046", "Network Service Discovery", "Discovery", "TA0007"),
	},
	"Default Credentials": {
		t("T1078.001", "Default Accounts", "Initial Access", "TA0001"),
		t("T1110.001", "Password Guessing", "Credential Access", "TA0006"),
	},
	"Default Creds": {
		t("T1078.001", "Default Accounts", "Initial Access", "TA0001"),
		t("T1110.001", "Password Guessing", "Credential Access", "TA0006"),
	},
	"Subdomain Takeover": {
		t("T1584.001", "Domains", "Resource Development", "TA0042"),
		t("T1189", "Drive-by Compromise", "Initial Access", "TA0001"),
	},
	"Unauthenticated Redis": {
		t("T1078.001", "Default Accounts", "Initial Access", "TA0001"),
		t("T1005", "Data from Local System", "Collection", "TA0009"),
	},
	"Unauthenticated MongoDB": {
		t("T1078.001", "Default Accounts", "Initial Access", "TA0001"),
		t("T1005", "Data from Local System", "Collection", "TA0009"),
	},
	"Exposed Docker API": {
		t("T1610", "Deploy Container", "Defense Evasion", "TA0005"),
		t("T1611", "Escape to Host", "Privilege Escalation", "TA0004"),
	},

	// ── Cloud Security ────────────────────────────────────────────────────────
	"Cloud-IMDS": {
		t("T1552.005", "Cloud Instance Metadata API", "Credential Access", "TA0006"),
		t("T1078.004", "Cloud Accounts", "Initial Access", "TA0001"),
	},
	"IMDS-Credentials": {
		t("T1552.005", "Cloud Instance Metadata API", "Credential Access", "TA0006"),
		t("T1078.004", "Cloud Accounts", "Initial Access", "TA0001"),
		t("T1530", "Data from Cloud Storage", "Collection", "TA0009"),
	},
	"S3-PublicRead": {
		t("T1530", "Data from Cloud Storage", "Collection", "TA0009"),
	},
	"S3-PublicWrite": {
		t("T1530", "Data from Cloud Storage", "Collection", "TA0009"),
		t("T1505.003", "Web Shell", "Persistence", "TA0003"),
	},
	"Cloud-StorageExposed": {
		t("T1530", "Data from Cloud Storage", "Collection", "TA0009"),
	},
	"K8s-APIServer": {
		t("T1613", "Container and Resource Discovery", "Discovery", "TA0007"),
		t("T1610", "Deploy Container", "Defense Evasion", "TA0005"),
	},
	"K8s-ServiceAccount": {
		t("T1078.004", "Cloud Accounts", "Initial Access", "TA0001"),
		t("T1552.007", "Container API", "Credential Access", "TA0006"),
	},

	// ── LLM / AI Red Team ────────────────────────────────────────────────────
	"LLM01-PromptInjection": {
		t("T1059", "Command and Scripting Interpreter", "Execution", "TA0002"),
		t("T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001"),
	},
	"LLM02-InfoDisclosure": {
		t("T1005", "Data from Local System", "Collection", "TA0009"),
	},
	"LLM06-ExcessiveAgency": {
		t("T1059", "Command and Scripting Interpreter", "Execution", "TA0002"),
		t("T1204", "User Execution", "Execution", "TA0002"),
	},
	"LLM07-SystemPromptLeak": {
		t("T1005", "Data from Local System", "Collection", "TA0009"),
	},
	"LLM08-Jailbreak": {
		t("T1562", "Impair Defenses", "Defense Evasion", "TA0005"),
	},
	"LLM03-RAGPoisoning": {
		t("T1565", "Data Manipulation", "Impact", "TA0040"),
	},

	// ── DevSecOps ────────────────────────────────────────────────────────────
	"Secret-AWSKey":            {{ID: "T1552.001", Name: "Credentials in Files", Tactic: "Credential Access", TacticID: "TA0006", URL: "https://attack.mitre.org/techniques/T1552/001/"}},
	"Secret-AWSSecretAccessKey": {{ID: "T1552.001", Name: "Credentials in Files", Tactic: "Credential Access", TacticID: "TA0006", URL: "https://attack.mitre.org/techniques/T1552/001/"}},
	"Secret-GitHubPersonalAccessToken": {
		t("T1552.001", "Credentials in Files", "Credential Access", "TA0006"),
		t("T1195.001", "Compromise Software Dependencies", "Initial Access", "TA0001"),
	},
	"Secret-RSAPrivateKey": {
		t("T1552.004", "Private Keys", "Credential Access", "TA0006"),
	},
	"Secret-DatabaseConnectionString": {
		t("T1552.001", "Credentials in Files", "Credential Access", "TA0006"),
		t("T1005", "Data from Local System", "Collection", "TA0009"),
	},
	"Secret-GenericPasswordinConfig": {
		t("T1552.001", "Credentials in Files", "Credential Access", "TA0006"),
	},
	"Secret-FileExposure": {
		t("T1083", "File and Directory Discovery", "Discovery", "TA0007"),
		t("T1552.001", "Credentials in Files", "Credential Access", "TA0006"),
	},
	"SAST-HardCred-001": {
		t("T1552.001", "Credentials in Files", "Credential Access", "TA0006"),
	},
	"SCA-CVE": {
		t("T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001"),
		t("T1203", "Exploitation for Client Execution", "Execution", "TA0002"),
	},
	"Container-RootUser": {
		t("T1610", "Deploy Container", "Defense Evasion", "TA0005"),
		t("T1611", "Escape to Host", "Privilege Escalation", "TA0004"),
	},
	"Container-Privileged": {
		t("T1611", "Escape to Host", "Privilege Escalation", "TA0004"),
		t("T1610", "Deploy Container", "Defense Evasion", "TA0005"),
	},
	"Container-SensitiveMount": {
		t("T1611", "Escape to Host", "Privilege Escalation", "TA0004"),
		t("T1552.001", "Credentials in Files", "Credential Access", "TA0006"),
	},
	"Container-SecretEnv": {
		t("T1552.007", "Container API", "Credential Access", "TA0006"),
	},
	"SAST-SSRF-001": {
		t("T1552.005", "Cloud Instance Metadata API", "Credential Access", "TA0006"),
		t("T1018", "Remote System Discovery", "Discovery", "TA0007"),
	},
	"SAST-XSS-001": {
		t("T1189", "Drive-by Compromise", "Initial Access", "TA0001"),
		t("T1059.007", "JavaScript", "Execution", "TA0002"),
	},
}

// MapFindingToATTCK returns ATT&CK techniques for a given finding type.
// Falls back to prefix matching if no exact match is found.
func MapFindingToATTCK(findingType string) []Technique {
	if techs, ok := findingTechniques[findingType]; ok {
		return techs
	}
	// Prefix matching for dynamic types (e.g. "SAST-SQLi-*" → "SQLi")
	normalized := strings.ToUpper(findingType)
	for key, techs := range findingTechniques {
		if strings.HasPrefix(normalized, strings.ToUpper(key)) ||
			strings.HasPrefix(strings.ToUpper(key), normalized) {
			return techs
		}
	}
	return nil
}

// GenerateCoverage produces an ATTCKCoverage report for a set of finding types.
func GenerateCoverage(findingTypes []string) ATTCKCoverage {
	var mappings []FindingTechniqueMap
	tacticMatrix := map[string][]Technique{}
	techSeen := map[string]bool{}
	tacticSeen := map[string]bool{}

	for _, ft := range findingTypes {
		techs := MapFindingToATTCK(ft)
		if len(techs) == 0 {
			continue
		}
		mappings = append(mappings, FindingTechniqueMap{
			FindingType: ft,
			Techniques:  techs,
		})
		for _, tech := range techs {
			if !techSeen[tech.ID] {
				techSeen[tech.ID] = true
			}
			if !tacticSeen[tech.Tactic] {
				tacticSeen[tech.Tactic] = true
			}
			// De-duplicate techniques in tactic matrix
			existing := tacticMatrix[tech.Tactic]
			found := false
			for _, e := range existing {
				if e.ID == tech.ID {
					found = true
					break
				}
			}
			if !found {
				tacticMatrix[tech.Tactic] = append(tacticMatrix[tech.Tactic], tech)
			}
		}
	}

	return ATTCKCoverage{
		FindingCount:   len(findingTypes),
		TechniqueCount: len(techSeen),
		TacticCount:    len(tacticSeen),
		Mappings:       mappings,
		TacticMatrix:   tacticMatrix,
	}
}
