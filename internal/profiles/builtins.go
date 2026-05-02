package profiles

import "time"

func builtinProfiles() []Profile {
	now := time.Now()

	agent := func(id string, extra ...map[string]interface{}) AgentConfig {
		cfg := AgentConfig{ID: id, Enabled: true}
		if len(extra) > 0 {
			cfg.Config = extra[0]
		}
		return cfg
	}

	return []Profile{
		{
			ID:          "quick-recon",
			Name:        "Quick Recon",
			Description: "Fast surface enumeration and low-hanging-fruit checks. Ideal for initial triage or CI gate validation. Completes in minutes.",
			Category:    "web",
			Icon:        "Zap",
			Color:       "#67e8f9",
			Tags:        []string{"fast", "recon", "triage"},
			Builtin:     true,
			Agents: []AgentConfig{
				agent("reconnaissance", map[string]interface{}{"depth": 2}),
				agent("web_spider"),
				agent("header_analyzer"),
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:          "owasp-top10",
			Name:        "OWASP Top 10",
			Description: "Comprehensive coverage of OWASP Top 10 2025 categories including injection, broken access control, cryptographic failures, and misconfigurations.",
			Category:    "web",
			Icon:        "Shield",
			Color:       "#c4b5fd",
			Tags:        []string{"owasp", "web", "comprehensive", "compliance"},
			Builtin:     true,
			Agents: []AgentConfig{
				agent("reconnaissance"),
				agent("xss_scanner"),
				agent("sqli_scanner", map[string]interface{}{"techniques": []string{"error-based", "time-based", "union"}}),
				agent("ssrf_scanner"),
				agent("lfi_scanner"),
				agent("idor_scanner"),
				agent("auth_tester"),
				agent("cors_analyzer"),
				agent("header_analyzer"),
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:          "api-security",
			Name:        "API Security",
			Description: "REST and GraphQL API testing including BOLA/IDOR, mass assignment, broken function-level authorization, injection, and JWT weaknesses.",
			Category:    "api",
			Icon:        "Code2",
			Color:       "#6ee7b7",
			Tags:        []string{"api", "rest", "graphql", "jwt", "idor"},
			Builtin:     true,
			Agents: []AgentConfig{
				agent("api_fuzzer", map[string]interface{}{"spec_discovery": true}),
				agent("idor_scanner"),
				agent("auth_tester", map[string]interface{}{"jwt": true, "oauth": true}),
				agent("sqli_scanner"),
				agent("ssrf_scanner"),
				agent("mass_assignment"),
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:          "cloud-container",
			Name:        "Cloud & Container",
			Description: "Cloud misconfiguration detection (AWS/GCP/Azure), IMDS exposure, S3 bucket permissions, Kubernetes RBAC, and container security analysis.",
			Category:    "cloud",
			Icon:        "Globe",
			Color:       "#fbbf24",
			Tags:        []string{"cloud", "aws", "gcp", "k8s", "container", "imds"},
			Builtin:     true,
			Agents: []AgentConfig{
				agent("ssrf_scanner", map[string]interface{}{"imds_probe": true}),
				agent("devsecops", map[string]interface{}{"mode": "container"}),
				agent("cloud_enum"),
				agent("header_analyzer"),
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:          "devsecops-full",
			Name:        "DevSecOps Pipeline",
			Description: "Full static analysis (Semgrep), SCA dependency audit (Grype), secrets detection across 25+ patterns, and Dockerfile/compose security review.",
			Category:    "devsecops",
			Icon:        "GitPullRequest",
			Color:       "#f87171",
			Tags:        []string{"sast", "sca", "secrets", "container", "cicd"},
			Builtin:     true,
			Agents: []AgentConfig{
				agent("devsecops", map[string]interface{}{"mode": "full"}),
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:          "compliance-audit",
			Name:        "Compliance Audit",
			Description: "PCI-DSS, SOC2, and ISO 27001 oriented checks. Focuses on cryptographic failures, authentication controls, logging gaps, and sensitive data exposure.",
			Category:    "compliance",
			Icon:        "BookOpen",
			Color:       "#a78bfa",
			Tags:        []string{"pci-dss", "soc2", "iso27001", "compliance", "audit"},
			Builtin:     true,
			Agents: []AgentConfig{
				agent("header_analyzer"),
				agent("auth_tester", map[string]interface{}{"mfa_check": true}),
				agent("cors_analyzer"),
				agent("tls_analyzer"),
				agent("devsecops", map[string]interface{}{"mode": "secrets"}),
				agent("sqli_scanner"),
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:          "full-pentest",
			Name:        "Full Pentest",
			Description: "All agents enabled at maximum depth. Includes recon, all injection types, auth testing, business logic, cloud checks, and DevSecOps scanning. Best for quarterly assessments.",
			Category:    "web",
			Icon:        "Target",
			Color:       "#ff7f50",
			Tags:        []string{"full", "deep", "quarterly", "comprehensive"},
			Builtin:     true,
			Agents: []AgentConfig{
				agent("reconnaissance", map[string]interface{}{"depth": 5}),
				agent("web_spider"),
				agent("xss_scanner", map[string]interface{}{"payloads": "waf-bypass"}),
				agent("sqli_scanner", map[string]interface{}{"techniques": []string{"error-based", "time-based", "union", "blind"}}),
				agent("ssrf_scanner", map[string]interface{}{"imds_probe": true}),
				agent("lfi_scanner"),
				agent("idor_scanner"),
				agent("auth_tester", map[string]interface{}{"jwt": true, "oauth": true, "saml": true}),
				agent("cors_analyzer"),
				agent("header_analyzer"),
				agent("tls_analyzer"),
				agent("api_fuzzer", map[string]interface{}{"spec_discovery": true}),
				agent("devsecops", map[string]interface{}{"mode": "full"}),
				agent("cloud_enum"),
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
	}
}
