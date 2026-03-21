// Package resourcehunter implements the Resource Hunter specialist agent.
// Discovers sensitive files, configuration leaks, exposed development artifacts,
// and backup files that should not be publicly accessible.
package resourcehunter

import (
	"context"
	"fmt"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

type Agent struct{ systemPrompt string }

func New() *Agent { return &Agent{systemPrompt: defaultSystemPrompt} }

func (a *Agent) Name() string         { return "Resource Hunter Agent" }
func (a *Agent) ID() string           { return "resourcehunter" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL")
	}

	var findings []*base.Finding
	for _, probe := range probes {
		findings = append(findings, &base.Finding{
			Type:       "Sensitive File",
			URL:        targetURL + probe.path,
			Payload:    probe.description,
			Severity:   probe.severity,
			Confidence: 0.0,
			Evidence: map[string]interface{}{
				"category":      probe.category,
				"expected_code": probe.expectedCode,
				"file_type":     probe.fileType,
			},
			Method: "GET",
		})
	}
	return findings, nil
}

type resourceProbe struct {
	path         string
	description  string
	category     string
	severity     string
	expectedCode int
	fileType     string
}

var probes = []resourceProbe{
	// Environment & configuration files
	{"/.env", "Environment file with secrets (DB passwords, API keys)", "config", "critical", 200, "env"},
	{"/.env.local", "Local environment override", "config", "critical", 200, "env"},
	{"/.env.production", "Production environment secrets", "config", "critical", 200, "env"},
	{"/.env.backup", "Backup of environment file", "config", "critical", 200, "env"},
	{"/config.yml", "YAML configuration file", "config", "high", 200, "yaml"},
	{"/config.json", "JSON configuration file", "config", "high", 200, "json"},
	{"/application.properties", "Java/Spring application properties", "config", "high", 200, "properties"},
	{"/appsettings.json", "ASP.NET application settings", "config", "high", 200, "json"},
	{"/wp-config.php", "WordPress configuration with DB credentials", "config", "critical", 200, "php"},
	{"/wp-config.php.bak", "WordPress config backup", "config", "critical", 200, "php"},

	// Version control
	{"/.git/HEAD", "Git repository exposed", "vcs", "critical", 200, "git"},
	{"/.git/config", "Git config with remote URLs", "vcs", "critical", 200, "git"},
	{"/.gitignore", "Gitignore reveals project structure", "vcs", "low", 200, "text"},
	{"/.svn/entries", "SVN repository exposed", "vcs", "high", 200, "svn"},
	{"/.hg/requires", "Mercurial repository exposed", "vcs", "high", 200, "hg"},

	// Backups & archives
	{"/backup.sql", "Database backup file", "backup", "critical", 200, "sql"},
	{"/backup.zip", "Backup archive", "backup", "critical", 200, "archive"},
	{"/db.sql", "Database dump", "backup", "critical", 200, "sql"},
	{"/dump.sql", "Database dump", "backup", "critical", 200, "sql"},
	{"/site.tar.gz", "Site backup archive", "backup", "high", 200, "archive"},

	// Debug & development
	{"/debug", "Debug endpoint exposed", "debug", "high", 200, "html"},
	{"/phpinfo.php", "PHP info page with server details", "debug", "medium", 200, "php"},
	{"/info.php", "PHP info page", "debug", "medium", 200, "php"},
	{"/server-status", "Apache server-status page", "debug", "medium", 200, "html"},
	{"/nginx-status", "Nginx status page", "debug", "medium", 200, "html"},
	{"/actuator", "Spring Boot Actuator endpoints", "debug", "high", 200, "json"},
	{"/actuator/env", "Spring Boot environment variables", "debug", "critical", 200, "json"},
	{"/actuator/heapdump", "Spring Boot heap dump", "debug", "critical", 200, "binary"},
	{"/__debug__/", "Django debug toolbar", "debug", "high", 200, "html"},
	{"/elmah.axd", "ASP.NET ELMAH error logs", "debug", "high", 200, "html"},

	// Source code
	{"/package.json", "Node.js package manifest", "source", "low", 200, "json"},
	{"/composer.json", "PHP Composer manifest", "source", "low", 200, "json"},
	{"/Gemfile", "Ruby Gemfile", "source", "low", 200, "text"},
	{"/requirements.txt", "Python requirements", "source", "low", 200, "text"},

	// API documentation
	{"/swagger.json", "Swagger/OpenAPI spec", "api_docs", "medium", 200, "json"},
	{"/openapi.json", "OpenAPI specification", "api_docs", "medium", 200, "json"},
	{"/api-docs", "API documentation endpoint", "api_docs", "medium", 200, "html"},
	{"/graphql", "GraphQL endpoint", "api_docs", "medium", 200, "json"},
	{"/.well-known/openid-configuration", "OpenID Connect discovery", "api_docs", "low", 200, "json"},

	// Secrets & tokens
	{"/id_rsa", "SSH private key", "secrets", "critical", 200, "key"},
	{"/.ssh/id_rsa", "SSH private key", "secrets", "critical", 200, "key"},
	{"/server.key", "SSL private key", "secrets", "critical", 200, "key"},
	{"/.dockerenv", "Docker environment indicator", "infra", "low", 200, "text"},
	{"/docker-compose.yml", "Docker Compose with service details", "infra", "medium", 200, "yaml"},
	{"/Dockerfile", "Dockerfile with build details", "infra", "low", 200, "text"},
	{"/.aws/credentials", "AWS credentials file", "secrets", "critical", 200, "ini"},

	// Admin panels
	{"/admin", "Admin panel", "admin", "medium", 200, "html"},
	{"/admin/login", "Admin login page", "admin", "low", 200, "html"},
	{"/administrator", "Joomla admin", "admin", "medium", 200, "html"},
	{"/wp-admin", "WordPress admin", "admin", "medium", 302, "html"},
	{"/phpmyadmin", "phpMyAdmin database management", "admin", "high", 200, "html"},
}

const defaultSystemPrompt = `You are a Resource Hunter -- a specialist in discovering sensitive files and misconfigurations:

Target Categories:
1. ENVIRONMENT FILES: .env, config.yml, application.properties, wp-config.php
2. VERSION CONTROL: .git/HEAD, .svn/entries, .hg/
3. BACKUPS: *.sql, *.zip, *.tar.gz database dumps
4. DEBUG ENDPOINTS: phpinfo, server-status, Spring Actuator, Django debug
5. SOURCE CODE: package.json, composer.json, requirements.txt
6. API DOCS: swagger.json, openapi.json, GraphQL endpoints
7. SECRETS: SSH keys, SSL keys, AWS credentials
8. ADMIN PANELS: /admin, /wp-admin, phpmyadmin

RULES:
1. .env and credential files are ALWAYS critical
2. Exposed .git is critical (full source code access)
3. Check response codes AND content (200 with HTML error != real file)
4. Spring Actuator /heapdump is critical (memory dump with secrets)
5. Always verify findings by checking response content, not just status codes`
