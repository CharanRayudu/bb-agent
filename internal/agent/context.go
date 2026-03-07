// Package agent provides the Tech Context intelligence layer.
// Provides Tech Context mixin logic.
//
// It loads technology profiles from recon data and generates context-aware
// "Prime Directive" prompt blocks that make every specialist agent aware of
// the target's exact technology stack -- transforming generic agents into
// stack-specific precision tools.
package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ---------------------------------------------------------------------------
// Technology inference rules
// ---------------------------------------------------------------------------

// frameworkToDB maps web frameworks to their most likely database.
var frameworkToDB = map[string]string{
	// PHP ecosystem
	"php": "MySQL", "laravel": "MySQL", "symfony": "MySQL",
	"wordpress": "MySQL", "drupal": "MySQL", "joomla": "MySQL",
	"codeigniter": "MySQL", "yii": "MySQL", "cakephp": "MySQL",
	// Python
	"django": "PostgreSQL", "flask": "PostgreSQL", "fastapi": "PostgreSQL",
	// Java
	"spring": "PostgreSQL", "struts": "Oracle", "hibernate": "PostgreSQL",
	// .NET
	"asp.net": "MSSQL", ".net": "MSSQL", "dotnet": "MSSQL",
	// Ruby
	"rails": "PostgreSQL", "sinatra": "PostgreSQL",
	// Node.js
	"express": "MongoDB", "nextjs": "PostgreSQL", "nestjs": "PostgreSQL",
	// CMS
	"magento": "MySQL", "prestashop": "MySQL", "opencart": "MySQL",
}

// serverToLang maps web servers to their typical backend language.
var serverToLang = map[string]string{
	"apache": "PHP", "iis": "ASP.NET",
	"tomcat": "Java", "jetty": "Java",
	"gunicorn": "Python", "uvicorn": "Python",
	"puma": "Ruby", "unicorn": "Ruby",
}

// tagToDB maps technology tags/infrastructure strings to database types.
var tagToDB = map[string]string{
	"mysql": "MySQL", "mariadb": "MySQL",
	"postgresql": "PostgreSQL", "postgres": "PostgreSQL",
	"mssql": "MSSQL", "sqlserver": "MSSQL",
	"oracle": "Oracle", "sqlite": "SQLite",
	"mongodb": "MongoDB", "redis": "Redis",
}

// ---------------------------------------------------------------------------
// TechStack represents the normalized technology profile of a target
// ---------------------------------------------------------------------------

// TechStack holds the inferred technology stack used by every specialist.
type TechStack struct {
	DB         string                 `json:"db"`
	Server     string                 `json:"server"`
	Lang       string                 `json:"lang"`
	Frameworks []string               `json:"frameworks"`
	WAF        string                 `json:"waf"`
	CDN        string                 `json:"cdn"`
	RawProfile map[string]interface{} `json:"raw_profile"`
}

// DefaultTechStack returns a blank "generic" stack.
func DefaultTechStack() *TechStack {
	return &TechStack{
		DB: "generic", Server: "generic", Lang: "generic",
		RawProfile: map[string]interface{}{},
	}
}

// InferOS returns the likely operating system based on the stack.
func (ts *TechStack) InferOS() string {
	s := strings.ToLower(ts.Server)
	l := strings.ToLower(ts.Lang)
	if strings.Contains(s, "iis") || strings.Contains(l, "asp") || strings.Contains(l, ".net") {
		return "Windows"
	}
	return "Linux"
}

// InferXMLParser suggests the XML parser based on the language.
func (ts *TechStack) InferXMLParser() string {
	parsers := map[string]string{
		"PHP": "libxml2", "Java": "DocumentBuilder/SAX", "Python": "lxml/etree",
		"ASP.NET": "XmlDocument", ".NET": "XmlDocument",
		"Node.js": "xml2js/libxmljs", "Ruby": "Nokogiri/REXML", "Go": "encoding/xml",
	}
	if p, ok := parsers[ts.Lang]; ok {
		return p
	}
	return "Unknown"
}

// ---------------------------------------------------------------------------
// Loading tech profile from the filesystem
// ---------------------------------------------------------------------------

// LoadTechStack reads a tech_profile.json from the report directory
// and normalizes it into an actionable TechStack.
func LoadTechStack(reportDir string) *TechStack {
	if reportDir == "" {
		return DefaultTechStack()
	}

	paths := []string{
		filepath.Join(reportDir, "recon", "tech_profile.json"),
		filepath.Join(reportDir, "tech_profile.json"),
		filepath.Join(reportDir, "recon", "technologies.json"),
	}

	var rawProfile map[string]interface{}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err == nil {
			if json.Unmarshal(data, &rawProfile) == nil {
				break
			}
		}
	}

	if rawProfile == nil {
		return DefaultTechStack()
	}

	return normalizeStack(rawProfile)
}

func getStringSlice(m map[string]interface{}, key string) []string {
	raw, ok := m[key]
	if !ok {
		return nil
	}
	arr, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func normalizeStack(raw map[string]interface{}) *TechStack {
	stack := &TechStack{
		DB: "generic", Server: "generic", Lang: "generic",
		Frameworks: getStringSlice(raw, "frameworks"),
		RawProfile: raw,
	}

	if wafList := getStringSlice(raw, "waf"); len(wafList) > 0 {
		stack.WAF = wafList[0]
	}
	if cdnList := getStringSlice(raw, "cdn"); len(cdnList) > 0 {
		stack.CDN = cdnList[0]
	}

	techTags := toLowerSlice(getStringSlice(raw, "tech_tags"))
	frameworks := toLowerSlice(stack.Frameworks)
	servers := toLowerSlice(getStringSlice(raw, "servers"))
	languages := toLowerSlice(getStringSlice(raw, "languages"))
	infra := toLowerSlice(getStringSlice(raw, "infrastructure"))

	// 1. Direct database detection from tags
	for _, tag := range append(techTags, infra...) {
		for hint, dbType := range tagToDB {
			if strings.Contains(tag, hint) {
				stack.DB = dbType
				goto dbDone
			}
		}
	}
dbDone:

	// 2. Framework -> DB inference
	if stack.DB == "generic" {
		for _, fw := range frameworks {
			for hint, dbType := range frameworkToDB {
				if strings.Contains(fw, hint) {
					stack.DB = dbType
					goto fwDone
				}
			}
		}
	}
fwDone:

	// 3. Server detection
	for _, srv := range servers {
		for _, hint := range []string{"apache", "nginx", "iis", "tomcat", "jetty", "gunicorn", "uvicorn"} {
			if strings.Contains(srv, hint) {
				stack.Server = strings.Title(hint)
				goto srvDone
			}
		}
	}
srvDone:

	// 4. Language detection
	if len(languages) > 0 {
		stack.Lang = strings.Title(languages[0])
	} else if stack.Server != "generic" {
		if lang, ok := serverToLang[strings.ToLower(stack.Server)]; ok && lang != "varies" {
			stack.Lang = lang
		}
	}

	// 5. Framework -> Language fallback
	if stack.Lang == "generic" {
		for _, fw := range frameworks {
			switch {
			case containsAny(fw, "php", "laravel", "symfony", "wordpress"):
				stack.Lang = "PHP"
			case containsAny(fw, "django", "flask", "fastapi"):
				stack.Lang = "Python"
			case containsAny(fw, "spring", "struts", "hibernate"):
				stack.Lang = "Java"
			case containsAny(fw, "asp.net", ".net", "razor"):
				stack.Lang = "ASP.NET"
			case containsAny(fw, "rails", "ruby"):
				stack.Lang = "Ruby"
			case containsAny(fw, "express", "next", "node"):
				stack.Lang = "Node.js"
			default:
				continue
			}
			break
		}
	}

	return stack
}

func toLowerSlice(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strings.ToLower(s)
	}
	return out
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Context-aware "Prime Directive" prompt generation
// ---------------------------------------------------------------------------

// GenerateContextPrompt builds the universal Prime Directive block
// that is prepended to every specialist agent's system prompt.
func GenerateContextPrompt(stack *TechStack) string {
	var b strings.Builder
	b.WriteString("## TARGET TECHNOLOGY STACK\n")
	b.WriteString(fmt.Sprintf("- Database: %s\n", stack.DB))
	b.WriteString(fmt.Sprintf("- Web Server: %s\n", stack.Server))
	b.WriteString(fmt.Sprintf("- Language/Framework: %s\n", stack.Lang))

	if len(stack.Frameworks) > 0 {
		limit := 3
		if len(stack.Frameworks) < limit {
			limit = len(stack.Frameworks)
		}
		b.WriteString(fmt.Sprintf("- Frameworks: %s\n", strings.Join(stack.Frameworks[:limit], ", ")))
	}
	if stack.WAF != "" {
		b.WriteString(fmt.Sprintf("- WAF Detected: %s\n", stack.WAF))
	}

	b.WriteString("\n## STRATEGIC IMPLICATIONS\n")

	// DB-specific
	if stack.DB != "generic" && stack.DB != "Unknown" {
		b.WriteString(fmt.Sprintf("- Focus ONLY on payloads compatible with %s.\n", stack.DB))
		switch stack.DB {
		case "MySQL":
			b.WriteString("- MySQL: Use CONCAT(), LOAD_FILE(), comment variations (-- , #, /**/)\n")
		case "PostgreSQL":
			b.WriteString("- PostgreSQL: Use string_agg(), ||, pg_sleep(), $$ quoting\n")
		case "MSSQL":
			b.WriteString("- MSSQL: Use WAITFOR DELAY, xp_cmdshell, CONVERT(), stacked queries\n")
		case "Oracle":
			b.WriteString("- Oracle: Use UTL_HTTP, DBMS_PIPE, TO_CHAR(), dual table\n")
		case "SQLite":
			b.WriteString("- SQLite: Use sqlite_version(), load_extension(), simple syntax\n")
		}
	} else {
		b.WriteString("- Database type unknown: test multi-database payloads\n")
	}

	// Language-specific
	if stack.Lang != "generic" && stack.Lang != "Unknown" {
		b.WriteString(fmt.Sprintf("- Identify parameter patterns common in %s applications.\n", stack.Lang))
		switch stack.Lang {
		case "PHP":
			b.WriteString("- PHP: Watch for magic_quotes bypass, mysql_real_escape_string issues\n")
		case "ASP.NET":
			b.WriteString("- ASP.NET: Consider parameterized query bypasses, ViewState\n")
		case "Java":
			b.WriteString("- Java: Look for PreparedStatement misuse, Hibernate HQL injection\n")
		case "Python":
			b.WriteString("- Python: Check for raw SQL in Django ORM, Jinja2 SSTI\n")
		case "Node.js":
			b.WriteString("- Node.js: Check for NoSQL injection, eval() misuse\n")
		}
	}

	// WAF
	if stack.WAF != "" {
		b.WriteString(fmt.Sprintf("- WAF PRESENT (%s): Use evasion techniques -- encoding, case mixing, comments\n", stack.WAF))
	}

	return b.String()
}

// GenerateXSSContext generates XSS-specific Prime Directive.
func GenerateXSSContext(stack *TechStack) string {
	var b strings.Builder
	b.WriteString("## TARGET TECHNOLOGY STACK (XSS CONTEXT)\n")
	b.WriteString(fmt.Sprintf("- Web Server: %s\n", stack.Server))
	b.WriteString(fmt.Sprintf("- Backend Language: %s\n", stack.Lang))

	frontends := detectFrontends(stack)
	if len(frontends) > 0 {
		b.WriteString(fmt.Sprintf("- Frontend Frameworks: %s\n", strings.Join(frontends, ", ")))
	}

	b.WriteString("\n## XSS STRATEGIC IMPLICATIONS\n")

	for _, fw := range frontends {
		switch fw {
		case "react":
			b.WriteString("- React: dangerouslySetInnerHTML is primary vector\n")
			b.WriteString("- React: Focus on SSR XSS if Next.js detected\n")
		case "angular":
			b.WriteString("- Angular: bypassSecurityTrust* functions are key vectors\n")
			b.WriteString("- Angular: Template injection via {{ }} interpolation (CSTI overlap)\n")
		case "vue":
			b.WriteString("- Vue: v-html directive is primary vector\n")
			b.WriteString("- Vue: Template injection via {{ }} interpolation\n")
		}
	}

	switch stack.Lang {
	case "PHP":
		b.WriteString("- PHP: Look for echo/print without htmlspecialchars()\n")
	case "Python":
		b.WriteString("- Python: Jinja2 |safe filter, mark_safe() are vectors\n")
	case "Node.js":
		b.WriteString("- Node.js: EJS <%- %> unescaped output, Pug != operator\n")
	case "Java":
		b.WriteString("- Java: JSP scriptlets, EL expressions ${} are vectors\n")
	}

	if stack.WAF != "" {
		b.WriteString(fmt.Sprintf("- WAF PRESENT (%s): Case variation, event handlers, encoding, tag alternatives\n", stack.WAF))
	}

	return b.String()
}

// GenerateSQLiContext generates SQLi-specific Prime Directive.
func GenerateSQLiContext(stack *TechStack) string {
	var b strings.Builder
	b.WriteString("## TARGET TECHNOLOGY STACK (SQLi CONTEXT)\n")
	b.WriteString(fmt.Sprintf("- Database: %s\n", stack.DB))
	b.WriteString(fmt.Sprintf("- Language: %s\n", stack.Lang))

	b.WriteString("\n## SQLi STRATEGIC IMPLICATIONS\n")
	switch stack.DB {
	case "MySQL":
		b.WriteString("- MySQL: UNION SELECT column count, CONCAT(), information_schema\n")
		b.WriteString("- MySQL: Comment variations: -- , #, /**/\n")
	case "PostgreSQL":
		b.WriteString("- PostgreSQL: string_agg(), ||, pg_sleep(), $$ quoting\n")
		b.WriteString("- PostgreSQL: Stacked queries typically work\n")
	case "MSSQL":
		b.WriteString("- MSSQL: WAITFOR DELAY, xp_cmdshell, CONVERT()\n")
		b.WriteString("- MSSQL: Stacked queries for OS command execution\n")
	case "Oracle":
		b.WriteString("- Oracle: UTL_HTTP.REQUEST for OOB, DBMS_PIPE.RECEIVE_MESSAGE for time\n")
	case "SQLite":
		b.WriteString("- SQLite: sqlite_version(), simple syntax, no stacked queries\n")
	default:
		b.WriteString("- Database unknown: test with multi-database payloads\n")
	}

	if stack.WAF != "" {
		b.WriteString(fmt.Sprintf("- WAF (%s): Use inline comments, case mixing, encoding\n", stack.WAF))
	}

	return b.String()
}

// GenerateSSRFContext generates SSRF-specific Prime Directive.
func GenerateSSRFContext(stack *TechStack) string {
	var b strings.Builder
	b.WriteString("## TARGET TECHNOLOGY STACK (SSRF CONTEXT)\n")
	b.WriteString(fmt.Sprintf("- Backend Language: %s\n", stack.Lang))

	clouds := detectCloudProviders(stack)
	if len(clouds) > 0 {
		b.WriteString(fmt.Sprintf("- Cloud Provider: %s\n", strings.Join(clouds, ", ")))
	}

	b.WriteString("\n## SSRF STRATEGIC IMPLICATIONS\n")
	for _, cloud := range clouds {
		switch cloud {
		case "aws":
			b.WriteString("- AWS: Target http://169.254.169.254/latest/meta-data/\n")
			b.WriteString("- AWS: Check for IAM credentials at /iam/security-credentials/\n")
		case "gcp":
			b.WriteString("- GCP: Target http://metadata.google.internal/\n")
			b.WriteString("- GCP: Use Metadata-Flavor: Google header\n")
		case "azure":
			b.WriteString("- Azure: Target http://169.254.169.254/metadata/\n")
			b.WriteString("- Azure: Use Metadata: true header\n")
		}
	}

	if len(clouds) == 0 {
		b.WriteString("- Test internal: 127.0.0.1, localhost, 10.x, 172.16.x, 192.168.x\n")
		b.WriteString("- Test file:// and gopher:// protocols\n")
	}

	switch stack.Lang {
	case "PHP":
		b.WriteString("- PHP: Test gopher://, dict://, expect:// wrappers\n")
	case "Python":
		b.WriteString("- Python: Test file://, dict://, gopher:// via urllib/requests\n")
	case "Java":
		b.WriteString("- Java: Test jar://, netdoc:// protocols\n")
	}

	return b.String()
}

// GenerateRCEContext generates RCE-specific Prime Directive.
func GenerateRCEContext(stack *TechStack) string {
	var b strings.Builder
	osType := stack.InferOS()

	b.WriteString("## TARGET TECHNOLOGY STACK (RCE CONTEXT)\n")
	b.WriteString(fmt.Sprintf("- Backend Language: %s\n", stack.Lang))
	b.WriteString(fmt.Sprintf("- Likely OS: %s\n", osType))

	b.WriteString("\n## RCE STRATEGIC IMPLICATIONS\n")
	if osType == "Linux" {
		b.WriteString("- Linux: Use $(cmd), `cmd`, ; cmd, | cmd, && cmd\n")
		b.WriteString("- Linux: Blind RCE via sleep, ping, curl to callback\n")
	} else {
		b.WriteString("- Windows: Use & cmd, | cmd, %COMSPEC% /c cmd\n")
		b.WriteString("- Windows: Blind RCE via ping -n, timeout /t\n")
	}

	switch stack.Lang {
	case "PHP":
		b.WriteString("- PHP: system(), exec(), passthru(), shell_exec(), popen()\n")
		b.WriteString("- PHP: eval(), assert(), preg_replace with /e modifier\n")
	case "Python":
		b.WriteString("- Python: os.system(), subprocess.*, os.popen()\n")
		b.WriteString("- Python: eval(), exec(), pickle.loads()\n")
	case "Node.js":
		b.WriteString("- Node.js: child_process.exec(), spawn(), fork()\n")
		b.WriteString("- Node.js: eval(), new Function(), vm module\n")
	case "Java":
		b.WriteString("- Java: Runtime.getRuntime().exec(), ProcessBuilder\n")
		b.WriteString("- Java: Deserialization (ysoserial payloads)\n")
	case "Ruby":
		b.WriteString("- Ruby: system(), exec(), `cmd`, %x{cmd}\n")
		b.WriteString("- Ruby: YAML.load() deserialization\n")
	}

	if stack.WAF != "" {
		b.WriteString(fmt.Sprintf("- WAF (%s): Variable substitution (${IFS}), command splitting, base64 encoding\n", stack.WAF))
	}

	return b.String()
}

// GenerateLFIContext generates LFI-specific Prime Directive.
func GenerateLFIContext(stack *TechStack) string {
	var b strings.Builder
	osType := stack.InferOS()

	b.WriteString("## TARGET TECHNOLOGY STACK (LFI CONTEXT)\n")
	b.WriteString(fmt.Sprintf("- Backend Language: %s\n", stack.Lang))
	b.WriteString(fmt.Sprintf("- Likely OS: %s\n", osType))

	b.WriteString("\n## LFI STRATEGIC IMPLICATIONS\n")
	if osType == "Linux" {
		b.WriteString("- Linux: Target /etc/passwd, /etc/shadow\n")
		b.WriteString("- Linux: /proc/self/environ for environment variables\n")
		b.WriteString("- Linux: Log poisoning via /var/log/apache2/access.log\n")
	} else {
		b.WriteString("- Windows: Target C:\\Windows\\win.ini, C:\\Windows\\System32\\drivers\\etc\\hosts\n")
		b.WriteString("- Windows: UNC path for SSRF combo: \\\\attacker\\share\n")
	}

	if stack.Lang == "PHP" {
		b.WriteString("- PHP: Use wrappers (php://filter, php://input, data://)\n")
		b.WriteString("- PHP: php://filter/convert.base64-encode/resource=\n")
		b.WriteString("- PHP: expect:// wrapper for RCE if enabled\n")
	}

	if stack.WAF != "" {
		b.WriteString(fmt.Sprintf("- WAF (%s): Double encoding, null byte, Unicode bypasses\n", stack.WAF))
	}

	return b.String()
}

// GenerateCSTIContext generates CSTI/SSTI-specific Prime Directive.
func GenerateCSTIContext(stack *TechStack) string {
	var b strings.Builder
	b.WriteString("## TARGET TECHNOLOGY STACK (CSTI/SSTI CONTEXT)\n")
	b.WriteString(fmt.Sprintf("- Backend Language: %s\n", stack.Lang))

	engines := detectTemplateEngines(stack)
	if len(engines) > 0 {
		b.WriteString(fmt.Sprintf("- Detected Template Engines: %s\n", strings.Join(engines, ", ")))
	}

	b.WriteString("\n## CSTI/SSTI STRATEGIC IMPLICATIONS\n")
	for _, eng := range engines {
		switch eng {
		case "jinja2":
			b.WriteString("- Jinja2: {{ config }}, {{ self.__class__.__mro__ }}\n")
			b.WriteString("- Jinja2: RCE via __subclasses__(), __globals__\n")
		case "twig":
			b.WriteString("- Twig: {{_self.env.registerUndefinedFilterCallback('exec')}}\n")
		case "freemarker":
			b.WriteString("- FreeMarker: <#assign ex=\"freemarker.template.utility.Execute\"?new()>\n")
		case "erb":
			b.WriteString("- ERB: <%= 7*7 %>, <%= system('id') %>\n")
		case "ejs":
			b.WriteString("- EJS: <%- include('file') %>, <%= 7*7 %>\n")
		}
	}

	return b.String()
}

// GenerateHeaderInjectionContext generates Header Injection-specific Prime Directive.
func GenerateHeaderInjectionContext(stack *TechStack) string {
	var b strings.Builder
	b.WriteString("## TARGET TECHNOLOGY STACK (HEADER INJECTION CONTEXT)\n")
	b.WriteString(fmt.Sprintf("- Web Server: %s\n", stack.Server))

	if stack.CDN != "" {
		b.WriteString(fmt.Sprintf("- CDN: %s\n", stack.CDN))
	}

	b.WriteString("\n## HEADER INJECTION STRATEGIC IMPLICATIONS\n")
	switch strings.ToLower(stack.Server) {
	case "nginx":
		b.WriteString("- Nginx: CRLF in Location header, X-Forwarded-* injection\n")
	case "apache":
		b.WriteString("- Apache: mod_proxy header injection, X-Forwarded-For chain\n")
	case "iis":
		b.WriteString("- IIS: Unicode CRLF variants (%u000d%u000a), ARR proxy headers\n")
	}

	if stack.CDN != "" {
		b.WriteString(fmt.Sprintf("- CDN (%s): Cache poisoning via Host header, X-Forwarded-Host\n", stack.CDN))
	}

	return b.String()
}

// ---------------------------------------------------------------------------
// Helper detection functions
// ---------------------------------------------------------------------------

func detectFrontends(stack *TechStack) []string {
	var detected []string
	hints := make([]string, 0, len(stack.Frameworks))
	for _, fw := range stack.Frameworks {
		hints = append(hints, strings.ToLower(fw))
	}
	if tags := getStringSlice(stack.RawProfile, "tech_tags"); tags != nil {
		hints = append(hints, toLowerSlice(tags)...)
	}

	combined := strings.Join(hints, " ")
	fwMap := map[string][]string{
		"react":   {"react", "reactjs", "next.js", "nextjs", "gatsby"},
		"angular": {"angular", "angularjs"},
		"vue":     {"vue", "vuejs", "vue.js", "nuxt"},
		"jquery":  {"jquery"},
		"svelte":  {"svelte", "sveltekit"},
	}
	for fw, keywords := range fwMap {
		for _, kw := range keywords {
			if strings.Contains(combined, kw) {
				detected = append(detected, fw)
				break
			}
		}
	}
	return detected
}

func detectCloudProviders(stack *TechStack) []string {
	infra := getStringSlice(stack.RawProfile, "infrastructure")
	combined := strings.ToLower(strings.Join(infra, " "))

	var providers []string
	if containsAny(combined, "aws", "amazon", "ec2", "s3", "alb", "elb", "cloudfront") {
		providers = append(providers, "aws")
	}
	if containsAny(combined, "gcp", "google", "gke", "cloud run", "gce") {
		providers = append(providers, "gcp")
	}
	if containsAny(combined, "azure", "microsoft", "aks", "app service") {
		providers = append(providers, "azure")
	}
	return providers
}

func detectTemplateEngines(stack *TechStack) []string {
	hints := toLowerSlice(stack.Frameworks)
	if tags := getStringSlice(stack.RawProfile, "tech_tags"); tags != nil {
		hints = append(hints, toLowerSlice(tags)...)
	}
	combined := strings.Join(hints, " ")

	engineMap := map[string][]string{
		"jinja2":     {"jinja", "jinja2", "flask", "django"},
		"twig":       {"twig", "symfony"},
		"freemarker": {"freemarker", "spring"},
		"thymeleaf":  {"thymeleaf", "spring"},
		"erb":        {"erb", "rails"},
		"ejs":        {"ejs", "express"},
		"pug":        {"pug", "jade"},
		"handlebars": {"handlebars", "hbs"},
		"razor":      {"razor", "asp.net", ".net"},
	}

	var detected []string
	for engine, keywords := range engineMap {
		for _, kw := range keywords {
			if strings.Contains(combined, kw) {
				detected = append(detected, engine)
				break
			}
		}
	}

	// Language fallback
	if len(detected) == 0 {
		langEngines := map[string][]string{
			"Python": {"jinja2"}, "PHP": {"twig"}, "Java": {"freemarker"},
			"Ruby": {"erb"}, "Node.js": {"ejs"}, "ASP.NET": {"razor"},
		}
		if engines, ok := langEngines[stack.Lang]; ok {
			detected = engines
		}
	}

	return detected
}
