package agent

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// ExportBurpSuiteXML converts findings to Burp Suite issues XML format.
func ExportBurpSuiteXML(findings []*Finding) string {
	var sb strings.Builder

	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	sb.WriteString("<!DOCTYPE issues [\n")
	sb.WriteString("  <!ELEMENT issues (issue*)>\n")
	sb.WriteString("  <!ATTLIST issues burpVersion CDATA \"\">\n")
	sb.WriteString("  <!ATTLIST issues exportTime CDATA \"\">\n")
	sb.WriteString("  <!ELEMENT issue (serialNumber,type,name,host,path,location,severity,confidence,issueBackground,remediationBackground,requestresponse*)>\n")
	sb.WriteString("]>\n")
	sb.WriteString(fmt.Sprintf(`<issues burpVersion="2024.1" exportTime="%s">`+"\n",
		time.Now().UTC().Format("Mon Jan 02 15:04:05 MST 2006")))

	for i, f := range findings {
		serialNum := fmt.Sprintf("%d%06d", time.Now().Unix(), i+1)
		burpTypeID := burpIssueTypeID(f.Type)
		host, path := splitHostPath(f.URL)
		severity := mapBurpSeverity(f.Severity)
		confidence := mapBurpConfidence(f.Confidence)
		background := burpIssueBackground(f.Type)
		remediation := burpRemediationBackground(f.Type)

		sb.WriteString("  <issue>\n")
		sb.WriteString(fmt.Sprintf("    <serialNumber>%s</serialNumber>\n", xmlEscape(serialNum)))
		sb.WriteString(fmt.Sprintf("    <type>%s</type>\n", xmlEscape(burpTypeID)))
		sb.WriteString(fmt.Sprintf("    <name>%s</name>\n", xmlEscape(f.Type)))
		sb.WriteString(fmt.Sprintf("    <host ip=\"\">%s</host>\n", xmlEscape(host)))
		sb.WriteString(fmt.Sprintf("    <path>%s</path>\n", xmlEscape(path)))

		location := path
		if f.Parameter != "" {
			location = fmt.Sprintf("%s [%s parameter]", path, f.Parameter)
		}
		sb.WriteString(fmt.Sprintf("    <location>%s</location>\n", xmlEscape(location)))
		sb.WriteString(fmt.Sprintf("    <severity>%s</severity>\n", xmlEscape(severity)))
		sb.WriteString(fmt.Sprintf("    <confidence>%s</confidence>\n", xmlEscape(confidence)))
		sb.WriteString(fmt.Sprintf("    <issueBackground>%s</issueBackground>\n", xmlEscape(background)))
		sb.WriteString(fmt.Sprintf("    <remediationBackground>%s</remediationBackground>\n", xmlEscape(remediation)))

		// Request/response section
		sb.WriteString("    <requestresponse>\n")
		sb.WriteString("      <request base64=\"true\">")
		reqStr := buildBurpRequest(f)
		sb.WriteString(base64.StdEncoding.EncodeToString([]byte(reqStr)))
		sb.WriteString("</request>\n")

		respStr := buildBurpResponse(f)
		sb.WriteString("      <response base64=\"true\">")
		sb.WriteString(base64.StdEncoding.EncodeToString([]byte(respStr)))
		sb.WriteString("</response>\n")
		sb.WriteString("    </requestresponse>\n")

		sb.WriteString("  </issue>\n")
	}

	sb.WriteString("</issues>\n")
	return sb.String()
}

// burpIssueTypeID returns a numeric type ID mimicking Burp's internal type codes.
func burpIssueTypeID(vulnType string) string {
	key := strings.ToLower(strings.TrimSpace(vulnType))
	switch {
	case strings.Contains(key, "xss"):
		return "2097920"
	case strings.Contains(key, "sqli") || strings.Contains(key, "sql injection"):
		return "1049088"
	case strings.Contains(key, "ssrf"):
		return "1048832"
	case strings.Contains(key, "lfi") || strings.Contains(key, "local file"):
		return "1048580"
	case strings.Contains(key, "rce") || strings.Contains(key, "remote code"):
		return "1049344"
	case strings.Contains(key, "ssti") || strings.Contains(key, "template injection"):
		return "1049600"
	case strings.Contains(key, "xxe"):
		return "1049856"
	case strings.Contains(key, "idor"):
		return "5244416"
	case strings.Contains(key, "jwt"):
		return "6291456"
	case strings.Contains(key, "file upload"):
		return "1049112"
	case strings.Contains(key, "open redirect"):
		return "2098688"
	case strings.Contains(key, "cors"):
		return "6291968"
	case strings.Contains(key, "csrf"):
		return "2098432"
	case strings.Contains(key, "log4shell"):
		return "1049900"
	case strings.Contains(key, "header injection"):
		return "2098176"
	default:
		return "134217728"
	}
}

// mapBurpSeverity maps internal severity strings to Burp Suite severity labels.
func mapBurpSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "High" // Burp uses High as its maximum label
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	default:
		return "Information"
	}
}

// mapBurpConfidence maps a confidence float (0-1) to Burp's confidence labels.
func mapBurpConfidence(confidence float64) string {
	switch {
	case confidence >= 0.9:
		return "Certain"
	case confidence >= 0.7:
		return "Firm"
	default:
		return "Tentative"
	}
}

// burpIssueBackground returns a standard description for the issue type.
func burpIssueBackground(vulnType string) string {
	rem := RemediationFor(vulnType)
	return rem.Summary
}

// burpRemediationBackground returns remediation steps as a single string.
func burpRemediationBackground(vulnType string) string {
	rem := RemediationFor(vulnType)
	if len(rem.Steps) == 0 {
		return rem.Summary
	}
	var parts []string
	for i, step := range rem.Steps {
		parts = append(parts, fmt.Sprintf("%d. %s", i+1, step))
	}
	return strings.Join(parts, " ")
}

// buildBurpRequest builds a synthetic HTTP request string for evidence.
func buildBurpRequest(f *Finding) string {
	method := strings.ToUpper(strings.TrimSpace(f.Method))
	if method == "" {
		method = "GET"
	}

	u, err := url.Parse(f.URL)
	if err != nil {
		return fmt.Sprintf("%s / HTTP/1.1\r\nHost: unknown\r\n\r\n", method)
	}

	path := u.Path
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path = path + "?" + u.RawQuery
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path))
	sb.WriteString(fmt.Sprintf("Host: %s\r\n", u.Host))
	sb.WriteString("User-Agent: Mirage Security Scanner\r\n")
	sb.WriteString("Accept: */*\r\n")

	if method == "POST" && f.Parameter != "" && f.Payload != "" {
		body := url.QueryEscape(f.Parameter) + "=" + url.QueryEscape(f.Payload)
		sb.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
		sb.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
		sb.WriteString("\r\n")
		sb.WriteString(body)
	} else {
		sb.WriteString("\r\n")
	}

	return sb.String()
}

// buildBurpResponse builds a synthetic HTTP response string from evidence.
func buildBurpResponse(f *Finding) string {
	statusCode := 200
	statusText := "OK"
	body := ""

	if f.Evidence != nil {
		if sc, ok := f.Evidence["status_code"]; ok {
			switch v := sc.(type) {
			case int:
				statusCode = v
			case float64:
				statusCode = int(v)
			}
		}
		if b, ok := f.Evidence["body"].(string); ok {
			body = b
		}
	}

	if statusCode == 0 {
		statusCode = 200
	}

	switch statusCode {
	case 200:
		statusText = "OK"
	case 301:
		statusText = "Moved Permanently"
	case 302:
		statusText = "Found"
	case 400:
		statusText = "Bad Request"
	case 403:
		statusText = "Forbidden"
	case 404:
		statusText = "Not Found"
	case 500:
		statusText = "Internal Server Error"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\r\n", statusCode, statusText))
	sb.WriteString("Content-Type: text/html; charset=utf-8\r\n")
	sb.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	sb.WriteString("\r\n")
	sb.WriteString(body)
	return sb.String()
}

// splitHostPath splits a URL into scheme+host and path components.
func splitHostPath(rawURL string) (host, path string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL, "/"
	}
	host = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	path = u.Path
	if path == "" {
		path = "/"
	}
	return host, path
}

// xmlEscape escapes special XML characters in a string.
func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
}
