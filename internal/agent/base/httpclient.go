package base

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ProbeResult holds the outcome of a single HTTP probe.
type ProbeResult struct {
	StatusCode     int
	Body           string
	Headers        http.Header
	Duration       time.Duration
	Error          error
	ReflectedIn    string // "body", "header", or ""
	ErrorSignature string // e.g. "mysql_error", "pg_error", "mssql_error"
	TimingAnomaly  bool   // true if response took > baseline + 4s
}

// FuzzClient sends HTTP probes for vulnerability testing.
type FuzzClient struct {
	client    *http.Client
	baseDelay time.Duration // baseline timing for time-based detection
	auth      *AuthSession  // optional authenticated session
}

// NewFuzzClient creates a fuzz client with a 10s timeout and TLS verification disabled.
func NewFuzzClient() *FuzzClient {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	redirectCount := 0
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			redirectCount++
			if redirectCount >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	return &FuzzClient{client: client}
}

// readBody reads at most 512KB from the response body.
func readBody(resp *http.Response) string {
	if resp == nil || resp.Body == nil {
		return ""
	}
	defer resp.Body.Close()
	lr := io.LimitReader(resp.Body, 512*1024)
	b, _ := io.ReadAll(lr)
	return string(b)
}

// ProbeGET sends a GET request substituting payload into a query parameter.
// If paramName is empty, appends as ?inject=payload.
func (fc *FuzzClient) ProbeGET(ctx context.Context, targetURL, paramName, payload string) ProbeResult {
	probeURL := injectParam(targetURL, paramName, payload)

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return ProbeResult{Error: err, Duration: time.Since(start)}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")
	injectAuth(req, fc.auth)

	resp, err := fc.client.Do(req)
	dur := time.Since(start)
	if err != nil {
		return ProbeResult{Error: err, Duration: dur}
	}

	body := readBody(resp)
	result := ProbeResult{
		StatusCode: resp.StatusCode,
		Body:       body,
		Headers:    resp.Header,
		Duration:   dur,
	}
	result.TimingAnomaly = fc.baseDelay > 0 && dur > fc.baseDelay+4*time.Second
	return result
}

// ProbePOST sends a POST with payload in a form field.
func (fc *FuzzClient) ProbePOST(ctx context.Context, targetURL, paramName, payload string) ProbeResult {
	if paramName == "" {
		paramName = "inject"
	}
	formData := url.Values{}
	formData.Set(paramName, payload)

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return ProbeResult{Error: err, Duration: time.Since(start)}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")
	injectAuth(req, fc.auth)

	resp, err := fc.client.Do(req)
	dur := time.Since(start)
	if err != nil {
		return ProbeResult{Error: err, Duration: dur}
	}

	body := readBody(resp)
	result := ProbeResult{
		StatusCode: resp.StatusCode,
		Body:       body,
		Headers:    resp.Header,
		Duration:   dur,
	}
	result.TimingAnomaly = fc.baseDelay > 0 && dur > fc.baseDelay+4*time.Second
	return result
}

// ProbeURL sends a GET with the entire URL replaced by payloadURL (for SSRF).
// The payloadURL is injected as the value of paramName in the targetURL.
func (fc *FuzzClient) ProbeURL(ctx context.Context, targetURL, paramName, payloadURL string) ProbeResult {
	return fc.ProbeGET(ctx, targetURL, paramName, payloadURL)
}

// Baseline measures a clean response for timing comparison.
func (fc *FuzzClient) Baseline(ctx context.Context, targetURL string) time.Duration {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")
	injectAuth(req, fc.auth)
	resp, err := fc.client.Do(req)
	dur := time.Since(start)
	if err != nil {
		return 0
	}
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	fc.baseDelay = dur
	return dur
}

// injectParam builds a URL with the given param set to payload.
func injectParam(targetURL, paramName, payload string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		// Fallback: simple concatenation
		if paramName == "" {
			paramName = "inject"
		}
		sep := "?"
		if strings.Contains(targetURL, "?") {
			sep = "&"
		}
		return targetURL + sep + url.QueryEscape(paramName) + "=" + url.QueryEscape(payload)
	}
	if paramName == "" {
		paramName = "inject"
	}
	q := u.Query()
	q.Set(paramName, payload)
	u.RawQuery = q.Encode()
	return u.String()
}

// DetectReflection checks if payload appears verbatim in the response body.
func DetectReflection(body, payload string) bool {
	if payload == "" {
		return false
	}
	return strings.Contains(body, payload)
}

// DetectXSSExecution checks for unescaped XSS execution markers in the body.
func DetectXSSExecution(body, payload string) bool {
	if !DetectReflection(body, payload) {
		return false
	}
	lower := strings.ToLower(body)
	return strings.Contains(lower, "<script") ||
		strings.Contains(lower, "onerror=") ||
		strings.Contains(lower, "alert(")
}

var (
	mysqlErrorRe = regexp.MustCompile(`(?i)(you have an error in your sql syntax|mysql_fetch|supplied argument is not a valid mysql|mysql_numrows|call to undefined function mysql)`)
	pgErrorRe    = regexp.MustCompile(`(?i)(pg_query\(\)|supplied argument is not a valid postgresql|unterminated quoted string at|pg_exec\(\)|error:.*syntax error at or near|postgresql.*error)`)
	mssqlErrorRe = regexp.MustCompile(`(?i)(microsoft sql server|syntax error converting|unclosed quotation mark|incorrect syntax near|sql server.*driver|odbc.*sql server)`)
	oracleErrorRe = regexp.MustCompile(`(?i)(ora-\d{4,5}|oracle.*error|quoted string not properly terminated)`)
	sqliteErrorRe = regexp.MustCompile(`(?i)(sqlite_error|sqlite3.*error|unrecognized token:)`)
)

// DetectSQLError performs regex matching for database error strings.
// Returns (found, dbtype) where dbtype is "mysql", "pg", "mssql", "oracle", "sqlite", or "".
func DetectSQLError(body string) (bool, string) {
	switch {
	case mysqlErrorRe.MatchString(body):
		return true, "mysql"
	case pgErrorRe.MatchString(body):
		return true, "pg"
	case mssqlErrorRe.MatchString(body):
		return true, "mssql"
	case oracleErrorRe.MatchString(body):
		return true, "oracle"
	case sqliteErrorRe.MatchString(body):
		return true, "sqlite"
	default:
		return false, ""
	}
}

// DetectPathTraversal checks for path traversal success markers in the body.
func DetectPathTraversal(body string) bool {
	return strings.Contains(body, "root:x:0:0") ||
		strings.Contains(body, "[boot loader]") ||
		strings.Contains(body, "[operating systems]")
}

// DetectSSRFResponse checks for cloud/metadata content echoed back in the response.
func DetectSSRFResponse(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "ami-id") ||
		strings.Contains(lower, "instance-id") ||
		strings.Contains(lower, "computemetadata") ||
		strings.Contains(lower, "169.254.169.254") ||
		strings.Contains(lower, "iam/security-credentials")
}
