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
}

// NewFuzzClient creates a fuzz client with a 10s timeout, TLS skip.
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

// Baseline measures a clean response for timing comparison.
func (fc *FuzzClient) Baseline(ctx context.Context, targetURL string) time.Duration {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return 0
	}
	resp, err := fc.client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 512*1024))
	return time.Since(start)
}

// ProbeGET sends a GET request substituting payload into a query parameter.
// paramName: the parameter to inject (e.g. "q", "id"). If empty, appends as ?inject=payload.
func (fc *FuzzClient) ProbeGET(ctx context.Context, targetURL, paramName, payload string) ProbeResult {
	injectedURL := injectQueryParam(targetURL, paramName, payload)
	return fc.doRequest(ctx, http.MethodGet, injectedURL, "", "")
}

// ProbePOST sends a POST with payload in a form field.
func (fc *FuzzClient) ProbePOST(ctx context.Context, targetURL, paramName, payload string) ProbeResult {
	if paramName == "" {
		paramName = "inject"
	}
	return fc.doRequest(ctx, http.MethodPost, targetURL, paramName, payload)
}

// ProbeURL sends a GET with the entire URL replaced by payload (for SSRF).
func (fc *FuzzClient) ProbeURL(ctx context.Context, targetURL, paramName, payloadURL string) ProbeResult {
	injectedURL := injectQueryParam(targetURL, paramName, payloadURL)
	return fc.doRequest(ctx, http.MethodGet, injectedURL, "", "")
}

// doRequest executes an HTTP request and returns a ProbeResult.
func (fc *FuzzClient) doRequest(ctx context.Context, method, targetURL, postParam, postValue string) ProbeResult {
	var req *http.Request
	var err error

	if method == http.MethodPost && postParam != "" {
		formData := url.Values{}
		formData.Set(postParam, postValue)
		body := strings.NewReader(formData.Encode())
		req, err = http.NewRequestWithContext(ctx, method, targetURL, body)
		if err != nil {
			return ProbeResult{Error: err}
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req, err = http.NewRequestWithContext(ctx, method, targetURL, nil)
		if err != nil {
			return ProbeResult{Error: err}
		}
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")

	start := time.Now()
	resp, err := fc.client.Do(req)
	duration := time.Since(start)

	if err != nil {
		return ProbeResult{Error: err, Duration: duration}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	bodyStr := string(bodyBytes)

	result := ProbeResult{
		StatusCode: resp.StatusCode,
		Body:       bodyStr,
		Headers:    resp.Header,
		Duration:   duration,
	}

	// Flag timing anomaly if response took > baseline + 4s
	if fc.baseDelay > 0 && duration > fc.baseDelay+4*time.Second {
		result.TimingAnomaly = true
	} else if fc.baseDelay == 0 && duration > 4*time.Second {
		// No baseline set; flag anything over 4s
		result.TimingAnomaly = true
	}

	return result
}

// injectQueryParam injects payload into the named query parameter, or adds inject=payload if empty.
func injectQueryParam(rawURL, paramName, payload string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := parsed.Query()
	if paramName == "" {
		paramName = "inject"
	}
	q.Set(paramName, payload)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

// SetBaseline stores a measured baseline duration for timing comparisons.
func (fc *FuzzClient) SetBaseline(d time.Duration) {
	fc.baseDelay = d
}

// DetectReflection checks if payload appears verbatim in response body.
func DetectReflection(body, payload string) bool {
	if payload == "" {
		return false
	}
	return strings.Contains(body, payload)
}

// DetectXSSExecution checks for unescaped XSS indicators in body after reflection.
func DetectXSSExecution(body, payload string) bool {
	if !DetectReflection(body, payload) {
		return false
	}
	lower := strings.ToLower(body)
	return strings.Contains(lower, "<script") ||
		strings.Contains(lower, "onerror=") ||
		strings.Contains(lower, "onload=") ||
		strings.Contains(lower, "alert(")
}

var (
	mysqlErrorRe = regexp.MustCompile(`(?i)(you have an error in your sql syntax|mysql_fetch|mysql_num_rows|supplied argument is not a valid mysql|Warning: mysql_|com\.mysql\.jdbc\.exceptions)`)
	pgErrorRe    = regexp.MustCompile(`(?i)(pg_query\(\)|pg_exec\(\)|PostgreSQL.*ERROR|ERROR:.*syntax error|org\.postgresql\.util\.PSQLException|unterminated quoted string at or near)`)
	mssqlErrorRe = regexp.MustCompile(`(?i)(Microsoft OLE DB Provider for SQL|Unclosed quotation mark after the character string|SqlException|System\.Data\.SqlClient\.SqlException|Incorrect syntax near|ODBC SQL Server Driver)`)
	oracleErrorRe = regexp.MustCompile(`(?i)(ORA-\d{5}|oracle\.jdbc\.driver|quoted string not properly terminated)`)
	sqliteErrorRe = regexp.MustCompile(`(?i)(SQLite\/JDBCDriver|SQLite\.Exception|System\.Data\.SQLite|sqlite3\.OperationalError|unrecognized token:)`)
)

// DetectSQLError matches MySQL/PG/MSSQL/Oracle/SQLite error strings.
// Returns (found bool, dbtype string).
func DetectSQLError(body string) (bool, string) {
	switch {
	case mysqlErrorRe.MatchString(body):
		return true, "mysql"
	case pgErrorRe.MatchString(body):
		return true, "postgresql"
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

var (
	passwdRe    = regexp.MustCompile(`root:x?:0:0`)
	winIniRe    = regexp.MustCompile(`(?i)\[boot loader\]`)
)

// DetectPathTraversal checks for /etc/passwd or Windows boot.ini signatures.
func DetectPathTraversal(body string) bool {
	return passwdRe.MatchString(body) || winIniRe.MatchString(body)
}

var (
	awsMetaRe  = regexp.MustCompile(`(?i)(ami-id|instance-id|instance-type|local-ipv4|security-credentials)`)
	gcpMetaRe  = regexp.MustCompile(`(?i)(computeMetadata|project-id|serviceAccounts)`)
	linkLocalRe = regexp.MustCompile(`169\.254\.169\.254`)
)

// DetectSSRFResponse checks for cloud metadata indicators echoed back.
func DetectSSRFResponse(body string) bool {
	return awsMetaRe.MatchString(body) ||
		gcpMetaRe.MatchString(body) ||
		linkLocalRe.MatchString(body)
}
