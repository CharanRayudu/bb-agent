package base

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AuthSession holds credentials and session state for authenticated scanning.
type AuthSession struct {
	Type        string            // "cookie", "bearer", "basic", "api_key", "form_login"
	Cookies     []*http.Cookie
	Headers     map[string]string // Authorization, X-API-Key, etc.
	Username    string
	Password    string
	LoginURL    string
	LoginMethod string
	LoginBody   map[string]string
	IsActive    bool
	LastRefresh time.Time
}

// WithAuth returns a new FuzzClient that injects auth into every request.
func (fc *FuzzClient) WithAuth(session *AuthSession) *FuzzClient {
	return &FuzzClient{
		client:    fc.client,
		baseDelay: fc.baseDelay,
		auth:      session,
	}
}

// injectAuth applies the session's cookies and headers to an outgoing request.
func injectAuth(req *http.Request, session *AuthSession) {
	if session == nil {
		return
	}
	for _, c := range session.Cookies {
		req.AddCookie(c)
	}
	for k, v := range session.Headers {
		req.Header.Set(k, v)
	}
}

// FormLogin performs a form-based login and returns a session with cookies.
func FormLogin(ctx context.Context, loginURL, usernameField, passwordField, username, password string) (*AuthSession, error) {
	if usernameField == "" {
		usernameField = "username"
	}
	if passwordField == "" {
		passwordField = "password"
	}

	formData := url.Values{}
	formData.Set(usernameField, username)
	formData.Set(passwordField, password)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("form login: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")

	// Use a jar-aware client so redirects carry cookies.
	jar := &simpleCookieJar{}
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			// Propagate cookies on redirect.
			for _, c := range jar.cookies {
				r.AddCookie(c)
			}
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("form login: request failed: %w", err)
	}
	defer func() {
		if resp.Body != nil {
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
		}
	}()

	// Collect Set-Cookie headers.
	cookies := resp.Cookies()
	jar.cookies = append(jar.cookies, cookies...)

	if len(cookies) == 0 {
		return nil, fmt.Errorf("form login: no cookies returned (status %d); login may have failed", resp.StatusCode)
	}

	session := &AuthSession{
		Type:        "form_login",
		Cookies:     cookies,
		Headers:     make(map[string]string),
		Username:    username,
		Password:    password,
		LoginURL:    loginURL,
		LoginMethod: http.MethodPost,
		LoginBody: map[string]string{
			usernameField: username,
			passwordField: password,
		},
		IsActive:    true,
		LastRefresh: time.Now(),
	}
	return session, nil
}

// BearerSession creates a bearer token session.
func BearerSession(token string) *AuthSession {
	return &AuthSession{
		Type: "bearer",
		Headers: map[string]string{
			"Authorization": "Bearer " + token,
		},
		IsActive:    true,
		LastRefresh: time.Now(),
	}
}

// CookieSession creates a cookie-based session from a raw cookie string
// (the value of a Cookie: header, e.g. "session=abc123; csrf=xyz").
func CookieSession(rawCookies string) *AuthSession {
	var cookies []*http.Cookie
	// Parse name=value pairs separated by "; ".
	for _, part := range strings.Split(rawCookies, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eqIdx := strings.IndexByte(part, '=')
		if eqIdx < 0 {
			cookies = append(cookies, &http.Cookie{Name: part})
			continue
		}
		cookies = append(cookies, &http.Cookie{
			Name:  strings.TrimSpace(part[:eqIdx]),
			Value: strings.TrimSpace(part[eqIdx+1:]),
		})
	}
	return &AuthSession{
		Type:        "cookie",
		Cookies:     cookies,
		Headers:     make(map[string]string),
		IsActive:    true,
		LastRefresh: time.Now(),
	}
}

// RefreshIfNeeded re-logs in if the session was obtained via form_login and
// is older than 30 minutes.
func (s *AuthSession) RefreshIfNeeded(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if !s.IsActive {
		return fmt.Errorf("session is not active")
	}

	const sessionTTL = 30 * time.Minute
	if time.Since(s.LastRefresh) < sessionTTL {
		return nil
	}

	if s.Type != "form_login" || s.LoginURL == "" {
		// Nothing to refresh for non-form sessions.
		return nil
	}

	usernameField := "username"
	passwordField := "password"
	for k := range s.LoginBody {
		if strings.Contains(strings.ToLower(k), "user") || strings.Contains(strings.ToLower(k), "email") {
			usernameField = k
		}
		if strings.Contains(strings.ToLower(k), "pass") {
			passwordField = k
		}
	}

	fresh, err := FormLogin(ctx, s.LoginURL, usernameField, passwordField, s.Username, s.Password)
	if err != nil {
		return fmt.Errorf("session refresh: %w", err)
	}

	s.Cookies = fresh.Cookies
	s.LastRefresh = time.Now()
	return nil
}

// simpleCookieJar is a minimal cookie jar used only during FormLogin redirects.
type simpleCookieJar struct {
	cookies []*http.Cookie
}
