package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Role represents a user's access level.
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
)

type contextKey string

const userContextKey contextKey = "user"

// UserClaims holds JWT payload.
type UserClaims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     Role   `json:"role"`
	jwt.RegisteredClaims
}

// AuthConfig holds JWT signing parameters and enforcement behavior.
type AuthConfig struct {
	Secret         string
	Issuer         string
	ExpiryDuration time.Duration
	// Required controls what happens when a request has no Authorization
	// header. When true, requests are rejected with 401. When false, the
	// middleware attaches an anonymous viewer identity (NEVER admin) so
	// downstream RequireRole gates still protect privileged endpoints.
	Required bool
}

// DefaultAuthConfig returns a sensible default that never fails open to
// admin. When secret is empty, auth is treated as optional (dev mode) but
// anonymous requests are assigned the viewer role only.
func DefaultAuthConfig(secret string) *AuthConfig {
	required := secret != ""
	if secret == "" {
		secret = "mirage-dev-secret-change-in-production"
		log.Println("[AUTH] WARNING: JWT_SECRET not set -- using a development-only signing key. Do NOT expose this server publicly.")
	}
	return &AuthConfig{
		Secret:         secret,
		Issuer:         "mirage",
		ExpiryDuration: 24 * time.Hour,
		Required:       required,
	}
}

// GenerateToken creates a signed JWT for a user.
func GenerateToken(cfg *AuthConfig, userID, username string, role Role) (string, error) {
	claims := UserClaims{
		UserID:   userID,
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    cfg.Issuer,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(cfg.ExpiryDuration)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.Secret))
}

// ValidateToken parses and validates a JWT string.
func ValidateToken(cfg *AuthConfig, tokenStr string) (*UserClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &UserClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(cfg.Secret), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*UserClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}
	return claims, nil
}

// JWTAuthMiddleware validates the Authorization header.
//
// Security contract:
//   - A valid Bearer token attaches the signed claims.
//   - An invalid/expired token is always rejected with 401.
//   - A missing header is rejected with 401 when cfg.Required is true;
//     otherwise the request is attached with the *viewer* role so that
//     RequireRole(Operator) / RequireRole(Admin) still return 403.
//   - No code path ever elevates an anonymous request to admin.
func JWTAuthMiddleware(cfg *AuthConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		if authHeader == "" {
			if cfg.Required {
				http.Error(w, `{"error":"authorization header required"}`, http.StatusUnauthorized)
				return
			}
			claims := &UserClaims{
				UserID:   "anonymous",
				Username: "anonymous",
				Role:     RoleViewer,
			}
			ctx := context.WithValue(r.Context(), userContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
			http.Error(w, `{"error":"invalid authorization header"}`, http.StatusUnauthorized)
			return
		}

		claims, err := ValidateToken(cfg, parts[1])
		if err != nil {
			http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole returns middleware that ensures the user has the minimum required role.
func RequireRole(minRole Role) func(http.Handler) http.Handler {
	hierarchy := map[Role]int{
		RoleViewer:   1,
		RoleOperator: 2,
		RoleAdmin:    3,
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetUserFromContext(r.Context())
			if claims == nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			if hierarchy[claims.Role] < hierarchy[minRole] {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// GetUserFromContext extracts user claims from the request context.
func GetUserFromContext(ctx context.Context) *UserClaims {
	claims, _ := ctx.Value(userContextKey).(*UserClaims)
	return claims
}

// GenerateAPIKey creates a random API key and returns the plaintext key and
// its deterministic lookup hash. The lookup hash is a keyed HMAC-SHA256
// using the server's signing secret, so rainbow tables against the DB
// column do not recover keys even if the DB is leaked. Callers MUST pass
// the same secret to HashAPIKey when checking later.
func GenerateAPIKey(secret string) (plaintext string, hash string, err error) {
	bytes := make([]byte, 32)
	if _, err = rand.Read(bytes); err != nil {
		return "", "", err
	}
	plaintext = "mrg_" + hex.EncodeToString(bytes)
	hash = HashAPIKey(plaintext, secret)
	return plaintext, hash, nil
}

// HashAPIKey returns the HMAC-SHA256 of the key under the given secret.
// An empty secret degrades to plain SHA-256 — callers should always pass a
// non-empty secret in production.
func HashAPIKey(key, secret string) string {
	if secret == "" {
		h := sha256.Sum256([]byte(key))
		return hex.EncodeToString(h[:])
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(key))
	return hex.EncodeToString(mac.Sum(nil))
}

// ============ Auth HTTP Handlers ============

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Username == "" || req.Password == "" {
		http.Error(w, `{"error":"username and password are required"}`, http.StatusBadRequest)
		return
	}

	var id, passwordHash, role string
	err := s.db.QueryRow(
		`SELECT id, password_hash, role FROM users WHERE username = $1`,
		req.Username,
	).Scan(&id, &passwordHash, &role)
	if err == sql.ErrNoRows {
		// Uniform error + constant-time dummy work to resist user enumeration
		// and timing oracles.
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$10$abcdefghijklmnopqrstuuDy9OdzQpJpX1Gw1JqB/5QJdV1hEe0mKy"), []byte(req.Password))
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	} else if err != nil {
		log.Printf("Login DB error: %v", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	authCfg := DefaultAuthConfig(s.cfg.JWTSecret)
	authCfg.Required = s.cfg.AuthRequired
	token, err := GenerateToken(authCfg, id, req.Username, Role(role))
	if err != nil {
		http.Error(w, `{"error":"failed to generate token"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":    token,
		"username": req.Username,
		"role":     role,
	})
}

// authGate wraps a handler with JWT authentication and a minimum-role
// requirement. When cfg.AuthRequired is false (dev mode, default), it is a
// no-op so tests and local usage continue to work. When true, requests
// without a valid Bearer token matching the minimum role receive 401/403.
func (s *Server) authGate(minRole Role, h http.HandlerFunc) http.HandlerFunc {
	if s == nil || s.cfg == nil || !s.cfg.AuthRequired {
		return h
	}
	authCfg := DefaultAuthConfig(s.cfg.JWTSecret)
	authCfg.Required = true
	chained := JWTAuthMiddleware(authCfg, RequireRole(minRole)(http.HandlerFunc(h)))
	return chained.ServeHTTP
}

// HashPassword returns a bcrypt hash suitable for storing in users.password_hash.
func HashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

func (s *Server) handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		rows, err := s.db.Query(`SELECT id, name, role, created_at, last_used FROM api_keys ORDER BY created_at DESC`)
		if err != nil {
			http.Error(w, `{"error":"failed to list keys"}`, http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		type keyInfo struct {
			ID        string     `json:"id"`
			Name      string     `json:"name"`
			Role      string     `json:"role"`
			CreatedAt time.Time  `json:"created_at"`
			LastUsed  *time.Time `json:"last_used"`
		}
		var keys []keyInfo
		for rows.Next() {
			var k keyInfo
			if rows.Scan(&k.ID, &k.Name, &k.Role, &k.CreatedAt, &k.LastUsed) == nil {
				keys = append(keys, k)
			}
		}
		if keys == nil {
			keys = []keyInfo{}
		}
		json.NewEncoder(w).Encode(keys)

	case http.MethodPost:
		var req struct {
			Name string `json:"name"`
			Role string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
			return
		}
		if req.Name == "" {
			req.Name = "unnamed"
		}
		if req.Role == "" {
			req.Role = "operator"
		}

		plaintext, hash, err := GenerateAPIKey(s.cfg.JWTSecret)
		if err != nil {
			http.Error(w, `{"error":"failed to generate key"}`, http.StatusInternalServerError)
			return
		}

		claims := GetUserFromContext(r.Context())
		createdBy := ""
		if claims != nil {
			createdBy = claims.Username
		}

		_, err = s.db.Exec(
			`INSERT INTO api_keys (name, key_hash, role, created_by) VALUES ($1, $2, $3, $4)`,
			req.Name, hash, req.Role, createdBy,
		)
		if err != nil {
			http.Error(w, `{"error":"failed to store key"}`, http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]string{
			"key":  plaintext,
			"name": req.Name,
			"role": req.Role,
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
