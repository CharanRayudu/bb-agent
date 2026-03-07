package server

import (
	"context"
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

// AuthConfig holds JWT signing parameters.
type AuthConfig struct {
	Secret         string
	Issuer         string
	ExpiryDuration time.Duration
}

// DefaultAuthConfig returns a sensible default.
func DefaultAuthConfig(secret string) *AuthConfig {
	if secret == "" {
		secret = "mirage-dev-secret-change-in-production"
	}
	return &AuthConfig{
		Secret:         secret,
		Issuer:         "mirage",
		ExpiryDuration: 24 * time.Hour,
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
// If auth is disabled (e.g. no secret), it passes through as admin.
func JWTAuthMiddleware(cfg *AuthConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		// No auth header -- allow through as anonymous/admin in dev mode
		if authHeader == "" {
			claims := &UserClaims{
				UserID:   "anonymous",
				Username: "anonymous",
				Role:     RoleAdmin,
			}
			ctx := context.WithValue(r.Context(), userContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Bearer token
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

// GenerateAPIKey creates a random API key and returns the plaintext key and its hash.
func GenerateAPIKey() (plaintext string, hash string, err error) {
	bytes := make([]byte, 32)
	if _, err = rand.Read(bytes); err != nil {
		return "", "", err
	}
	plaintext = "mrg_" + hex.EncodeToString(bytes)
	h := sha256.Sum256([]byte(plaintext))
	hash = hex.EncodeToString(h[:])
	return plaintext, hash, nil
}

// HashAPIKey returns the SHA-256 hash of an API key.
func HashAPIKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
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

	// Look up user
	var id, passwordHash, role string
	err := s.db.QueryRow(
		`SELECT id, password_hash, role FROM users WHERE username = $1`,
		req.Username,
	).Scan(&id, &passwordHash, &role)
	if err == sql.ErrNoRows {
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	} else if err != nil {
		log.Printf("Login DB error: %v", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	// In production, use bcrypt. For now, simple hash comparison.
	inputHash := sha256.Sum256([]byte(req.Password))
	if hex.EncodeToString(inputHash[:]) != passwordHash {
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	authCfg := DefaultAuthConfig(s.cfg.JWTSecret)
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

		plaintext, hash, err := GenerateAPIKey()
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
