package auth

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool" // 🆕
)

type contextKey string

const identityKey contextKey = "identity"

// Identity is placed in the request context by IdentityMiddleware.
type Identity struct {
	UserID    string // registered user (empty for guests)
	InstallID string // guest install id (empty for registered users)
	IsAdmin   bool
}

func (i Identity) IsGuest() bool     { return i.UserID == "" && i.InstallID != "" }
func (i Identity) IsUser() bool      { return i.UserID != "" }
func (i Identity) HasIdentity() bool { return i.UserID != "" || i.InstallID != "" }

// OwnerKey returns a stable key for logging / audit.
func (i Identity) OwnerKey() string {
	if i.UserID != "" {
		return "user:" + i.UserID
	}
	if i.InstallID != "" {
		return "install:" + i.InstallID
	}
	return ""
}

// ------------------------------------------------------------------
// IdentityMiddleware
// Reads (a) Authorization: Bearer <jwt>  -> registered user
//
//	(b) X-Install-ID: <uuid>         -> guest (auto-created in DB)
//
// Never rejects; it just populates the context. Use Require* wrappers
// to enforce.
// ------------------------------------------------------------------
func IdentityMiddleware(jwtSvc *JWTService, pool *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var ident Identity

			// (a) JWT — registered user
			if authz := r.Header.Get("Authorization"); strings.HasPrefix(authz, "Bearer ") {
				token := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
				if claims, err := jwtSvc.Verify(token); err == nil {
					ident.UserID = claims.UserID
					ident.IsAdmin = claims.Role == "admin"
				}
			}

			// (b) X-Install-ID — guest (auto-create if missing)
			if installID := strings.TrimSpace(r.Header.Get("X-Install-ID")); installID != "" {
				if len(installID) <= 64 {
					ident.InstallID = installID

					// ✅ Auto-create / update last_seen_at (fire-and-forget)
					if pool != nil {
						_, _ = pool.Exec(r.Context(), `
              INSERT INTO anonymous_installs (install_id, last_seen_at)
              VALUES ($1, NOW())
              ON CONFLICT (install_id)
              DO UPDATE SET last_seen_at = NOW()
            `, installID)
					}
				}
			}

			ctx := context.WithValue(r.Context(), identityKey, ident)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetIdentity extracts Identity from the request context.
func GetIdentity(r *http.Request) Identity {
	if v := r.Context().Value(identityKey); v != nil {
		if ident, ok := v.(Identity); ok {
			return ident
		}
	}
	return Identity{}
}

// ------------------------------------------------------------------
// Route guards
// ------------------------------------------------------------------

// RequireIdentity allows either a registered user or a guest.
func RequireIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !GetIdentity(r).HasIdentity() {
			writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireUser allows only registered users (no guests).
func RequireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !GetIdentity(r).IsUser() {
			writeJSONError(w, http.StatusForbidden, "login_required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireAdmin allows only users with role='admin'.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ident := GetIdentity(r)
		if !ident.IsUser() || !ident.IsAdmin {
			writeJSONError(w, http.StatusForbidden, "admin_required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ------------------------------------------------------------------
// Helper
// ------------------------------------------------------------------

func writeJSONError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

// ------------------------------------------------------------------
// Rate limiting (in-memory, per-IP)
// ------------------------------------------------------------------

type rateBucket struct {
	count   int
	resetAt time.Time
}

type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*rateBucket
	limit   int
	window  time.Duration
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		buckets: make(map[string]*rateBucket),
		limit:   limit,
		window:  window,
	}
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		for range ticker.C {
			rl.mu.Lock()
			now := time.Now()
			for k, b := range rl.buckets {
				if now.After(b.resetAt) {
					delete(rl.buckets, k)
				}
			}
			rl.mu.Unlock()
		}
	}()
	return rl
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[key]
	if !ok || now.After(b.resetAt) {
		rl.buckets[key] = &rateBucket{count: 1, resetAt: now.Add(rl.window)}
		return true
	}
	if b.count >= rl.limit {
		return false
	}
	b.count++
	return true
}

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !rl.Allow(ip) {
			writeJSONError(w, http.StatusTooManyRequests, "rate_limited")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.IndexByte(xff, ','); idx > 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ------------------------------------------------------------------
// Request logger — logs every incoming request with timing
// ------------------------------------------------------------------

func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		rw := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)

		ident := GetIdentity(r)
		owner := ident.OwnerKey()
		if owner == "" {
			owner = "anon"
		}

		log.Printf("[HTTP] %s %s | %s | %d | %s",
			r.Method,
			r.URL.Path,
			owner,
			rw.status,
			time.Since(start).Round(time.Millisecond),
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}
