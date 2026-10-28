package handlers

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/piumyomin/vpn-backend/internal/auth"
)

type EntitlementHandler struct {
	db *pgxpool.Pool
}

func NewEntitlementHandler(db *pgxpool.Pool) *EntitlementHandler {
	return &EntitlementHandler{db: db}
}

type entitlementResponse struct {
	Active           bool       `json:"active"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	RemainingSeconds int        `json:"remaining_seconds"`
	GrantedBy        string     `json:"granted_by,omitempty"`
}

// GET /api/entitlement
// Guest (X-Install-ID) သို့မဟုတ် User (JWT) နှစ်မျိုးလုံး ရ
func (h *EntitlementHandler) Get(w http.ResponseWriter, r *http.Request) {
	ident := auth.GetIdentity(r)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var (
		expiresAt time.Time
		grantedBy string
		err       error
	)

	if ident.IsUser() {
		err = h.db.QueryRow(ctx, `
      SELECT expires_at, granted_by
      FROM entitlements
      WHERE user_id = $1 AND expires_at > NOW()
      ORDER BY expires_at DESC LIMIT 1
    `, ident.UserID).Scan(&expiresAt, &grantedBy)
	} else {
		err = h.db.QueryRow(ctx, `
      SELECT e.expires_at, e.granted_by
      FROM entitlements e
      JOIN anonymous_installs a ON a.id = e.install_id
      WHERE a.install_id = $1 AND e.expires_at > NOW()
      ORDER BY e.expires_at DESC LIMIT 1
    `, ident.InstallID).Scan(&expiresAt, &grantedBy)
	}

	if errors.Is(err, pgx.ErrNoRows) {
		respondJSON(w, http.StatusOK, entitlementResponse{
			Active:           false,
			RemainingSeconds: 0,
		})
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "db_error")
		return
	}

	respondJSON(w, http.StatusOK, entitlementResponse{
		Active:           true,
		ExpiresAt:        &expiresAt,
		RemainingSeconds: int(time.Until(expiresAt).Seconds()),
		GrantedBy:        grantedBy,
	})
}

// TryFallback grants a short, rare free entitlement after a client reports no AdMob ad.
// The client only requests the chance; the server enforces owner identity, cooldown, probability, and duration.
func (h *EntitlementHandler) TryFallback(w http.ResponseWriter, r *http.Request) {
	ident := auth.GetIdentity(r)
	if !ident.HasIdentity() {
		respondError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	const (
		fallbackPercent = int64(1)
		cooldownHours   = 24
		fallbackHours   = 1
	)

	tx, err := h.db.Begin(ctx)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "db_error")
		return
	}
	defer tx.Rollback(ctx)

	var lockKey string
	if ident.IsUser() {
		lockKey = "user:" + ident.UserID
	} else {
		lockKey = "install:" + ident.InstallID
	}

	// Serialize fallback attempts for the same install/account.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, lockKey); err != nil {
		respondError(w, http.StatusInternalServerError, "db_error")
		return
	}

	var attemptedAt time.Time
	var lastAttemptErr error
	if ident.IsUser() {
		lastAttemptErr = tx.QueryRow(ctx, `
          SELECT attempted_at FROM fallback_attempts
          WHERE user_id = $1
          ORDER BY attempted_at DESC LIMIT 1
        `, ident.UserID).Scan(&attemptedAt)
	} else {
		lastAttemptErr = tx.QueryRow(ctx, `
          SELECT f.attempted_at FROM fallback_attempts f
          JOIN anonymous_installs a ON a.id = f.install_id
          WHERE a.install_id = $1
          ORDER BY f.attempted_at DESC LIMIT 1
        `, ident.InstallID).Scan(&attemptedAt)
	}

	if lastAttemptErr == nil && attemptedAt.Add(cooldownHours*time.Hour).After(time.Now()) {
		respondJSON(w, http.StatusTooManyRequests, map[string]interface{}{
			"active": false,
			"error":  "fallback_cooldown",
		})
		return
	}
	if lastAttemptErr != nil && !errors.Is(lastAttemptErr, pgx.ErrNoRows) {
		respondError(w, http.StatusInternalServerError, "db_error")
		return
	}

	// Pick server-side random chance in [0, 100); do not trust Android for this decision.
	n, err := rand.Int(rand.Reader, big.NewInt(100))
	if err != nil {
		respondError(w, http.StatusInternalServerError, "random_error")
		return
	}
	granted := n.Int64() < fallbackPercent

	var expiresAt *time.Time
	if granted {
		expires := time.Now().Add(fallbackHours * time.Hour)
		expiresAt = &expires

		if ident.IsUser() {
			_, err = tx.Exec(ctx, `
              INSERT INTO entitlements
                (user_id, granted_by, duration_hours, expires_at)
              VALUES ($1, 'fallback_free', $2, $3)
            `, ident.UserID, fallbackHours, expires)
		} else {
			_, err = tx.Exec(ctx, `
              INSERT INTO entitlements
                (install_id, granted_by, duration_hours, expires_at)
              SELECT a.id, 'fallback_free', $2, $3
              FROM anonymous_installs a WHERE a.install_id = $1
            `, ident.InstallID, fallbackHours, expires)
		}
		if err != nil {
			respondError(w, http.StatusInternalServerError, "db_error")
			return
		}
	}

	if ident.IsUser() {
		_, err = tx.Exec(ctx, `
          INSERT INTO fallback_attempts (user_id, granted)
          VALUES ($1, $2)
        `, ident.UserID, granted)
	} else {
		_, err = tx.Exec(ctx, `
          INSERT INTO fallback_attempts (install_id, granted)
          SELECT a.id, $2 FROM anonymous_installs a WHERE a.install_id = $1
        `, ident.InstallID, granted)
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "db_error")
		return
	}

	if err := tx.Commit(ctx); err != nil {
		respondError(w, http.StatusInternalServerError, "db_error")
		return
	}

	if !granted {
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"active": false,
			"error":  "fallback_not_selected",
		})
		return
	}

	respondJSON(w, http.StatusOK, entitlementResponse{
		Active:           true,
		ExpiresAt:        expiresAt,
		RemainingSeconds: int(time.Until(*expiresAt).Seconds()),
		GrantedBy:        "fallback_free",
	})
}
