package handlers

import (
	"context"
	"errors"
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
	Active           bool      `json:"active"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	RemainingSeconds int       `json:"remaining_seconds"`
	GrantedBy        string    `json:"granted_by,omitempty"`
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
