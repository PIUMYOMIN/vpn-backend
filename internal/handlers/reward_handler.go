package handlers

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SSVVerifier validates AdMob Server-Side Verification signatures.
// Implementation: internal/services/ssv_verifier.go
type SSVVerifier interface {
	Verify(query url.Values) error
}

type RewardHandler struct {
	db  *pgxpool.Pool
	ssv SSVVerifier
}

func NewRewardHandler(db *pgxpool.Pool, ssv SSVVerifier) *RewardHandler {
	return &RewardHandler{db: db, ssv: ssv}
}

// POST /api/reward/ssv
// AdMob -> Server (server-to-server callback)
// NOTE: No JWT/Install-ID header here. Owner is carried in custom_data.
// custom_data formats:
//   "user:<userID>"    - registered user
//   "install:<installID>" - guest
func (h *RewardHandler) SSVCallback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	// 1. Google signature verify (mandatory)
	if err := h.ssv.Verify(query); err != nil {
		respondError(w, http.StatusUnauthorized, "invalid_signature")
		return
	}

	transactionID := query.Get("transaction_id")
	customData := query.Get("custom_data")
	if transactionID == "" || customData == "" {
		respondError(w, http.StatusBadRequest, "missing_params")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// 2. Replay protection
	var exists bool
	if err := h.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM entitlements WHERE ad_transaction_id = $1)`,
		transactionID,
	).Scan(&exists); err != nil {
		respondError(w, http.StatusInternalServerError, "db_error")
		return
	}
	if exists {
		respondJSON(w, http.StatusOK, map[string]string{"status": "already_processed"})
		return
	}

	// 3. reward_hours from ad_config
	var rewardHours int
	if err := h.db.QueryRow(ctx,
		`SELECT reward_hours FROM ad_config WHERE id = 1`,
	).Scan(&rewardHours); err != nil {
		respondError(w, http.StatusInternalServerError, "config_error")
		return
	}
	if rewardHours <= 0 {
		rewardHours = 24
	}

	expiresAt := time.Now().Add(time.Duration(rewardHours) * time.Hour)

	// 4. Grant by owner type
	switch {
	case strings.HasPrefix(customData, "user:"):
		userID := strings.TrimPrefix(customData, "user:")
		_, err := h.db.Exec(ctx, `
      INSERT INTO entitlements
        (user_id, granted_by, ad_transaction_id, expires_at, duration_hours)
      VALUES ($1, 'rewarded_ad', $2, $3, $4)
    `, userID, transactionID, expiresAt, rewardHours)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "db_error")
			return
		}

	case strings.HasPrefix(customData, "install:"):
		installID := strings.TrimPrefix(customData, "install:")
		tag, err := h.db.Exec(ctx, `
      INSERT INTO entitlements
        (install_id, granted_by, ad_transaction_id, expires_at, duration_hours)
      SELECT a.id, 'rewarded_ad', $2, $3, $4
      FROM anonymous_installs a WHERE a.install_id = $1
    `, installID, transactionID, expiresAt, rewardHours)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "db_error")
			return
		}
		if tag.RowsAffected() == 0 {
			respondError(w, http.StatusNotFound, "install_not_found")
			return
		}

	default:
		respondError(w, http.StatusBadRequest, "invalid_custom_data")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "granted"})
}
