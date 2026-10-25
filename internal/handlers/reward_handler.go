package handlers

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SSVVerifier validates AdMob Server-Side Verification signatures.
type SSVVerifier interface {
	Verify(rawQuery string, query url.Values) error
}

type RewardHandler struct {
	db  *pgxpool.Pool
	ssv SSVVerifier
}

func NewRewardHandler(db *pgxpool.Pool, ssv SSVVerifier) *RewardHandler {
	return &RewardHandler{db: db, ssv: ssv}
}

// SSVCallback is AdMob → backend (GET or POST with query params).
// Owner is in custom_data: "user:<uuid>" or "install:<uuid>".
// Remaining time stacks: active grant + reward hours (e.g. 12h24m + 24h → 36h24m).
func (h *RewardHandler) SSVCallback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	// AdMob console "Verify" pings with no transaction/signature.
	if query.Get("transaction_id") == "" || query.Get("signature") == "" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
		return
	}

	transactionID := strings.TrimSpace(query.Get("transaction_id"))
	customData, _ := url.QueryUnescape(strings.TrimSpace(query.Get("custom_data")))
	if transactionID == "" || customData == "" {
		respondError(w, http.StatusBadRequest, "missing_params")
		return
	}

	if err := h.ssv.Verify(r.URL.RawQuery, query); err != nil {
		log.Printf("SSV verification failed (no grant): %v", err)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	expiresAt, err := h.grantStacked(ctx, transactionID, customData)
	if err != nil {
		if err == errAlreadyProcessed {
			respondJSON(w, http.StatusOK, map[string]string{"status": "already_processed"})
			return
		}
		if err == errInvalidCustomData {
			log.Printf("SSV invalid custom_data: %q", customData)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
			return
		}
		log.Printf("SSV grant error: %v", err)
		respondError(w, http.StatusInternalServerError, "grant_error")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":            "granted",
		"expires_at":        expiresAt,
		"remaining_seconds": int(time.Until(expiresAt).Seconds()),
	})
}

var (
	errAlreadyProcessed  = errSentinel("already_processed")
	errInvalidCustomData = errSentinel("invalid_custom_data")
)

type errSentinel string

func (e errSentinel) Error() string { return string(e) }

func (h *RewardHandler) grantStacked(ctx context.Context, transactionID, customData string) (time.Time, error) {
	tx, err := h.db.Begin(ctx)
	if err != nil {
		return time.Time{}, err
	}
	defer tx.Rollback(ctx)

	var exists bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM entitlements WHERE ad_transaction_id = $1)`,
		transactionID,
	).Scan(&exists); err != nil {
		return time.Time{}, err
	}
	if exists {
		return time.Time{}, errAlreadyProcessed
	}

	var rewardHours int
	if err := tx.QueryRow(ctx,
		`SELECT reward_hours FROM ad_config WHERE id = 1`,
	).Scan(&rewardHours); err != nil {
		rewardHours = 24
	}
	if rewardHours <= 0 {
		rewardHours = 24
	}
	addDuration := time.Duration(rewardHours) * time.Hour
	now := time.Now()

	var expiresAt time.Time
	switch {
	case strings.HasPrefix(customData, "user:"):
		userID := strings.TrimSpace(strings.TrimPrefix(customData, "user:"))
		if userID == "" {
			return time.Time{}, errInvalidCustomData
		}
		_, _ = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "user:"+userID)

		var current *time.Time
		_ = tx.QueryRow(ctx,
			`SELECT MAX(expires_at) FROM entitlements WHERE user_id = $1::uuid`,
			userID,
		).Scan(&current)
		expiresAt = stackedExpiry(now, current, addDuration)

		_, err = tx.Exec(ctx, `
			INSERT INTO entitlements
				(user_id, granted_by, ad_transaction_id, expires_at, duration_hours)
			VALUES ($1::uuid, 'rewarded_ad', $2, $3, $4)
		`, userID, transactionID, expiresAt, rewardHours)

	case strings.HasPrefix(customData, "install:"):
		installID := strings.TrimSpace(strings.TrimPrefix(customData, "install:"))
		if installID == "" {
			return time.Time{}, errInvalidCustomData
		}
		_, _ = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "install:"+installID)

		var installUUID string
		if err := tx.QueryRow(ctx, `
			INSERT INTO anonymous_installs (install_id, last_seen_at)
			VALUES ($1, NOW())
			ON CONFLICT (install_id) DO UPDATE SET last_seen_at = NOW()
			RETURNING id
		`, installID).Scan(&installUUID); err != nil {
			return time.Time{}, err
		}

		var current *time.Time
		_ = tx.QueryRow(ctx,
			`SELECT MAX(expires_at) FROM entitlements WHERE install_id = $1`,
			installUUID,
		).Scan(&current)
		expiresAt = stackedExpiry(now, current, addDuration)

		_, err = tx.Exec(ctx, `
			INSERT INTO entitlements
				(install_id, granted_by, ad_transaction_id, expires_at, duration_hours)
			VALUES ($1, 'rewarded_ad', $2, $3, $4)
		`, installUUID, transactionID, expiresAt, rewardHours)

	default:
		return time.Time{}, errInvalidCustomData
	}

	if err != nil {
		if isUniqueViolation(err) {
			return time.Time{}, errAlreadyProcessed
		}
		return time.Time{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return time.Time{}, err
	}
	return expiresAt, nil
}

func stackedExpiry(now time.Time, current *time.Time, add time.Duration) time.Time {
	if current != nil && current.After(now) {
		return current.Add(add)
	}
	return now.Add(add)
}
