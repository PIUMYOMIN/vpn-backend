package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AdminHandler struct {
	db    *pgxpool.Pool
	wgSvc interface{ RemovePeer(string) error }
}

func NewAdminHandler(db *pgxpool.Pool, wgSvc interface{ RemovePeer(string) error }) *AdminHandler {
	return &AdminHandler{db: db, wgSvc: wgSvc}
}

// ============================================================
// Users
// ============================================================

type adminUserRow struct {
	ID            string     `json:"id"`
	Email         string     `json:"email"`
	Role          string     `json:"role"`
	EmailVerified bool       `json:"email_verified"`
	IsBanned      bool       `json:"is_banned"`
	CreatedAt     time.Time  `json:"created_at"`
	LastLoginAt   *time.Time `json:"last_login_at,omitempty"`
}

// GET /admin/users?search=&page=
func (h *AdminHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	search := r.URL.Query().Get("search")
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	limit := 20
	offset := (page - 1) * limit

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var rows pgx.Rows
	var err error

	if search != "" {
		rows, err = h.db.Query(ctx, `
      SELECT id, email, role, email_verified, is_banned, created_at, last_login_at
      FROM users WHERE LOWER(email) LIKE LOWER($1)
      ORDER BY created_at DESC LIMIT $2 OFFSET $3
    `, "%"+search+"%", limit, offset)
	} else {
		rows, err = h.db.Query(ctx, `
      SELECT id, email, role, email_verified, is_banned, created_at, last_login_at
      FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2
    `, limit, offset)
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "db_error")
		return
	}
	defer rows.Close()

	users := []adminUserRow{}
	for rows.Next() {
		var u adminUserRow
		if err := rows.Scan(&u.ID, &u.Email, &u.Role, &u.EmailVerified, &u.IsBanned, &u.CreatedAt, &u.LastLoginAt); err == nil {
			users = append(users, u)
		}
	}

	var total int
	if search != "" {
		_ = h.db.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE LOWER(email) LIKE LOWER($1)`, "%"+search+"%").Scan(&total)
	} else {
		_ = h.db.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&total)
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"users": users, "total": total, "page": page, "limit": limit,
	})
}

// PATCH /admin/users/{id}
// Body: { "banned": true|false }
func (h *AdminHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	if userID == "" {
		respondError(w, http.StatusBadRequest, "missing_id")
		return
	}
	var req struct {
		Banned bool `json:"banned"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_body")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	userID = strings.TrimSpace(userID)
	tag, err := h.db.Exec(ctx,
		`UPDATE users SET is_banned = $1 WHERE id = $2::uuid`,
		req.Banned, userID,
	)
	if err != nil {
		log.Printf("admin.updateUser: %v", err)
		respondError(w, http.StatusInternalServerError, "db_error")
		return
	}

	// if err != nil {
	// 	respondError(w, http.StatusInternalServerError, "db_error")
	// 	return
	// }
	if tag.RowsAffected() == 0 {
		respondError(w, http.StatusNotFound, "user_not_found")
		return
	}

	if req.Banned {
		_, _ = h.db.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
		h.disableUserPeers(ctx, userID)
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// POST /admin/users/{id}/grant
// Body: { "hours": 24 }
func (h *AdminHandler) GrantEntitlement(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.PathValue("id"))
	if userID == "" {
		respondError(w, http.StatusBadRequest, "missing_id")
		return
	}

	var req struct {
		Hours int `json:"hours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_body")
		return
	}
	if req.Hours <= 0 || req.Hours > 720 {
		req.Hours = 24
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var exists bool
	if err := h.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1::uuid)`, userID).Scan(&exists); err != nil {
		log.Printf("admin.grant: check user %q failed: %v", userID, err)
		respondError(w, http.StatusBadRequest, "invalid_user_id")
		return
	}
	if !exists {
		respondError(w, http.StatusNotFound, "user_not_found")
		return
	}

	expires := time.Now().Add(time.Duration(req.Hours) * time.Hour)
	_, err := h.db.Exec(ctx, `
		INSERT INTO entitlements (user_id, granted_by, duration_hours, expires_at)
		VALUES ($1::uuid, 'manual', $2, $3)
	`, userID, req.Hours, expires)
	if err != nil {
		log.Printf("admin.grant: insert failed for user=%q hours=%d: %v", userID, req.Hours, err)
		respondError(w, http.StatusInternalServerError, "db_error")
		return
	}

	log.Printf("admin.grant: user=%s hours=%d expires=%s", userID, req.Hours, expires.Format(time.RFC3339))
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"status": "ok", "expires_at": expires, "hours": req.Hours,
	})
}

// ============================================================
// Peers
// ============================================================

type adminPeerRow struct {
	ID        string    `json:"id"`
	Owner     string    `json:"owner"`
	OwnerType string    `json:"owner_type"`
	PublicKey string    `json:"public_key"`
	AllowedIP string    `json:"allowed_ip"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
}

// GET /admin/peers?active=true
func (h *AdminHandler) ListPeers(w http.ResponseWriter, r *http.Request) {
	activeOnly := r.URL.Query().Get("active") == "true"

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	q := `SELECT id, COALESCE(user_id::text, install_id::text) AS owner,
               CASE WHEN user_id IS NOT NULL THEN 'user' ELSE 'install' END AS owner_type,
               public_key, allowed_ip, is_active, created_at
        FROM vpn_peers`
	if activeOnly {
		q += ` WHERE is_active = TRUE`
	}
	q += ` ORDER BY created_at DESC LIMIT 100`

	rows, err := h.db.Query(ctx, q)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "db_error")
		return
	}
	defer rows.Close()

	peers := []adminPeerRow{}
	for rows.Next() {
		var p adminPeerRow
		if err := rows.Scan(&p.ID, &p.Owner, &p.OwnerType, &p.PublicKey, &p.AllowedIP, &p.IsActive, &p.CreatedAt); err == nil {
			peers = append(peers, p)
		}
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"peers": peers})
}

// DELETE /admin/peers/{id}
func (h *AdminHandler) DeletePeer(w http.ResponseWriter, r *http.Request) {
	peerID := r.PathValue("id")
	if peerID == "" {
		respondError(w, http.StatusBadRequest, "missing_id")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var pubKey string
	if err := h.db.QueryRow(ctx, `SELECT public_key FROM vpn_peers WHERE id = $1`, peerID).Scan(&pubKey); err != nil {
		respondError(w, http.StatusNotFound, "peer_not_found")
		return
	}

	if h.wgSvc != nil {
		_ = h.wgSvc.RemovePeer(pubKey)
	}
	_, _ = h.db.Exec(ctx, `UPDATE vpn_peers SET is_active = FALSE WHERE id = $1`, peerID)

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ============================================================
// Ad Config
// ============================================================

// GET /admin/ad-config
func (h *AdminHandler) GetAdConfig(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var cfg struct {
		AdsEnabled            bool      `json:"ads_enabled"`
		AdMobAppID            *string   `json:"admob_app_id"`
		RewardedAdUnitID      *string   `json:"rewarded_ad_unit_id"`
		BannerAdUnitID        *string   `json:"banner_ad_unit_id"`
		AppOpenAdUnitID       *string   `json:"app_open_ad_unit_id"`
		RewardHours           int       `json:"reward_hours"`
		BannerRefreshSeconds  int       `json:"banner_refresh_seconds"`
		BannerMaxPerSession   int       `json:"banner_max_per_session"`
		BannerMaxPerDay       int       `json:"banner_max_per_day"`
		AppOpenMinIntervalHrs int       `json:"app_open_min_interval_hours"`
		UpdatedAt             time.Time `json:"updated_at"`
	}
	err := h.db.QueryRow(ctx, `
    SELECT ads_enabled, admob_app_id, rewarded_ad_unit_id, banner_ad_unit_id,
           app_open_ad_unit_id, reward_hours, banner_refresh_seconds,
           banner_max_per_session, banner_max_per_day, app_open_min_interval_hours,
           updated_at
    FROM ad_config WHERE id = 1
  `).Scan(&cfg.AdsEnabled, &cfg.AdMobAppID, &cfg.RewardedAdUnitID, &cfg.BannerAdUnitID,
		&cfg.AppOpenAdUnitID, &cfg.RewardHours, &cfg.BannerRefreshSeconds,
		&cfg.BannerMaxPerSession, &cfg.BannerMaxPerDay, &cfg.AppOpenMinIntervalHrs,
		&cfg.UpdatedAt)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "db_error")
		return
	}
	respondJSON(w, http.StatusOK, cfg)
}

// PATCH /admin/ad-config
func (h *AdminHandler) UpdateAdConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AdsEnabled            *bool   `json:"ads_enabled,omitempty"`
		AdMobAppID            *string `json:"admob_app_id,omitempty"`
		RewardedAdUnitID      *string `json:"rewarded_ad_unit_id,omitempty"`
		BannerAdUnitID        *string `json:"banner_ad_unit_id,omitempty"`
		AppOpenAdUnitID       *string `json:"app_open_ad_unit_id,omitempty"`
		RewardHours           *int    `json:"reward_hours,omitempty"`
		BannerRefreshSeconds  *int    `json:"banner_refresh_seconds,omitempty"`
		BannerMaxPerSession   *int    `json:"banner_max_per_session,omitempty"`
		BannerMaxPerDay       *int    `json:"banner_max_per_day,omitempty"`
		AppOpenMinIntervalHrs *int    `json:"app_open_min_interval_hours,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_body")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	_, err := h.db.Exec(ctx, `
    UPDATE ad_config SET
        ads_enabled = COALESCE($1, ads_enabled),
        admob_app_id = COALESCE($2, admob_app_id),
        rewarded_ad_unit_id = COALESCE($3, rewarded_ad_unit_id),
        banner_ad_unit_id = COALESCE($4, banner_ad_unit_id),
        app_open_ad_unit_id = COALESCE($5, app_open_ad_unit_id),
        reward_hours = COALESCE($6, reward_hours),
        banner_refresh_seconds = COALESCE($7, banner_refresh_seconds),
        banner_max_per_session = COALESCE($8, banner_max_per_session),
        banner_max_per_day = COALESCE($9, banner_max_per_day),
        app_open_min_interval_hours = COALESCE($10, app_open_min_interval_hours)
    WHERE id = 1
  `, req.AdsEnabled, req.AdMobAppID, req.RewardedAdUnitID, req.BannerAdUnitID,
		req.AppOpenAdUnitID, req.RewardHours, req.BannerRefreshSeconds,
		req.BannerMaxPerSession, req.BannerMaxPerDay, req.AppOpenMinIntervalHrs)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "db_error")
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ============================================================
// Stats
// ============================================================

// GET /admin/stats
func (h *AdminHandler) Stats(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var totalUsers, activePeers, activeEnts, guestInstalls int
	_ = h.db.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&totalUsers)
	_ = h.db.QueryRow(ctx, `SELECT COUNT(*) FROM vpn_peers WHERE is_active = TRUE`).Scan(&activePeers)
	_ = h.db.QueryRow(ctx, `SELECT COUNT(*) FROM entitlements WHERE expires_at > NOW()`).Scan(&activeEnts)
	_ = h.db.QueryRow(ctx, `SELECT COUNT(*) FROM anonymous_installs`).Scan(&guestInstalls)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"total_users":         totalUsers,
		"active_peers":        activePeers,
		"active_entitlements": activeEnts,
		"guest_installs":      guestInstalls,
		"timestamp":           time.Now(),
	})
}

// ============================================================
// Helpers
// ============================================================

func (h *AdminHandler) disableUserPeers(ctx context.Context, userID string) {
	rows, err := h.db.Query(ctx, `SELECT public_key FROM vpn_peers WHERE user_id = $1 AND is_active = TRUE`, userID)
	if err != nil {
		return
	}
	var keys []string
	for rows.Next() {
		var k string
		if rows.Scan(&k) == nil {
			keys = append(keys, k)
		}
	}
	rows.Close()

	if h.wgSvc != nil {
		for _, k := range keys {
			_ = h.wgSvc.RemovePeer(k)
		}
	}
	_, _ = h.db.Exec(ctx, `UPDATE vpn_peers SET is_active = FALSE WHERE user_id = $1`, userID)
}
