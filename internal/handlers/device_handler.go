package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/piumyomin/vpn-backend/internal/auth"
)

type DeviceHandler struct {
	db *pgxpool.Pool
}

func NewDeviceHandler(db *pgxpool.Pool) *DeviceHandler {
	return &DeviceHandler{db: db}
}

type deviceResponse struct {
	ID                string    `json:"id"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	DeviceName        *string   `json:"device_name,omitempty"`
	Platform          *string   `json:"platform,omitempty"`
	LastSeenAt        time.Time `json:"last_seen_at"`
	CreatedAt         time.Time `json:"created_at"`
}

// GET /api/devices
func (h *DeviceHandler) List(w http.ResponseWriter, r *http.Request) {
	ident := auth.GetIdentity(r)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	rows, err := h.db.Query(ctx, `
    SELECT id, device_fingerprint, device_name, platform, last_seen_at, created_at
    FROM devices
    WHERE user_id = $1
    ORDER BY last_seen_at DESC
  `, ident.UserID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "db_error")
		return
	}
	defer rows.Close()

	devices := []deviceResponse{}
	for rows.Next() {
		var d deviceResponse
		if err := rows.Scan(&d.ID, &d.DeviceFingerprint, &d.DeviceName,
			&d.Platform, &d.LastSeenAt, &d.CreatedAt); err != nil {
			respondError(w, http.StatusInternalServerError, "db_error")
			return
		}
		devices = append(devices, d)
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"devices": devices})
}

// DELETE /api/devices/{id}
func (h *DeviceHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ident := auth.GetIdentity(r)
	deviceID := r.PathValue("id")
	if deviceID == "" {
		respondError(w, http.StatusBadRequest, "missing_device_id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	tag, err := h.db.Exec(ctx, `
    DELETE FROM devices WHERE id = $1 AND user_id = $2
  `, deviceID, ident.UserID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "db_error")
		return
	}
	if tag.RowsAffected() == 0 {
		respondError(w, http.StatusNotFound, "device_not_found")
		return
	}

	// ဒီ device ရဲ့ peer တွေကို ပိတ်
	_, _ = h.db.Exec(ctx, `
    UPDATE vpn_peers SET is_active = FALSE
    WHERE device_id = $1 AND is_active = TRUE
  `, deviceID)

	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
