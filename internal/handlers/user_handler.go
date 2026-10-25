package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/piumyomin/vpn-backend/internal/auth"
)

type UserHandler struct {
	db *pgxpool.Pool
}

func NewUserHandler(db *pgxpool.Pool) *UserHandler {
	return &UserHandler{db: db}
}

type userResponse struct {
	ID            string     `json:"id"`
	Email         string     `json:"email"`
	Role          string     `json:"role"`
	EmailVerified bool       `json:"email_verified"`
	CreatedAt     time.Time  `json:"created_at"`
	LastLoginAt   *time.Time `json:"last_login_at,omitempty"`
}

// GET /api/me
func (h *UserHandler) Me(w http.ResponseWriter, r *http.Request) {
	ident := auth.GetIdentity(r)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var u userResponse
	err := h.db.QueryRow(ctx, `
    SELECT id, email, role, email_verified, created_at, last_login_at
    FROM users WHERE id = $1
  `, ident.UserID).Scan(
		&u.ID, &u.Email, &u.Role, &u.EmailVerified, &u.CreatedAt, &u.LastLoginAt,
	)
	if err != nil {
		respondError(w, http.StatusNotFound, "user_not_found")
		return
	}
	respondJSON(w, http.StatusOK, u)
}
