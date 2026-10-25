package handlers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/piumyomin/vpn-backend/internal/auth"
	"github.com/piumyomin/vpn-backend/internal/services"
)

const (
	maxFailedAttempts = 5
	lockoutDuration   = 15 * time.Minute
)

type AuthHandler struct {
	db       *pgxpool.Pool
	jwtSvc   *auth.JWTService
	emailSvc *services.EmailService
}

func NewAuthHandler(db *pgxpool.Pool, jwtSvc *auth.JWTService, emailSvc *services.EmailService) *AuthHandler {
	return &AuthHandler{db: db, jwtSvc: jwtSvc, emailSvc: emailSvc}
}

// ---------------- Register ----------------

type registerRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	InstallID string `json:"install_id,omitempty"`
}

// POST /auth/register
// Body: { email, password, install_id? }
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_body")
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || req.Password == "" {
		respondError(w, http.StatusBadRequest, "missing_fields")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrWeakPassword) {
			respondError(w, http.StatusBadRequest, "weak_password")
			return
		}
		respondError(w, http.StatusInternalServerError, "hash_error")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	tx, err := h.db.Begin(ctx)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "db_error")
		return
	}
	defer tx.Rollback(ctx)

	// MVP: email_verified = TRUE (no email service needed yet).
	var userID string
	err = tx.QueryRow(ctx, `
    INSERT INTO users (email, password_hash, email_verified)
    VALUES ($1, $2, TRUE)
    RETURNING id
  `, email, hash).Scan(&userID)
	if err != nil {
		if isUniqueViolation(err) {
			respondError(w, http.StatusConflict, "email_exists")
			return
		}
		respondError(w, http.StatusInternalServerError, "db_error")
		return
	}

	// Guest -> user data transfer
	if req.InstallID != "" {
		var installUUID string
		if err := tx.QueryRow(ctx,
			`SELECT id FROM anonymous_installs WHERE install_id = $1`,
			req.InstallID,
		).Scan(&installUUID); err == nil {
			// entitlements transfer (only non-expired)
			_, _ = tx.Exec(ctx, `
        UPDATE entitlements
        SET user_id = $1, install_id = NULL
        WHERE install_id = $2 AND expires_at > NOW()
      `, userID, installUUID)

			// peers transfer
			_, _ = tx.Exec(ctx, `
        UPDATE vpn_peers
        SET user_id = $1, install_id = NULL
        WHERE install_id = $2
      `, userID, installUUID)

			// install row remove
			_, _ = tx.Exec(ctx, `DELETE FROM anonymous_installs WHERE id = $1`, installUUID)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		respondError(w, http.StatusInternalServerError, "db_error")
		return
	}

	pair, err := h.jwtSvc.GeneratePair(ctx, userID, "user", nil)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "token_error")
		return
	}

	respondJSON(w, http.StatusCreated, pair)
}

// ---------------- Login ----------------

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// POST /auth/login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_body")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || req.Password == "" {
		respondError(w, http.StatusBadRequest, "missing_fields")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var (
		userID         string
		passwordHash   string
		role           string
		isBanned       bool
		failedAttempts int
		lockedUntil    *time.Time
	)
	err := h.db.QueryRow(ctx, `
    SELECT id, password_hash, role, is_banned, failed_attempts, locked_until
    FROM users WHERE LOWER(email) = $1
  `, email).Scan(&userID, &passwordHash, &role, &isBanned, &failedAttempts, &lockedUntil)

	if errors.Is(err, pgx.ErrNoRows) {
		// timing equalization
		_, _ = auth.VerifyPassword(req.Password, auth.DummyHash)
		respondError(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "db_error")
		return
	}

	if isBanned {
		respondError(w, http.StatusForbidden, "account_banned")
		return
	}
	if lockedUntil != nil && lockedUntil.After(time.Now()) {
		retryAfter := int(time.Until(*lockedUntil).Seconds())
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		respondError(w, http.StatusTooManyRequests, "account_locked")
		return
	}

	ok, _ := auth.VerifyPassword(req.Password, passwordHash)
	if !ok {
		newAttempts := failedAttempts + 1
		var newLock *time.Time
		if newAttempts >= maxFailedAttempts {
			t := time.Now().Add(lockoutDuration)
			newLock = &t
			newAttempts = 0
		}
		_, _ = h.db.Exec(ctx, `
      UPDATE users SET failed_attempts = $1, locked_until = $2 WHERE id = $3
    `, newAttempts, newLock, userID)
		respondError(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}

	_, _ = h.db.Exec(ctx, `
    UPDATE users
    SET failed_attempts = 0, locked_until = NULL, last_login_at = NOW()
    WHERE id = $1
  `, userID)

	pair, err := h.jwtSvc.GeneratePair(ctx, userID, role, nil)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "token_error")
		return
	}
	respondJSON(w, http.StatusOK, pair)
}

// ---------------- Refresh ----------------

// POST /auth/refresh
// Body: { refresh_token }
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		respondError(w, http.StatusBadRequest, "invalid_body")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	pair, _, err := h.jwtSvc.Rotate(ctx, req.RefreshToken)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidRefreshToken) {
			respondError(w, http.StatusUnauthorized, "invalid_refresh_token")
			return
		}
		respondError(w, http.StatusInternalServerError, "token_error")
		return
	}
	respondJSON(w, http.StatusOK, pair)
}

// ---------------- Logout ----------------

// POST /auth/logout
// Body: { refresh_token }
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		respondError(w, http.StatusBadRequest, "invalid_body")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	_ = h.jwtSvc.Revoke(ctx, req.RefreshToken)
	respondJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// ---------------- Delete Account ----------------

// DELETE /auth/account
// Header: Authorization: Bearer <access_token>
// Body: { "password": "..." }
func (h *AuthHandler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	ident := auth.GetIdentity(r)

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
		respondError(w, http.StatusBadRequest, "invalid_body")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Password စစ်
	var hash string
	if err := h.db.QueryRow(ctx,
		`SELECT password_hash FROM users WHERE id = $1`, ident.UserID,
	).Scan(&hash); err != nil {
		respondError(w, http.StatusNotFound, "user_not_found")
		return
	}

	ok, _ := auth.VerifyPassword(req.Password, hash)
	if !ok {
		respondError(w, http.StatusUnauthorized, "invalid_password")
		return
	}

	// User ဖျက် (ON DELETE CASCADE က devices/peers/entitlements/tokens အားလုံး ဖျက်ပေးတယ်)
	tag, err := h.db.Exec(ctx, `DELETE FROM users WHERE id = $1`, ident.UserID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "db_error")
		return
	}
	if tag.RowsAffected() == 0 {
		respondError(w, http.StatusNotFound, "user_not_found")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ---------------- Forgot Password ----------------

// POST /auth/forgot-password
// Body: { "email": "..." }
func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_body")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		respondError(w, http.StatusBadRequest, "missing_fields")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// ⚠️ Always return 200 — prevent user enumeration
	var userID string
	err := h.db.QueryRow(ctx, `SELECT id FROM users WHERE LOWER(email) = $1`, email).Scan(&userID)

	if err != nil {
    // User မ ရှိရင် enumeration ကာကွယ်ဖို့ log ပဲ ထုတ် (response က sent ပဲ)
    log.Printf("forgot-password: user not found for %q", email)
  } else {
    // Generate opaque token (32 bytes)
    tokenBytes := make([]byte, 32)
    if _, rerr := rand.Read(tokenBytes); rerr != nil {
      log.Printf("forgot-password: rand.Read failed: %v", rerr)
    } else {
      plain := base64.URLEncoding.EncodeToString(tokenBytes)
      hash := sha256.Sum256([]byte(plain))
      tokenHash := hex.EncodeToString(hash[:])
      expires := time.Now().Add(1 * time.Hour)

      // ✅ Error ကို log ထုတ်
      _, dbErr := h.db.Exec(ctx, `
        INSERT INTO email_tokens (user_id, token_hash, purpose, expires_at)
        VALUES ($1, $2, 'reset', $3)
      `, userID, tokenHash, expires)
      if dbErr != nil {
        log.Printf("forgot-password: INSERT email_tokens failed: %v", dbErr)
      } else {
        log.Printf("forgot-password: token created for user=%s", userID)

        // ✅ Email error ကို log ထုတ်
        if h.emailSvc != nil {
          if mailErr := h.emailSvc.SendPasswordReset(email, plain); mailErr != nil {
            log.Printf("forgot-password: send email failed: %v", mailErr)
          } else {
            log.Printf("forgot-password: email sent to %s", email)
          }
        }

        // ⚠️ DEV ONLY — plain token ကို log မှာ ပြ (email မ ရရင် သုံးဖို့)
        if os.Getenv("DEV_LOG_RESET_TOKEN") == "true" {
          log.Printf("🔑 [DEV] reset token for %s: %s", email, plain)
        }
      }
    }
  }

	respondJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

// ---------------- Reset Password ----------------

// POST /auth/reset-password
// Body: { "token": "...", "new_password": "..." }
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_body")
		return
	}
	if req.Token == "" || req.NewPassword == "" {
		respondError(w, http.StatusBadRequest, "missing_fields")
		return
	}
	if err := auth.ValidatePasswordStrength(req.NewPassword); err != nil {
		respondError(w, http.StatusBadRequest, "weak_password")
		return
	}

	hash := sha256.Sum256([]byte(req.Token))
	tokenHash := hex.EncodeToString(hash[:])

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var tokenID, userID string
	err := h.db.QueryRow(ctx, `
    SELECT id, user_id FROM email_tokens
    WHERE token_hash = $1 AND purpose = 'reset'
      AND used_at IS NULL AND expires_at > NOW()
  `, tokenHash).Scan(&tokenID, &userID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid_token")
		return
	}

	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "hash_error")
		return
	}

	tx, err := h.db.Begin(ctx)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "db_error")
		return
	}
	defer tx.Rollback(ctx)

	// Update password + reset lockout
	if _, err := tx.Exec(ctx, `
    UPDATE users SET password_hash = $1, failed_attempts = 0, locked_until = NULL
    WHERE id = $2
  `, newHash, userID); err != nil {
		respondError(w, http.StatusInternalServerError, "db_error")
		return
	}

	// Mark token as used
	_, _ = tx.Exec(ctx, `UPDATE email_tokens SET used_at = NOW() WHERE id = $1`, tokenID)

	// Security: revoke all refresh tokens (force re-login)
	_, _ = tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL`, userID)

	if err := tx.Commit(ctx); err != nil {
		respondError(w, http.StatusInternalServerError, "db_error")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
