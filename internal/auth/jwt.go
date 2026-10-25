package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrInvalidToken        = errors.New("invalid token")
	ErrInvalidRefreshToken = errors.New("invalid or expired refresh token")
)

// Claims is embedded in the access token JWT.
type Claims struct {
	UserID string `json:"uid"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// TokenPair is what the client receives on login / refresh.
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// JWTService issues and verifies tokens. Refresh tokens are opaque
// random strings stored hashed in the DB (see 000007 migration).
type JWTService struct {
	secret     []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
	db         *pgxpool.Pool
}

func NewJWTService(secret string, accessTTL, refreshTTL time.Duration, db *pgxpool.Pool) *JWTService {
	return &JWTService{
		secret:     []byte(secret),
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
		db:         db,
	}
}

// ------------------------------------------------------------------
// Access token (JWT, short-lived)
// ------------------------------------------------------------------

func (s *JWTService) GenerateAccessToken(userID, role string) (string, time.Time, error) {
	now := time.Now()
	exp := now.Add(s.accessTTL)

	claims := Claims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			Subject:   userID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(s.secret)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, exp, nil
}

func (s *JWTService) Verify(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		// Reject anything that is not HMAC (prevents alg= none attack)
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return s.secret, nil
	})
	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

// ------------------------------------------------------------------
// Refresh token (opaque random, hashed in DB)
// ------------------------------------------------------------------

func generateOpaqueToken() (plain, hashed string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	plain = base64.RawURLEncoding.EncodeToString(b)
	return plain, hashToken(plain), nil
}

func hashToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// GeneratePair issues a new access + refresh token pair and stores
// the refresh token's hash. deviceID may be nil.
func (s *JWTService) GeneratePair(
	ctx context.Context,
	userID, role string,
	deviceID *string,
) (*TokenPair, error) {
	access, exp, err := s.GenerateAccessToken(userID, role)
	if err != nil {
		return nil, err
	}

	plain, hashed, err := generateOpaqueToken()
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(s.refreshTTL)
	_, err = s.db.Exec(ctx, `
    INSERT INTO refresh_tokens (user_id, device_id, token_hash, expires_at)
    VALUES ($1, $2, $3, $4)
  `, userID, deviceID, hashed, expiresAt)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  access,
		RefreshToken: plain,
		ExpiresAt:    exp,
	}, nil
}

// Rotate consumes an old refresh token, revokes it, and returns a new pair.
// Returns (pair, userID, error).
func (s *JWTService) Rotate(ctx context.Context, oldPlain string) (*TokenPair, string, error) {
	oldHash := hashToken(oldPlain)
	var userID, role string
	var deviceID *string
	err := s.db.QueryRow(ctx, `
    SELECT u.id, u.role, rt.device_id
    FROM refresh_tokens rt
    JOIN users u ON u.id = rt.user_id
    WHERE rt.token_hash = $1
      AND rt.revoked_at IS NULL
      AND rt.expires_at > NOW()
  `, oldHash).Scan(&userID, &role, &deviceID)
	if err != nil {
		return nil, "", ErrInvalidRefreshToken
	}

	// Revoke the old token first (one-time use)
	if _, err := s.db.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = NOW() WHERE token_hash = $1`, oldHash,
	); err != nil {
		return nil, "", err
	}

	pair, err := s.GeneratePair(ctx, userID, role, deviceID)
	if err != nil {
		return nil, "", err
	}
	return pair, userID, nil
}

// Revoke marks a refresh token as revoked (logout).
func (s *JWTService) Revoke(ctx context.Context, plain string) error {
	_, err := s.db.Exec(ctx, `
    UPDATE refresh_tokens
    SET revoked_at = NOW()
    WHERE token_hash = $1 AND revoked_at IS NULL
  `, hashToken(plain))
	return err
}

// RevokeAllForUser revokes every active refresh token for a user
// (useful for "logout all devices" or after password change).
func (s *JWTService) RevokeAllForUser(ctx context.Context, userID string) error {
	_, err := s.db.Exec(ctx, `
    UPDATE refresh_tokens
    SET revoked_at = NOW()
    WHERE user_id = $1 AND revoked_at IS NULL
  `, userID)
	return err
}
