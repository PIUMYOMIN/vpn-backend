package models

import (
	"time"
)

// ==================================================================
// Constants / Enums
// ==================================================================

type UserRole string

const (
	RoleUser  UserRole = "user"
	RoleAdmin UserRole = "admin"
)

type GrantedBy string

const (
	GrantedByRewardedAd GrantedBy = "rewarded_ad"
	GrantedByManual     GrantedBy = "manual"
	GrantedByPromo      GrantedBy = "promo"
)

type EmailTokenPurpose string

const (
	PurposeVerify EmailTokenPurpose = "verify"
	PurposeReset  EmailTokenPurpose = "reset"
)

type AuditActorType string

const (
	ActorUser   AuditActorType = "user"
	ActorSystem AuditActorType = "system"
)

// ==================================================================
// User
// ==================================================================

type User struct {
	ID             string     `json:"id"`
	Email          string     `json:"email"`
	PasswordHash   string     `json:"-"` // JSON မှာ ဘယ်တော့မှ မပြ
	EmailVerified  bool       `json:"email_verified"`
	GoogleID       *string    `json:"-"` // internal only
	Role           UserRole   `json:"role"`
	TOTPSecret     *string    `json:"-"` // admin 2FA secret; မပြ
	IsBanned       bool       `json:"is_banned"`
	FailedAttempts int        `json:"-"`
	LockedUntil    *time.Time `json:"locked_until,omitempty"`
	LastLoginAt    *time.Time `json:"last_login_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

func (u *User) IsAdmin() bool { return u.Role == RoleAdmin }

// IsLocked reports whether the account is currently in lockout.
func (u *User) IsLocked(now time.Time) bool {
	return u.LockedUntil != nil && u.LockedUntil.After(now)
}

// CanLogin aggregates ban + lock + verification checks.
func (u *User) CanLogin(now time.Time) bool {
	return !u.IsBanned && !u.IsLocked(now) && u.EmailVerified
}

// ==================================================================
// AnonymousInstall (guest)
// ==================================================================

type AnonymousInstall struct {
	ID                string    `json:"id"`
	InstallID         string    `json:"install_id"`
	DeviceFingerprint *string   `json:"device_fingerprint,omitempty"`
	DeviceName        *string   `json:"device_name,omitempty"`
	Platform          *string   `json:"platform,omitempty"` // "android" | "ios"
	AppVersion        *string   `json:"app_version,omitempty"`
	LastSeenAt        time.Time `json:"last_seen_at"`
	CreatedAt         time.Time `json:"created_at"`
}

// IsStale reports if the install has not been seen for days.
func (a *AnonymousInstall) IsStale(now time.Time, days int) bool {
	return now.Sub(a.LastSeenAt) > time.Duration(days)*24*time.Hour
}

// ==================================================================
// Device (registered user device)
// ==================================================================

type Device struct {
	ID                string    `json:"id"`
	UserID            string    `json:"user_id"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	DeviceName        *string   `json:"device_name,omitempty"`
	Platform          *string   `json:"platform,omitempty"`
	LastSeenAt        time.Time `json:"last_seen_at"`
	CreatedAt         time.Time `json:"created_at"`
}

// ==================================================================
// VPNPeer
// ==================================================================

type VPNPeer struct {
	ID               string     `json:"id"`
	UserID           *string    `json:"user_id,omitempty"`
	InstallID        *string    `json:"install_id,omitempty"`
	DeviceID         *string    `json:"device_id,omitempty"`
	PublicKey        string     `json:"public_key"`
	PresharedKey     *string    `json:"-"` // secret; မပြ
	AllowedIP        string     `json:"allowed_ip"`
	ServerEndpoint   *string    `json:"server_endpoint,omitempty"`
	ClientPrivateKey *string    `json:"-"` // secret; မပြ
	IsActive         bool       `json:"is_active"`
	LastHandshake    *time.Time `json:"last_handshake,omitempty"`
	BytesRx          int64      `json:"bytes_rx"`
	BytesTx          int64      `json:"bytes_tx"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// OwnerKey returns a stable "user:<id>" or "install:<id>" string.
func (p *VPNPeer) OwnerKey() string {
	if p.UserID != nil {
		return "user:" + *p.UserID
	}
	if p.InstallID != nil {
		return "install:" + *p.InstallID
	}
	return "unknown"
}

// IsOwnerUser reports whether this peer belongs to a registered user.
func (p *VPNPeer) IsOwnerUser() bool { return p.UserID != nil }

// ==================================================================
// Entitlement (24h access grant)
// ==================================================================

type Entitlement struct {
	ID              string    `json:"id"`
	UserID          *string   `json:"user_id,omitempty"`
	InstallID       *string   `json:"install_id,omitempty"`
	GrantedBy       GrantedBy `json:"granted_by"`
	AdTransactionID *string   `json:"-"` // SSV replay key; မပြ
	DurationHours   int       `json:"duration_hours"`
	ExpiresAt       time.Time `json:"expires_at"`
	CreatedAt       time.Time `json:"created_at"`
}

// IsActive reports whether the entitlement is currently valid.
func (e *Entitlement) IsActive(now time.Time) bool {
	return e.ExpiresAt.After(now)
}

// RemainingSeconds returns seconds until expiry (0 if expired).
func (e *Entitlement) RemainingSeconds(now time.Time) int64 {
	if !e.IsActive(now) {
		return 0
	}
	return int64(e.ExpiresAt.Sub(now).Seconds())
}

// OwnerKey mirrors VPNPeer.OwnerKey.
func (e *Entitlement) OwnerKey() string {
	if e.UserID != nil {
		return "user:" + *e.UserID
	}
	if e.InstallID != nil {
		return "install:" + *e.InstallID
	}
	return "unknown"
}

// ==================================================================
// AdConfig (singleton row id=1)
// ==================================================================

type AdConfig struct {
	ID                    int       `json:"id"`
	AdsEnabled            bool      `json:"ads_enabled"`
	AdMobAppID            *string   `json:"admob_app_id,omitempty"`
	RewardedAdUnitID      *string   `json:"rewarded_ad_unit_id,omitempty"`
	BannerAdUnitID        *string   `json:"banner_ad_unit_id,omitempty"`
	AppOpenAdUnitID       *string   `json:"app_open_ad_unit_id,omitempty"`
	RewardHours           int       `json:"reward_hours"`
	BannerRefreshSeconds  int       `json:"banner_refresh_seconds"`
	BannerMaxPerSession   int       `json:"banner_max_per_session"`
	BannerMaxPerDay       int       `json:"banner_max_per_day"`
	AppOpenMinIntervalHrs int       `json:"app_open_min_interval_hours"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// Defaults returns a safe AdConfig used when the row is missing.
func DefaultAdConfig() AdConfig {
	return AdConfig{
		ID:                    1,
		AdsEnabled:            true,
		RewardHours:           24,
		BannerRefreshSeconds:  60,
		BannerMaxPerSession:   5,
		BannerMaxPerDay:       20,
		AppOpenMinIntervalHrs: 24,
	}
}

// ==================================================================
// RefreshToken
// ==================================================================
type RefreshToken struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	DeviceID  *string    `json:"device_id,omitempty"`
	TokenHash string     `json:"-"` // never expose
	UserAgent *string    `json:"user_agent,omitempty"`
	IPAddress *string    `json:"ip_address,omitempty"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

func (t *RefreshToken) IsValid(now time.Time) bool {
	return t.RevokedAt == nil && t.ExpiresAt.After(now)
}

// ==================================================================
// EmailToken (verify / reset)
// ==================================================================

type EmailToken struct {
	ID        string            `json:"id"`
	UserID    string            `json:"user_id"`
	TokenHash string            `json:"-"` // never expose
	Purpose   EmailTokenPurpose `json:"purpose"`
	ExpiresAt time.Time         `json:"expires_at"`
	UsedAt    *time.Time        `json:"used_at,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

func (t *EmailToken) IsUsable(now time.Time) bool {
	return t.UsedAt == nil && t.ExpiresAt.After(now)
}

// ==================================================================
// AuditLog
// ==================================================================

type AuditLog struct {
	ID          int64          `json:"id"`
	ActorUserID *string        `json:"actor_user_id,omitempty"`
	ActorType   AuditActorType `json:"actor_type"`
	Action      string         `json:"action"` // "peer.create", "user.ban", ...
	TargetType  *string        `json:"target_type,omitempty"`
	TargetID    *string        `json:"target_id,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	IPAddress   *string        `json:"ip_address,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
}

// Common action constants — use these instead of raw strings.
const (
	ActionUserRegister   = "user.register"
	ActionUserLogin      = "user.login"
	ActionUserLogout     = "user.logout"
	ActionUserBan        = "user.ban"
	ActionUserUnban      = "user.unban"
	ActionUserGrant      = "user.grant"
	ActionPeerCreate     = "peer.create"
	ActionPeerRevoke     = "peer.revoke"
	ActionPeerExpired    = "peer.expired" // from expiry_job
	ActionAdConfigUpdate = "ad_config.update"
	ActionSSVGranted     = "ssv.granted"
	ActionSSVRejected    = "ssv.rejected"
)
