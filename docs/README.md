# VPN Backend + Mobile App

Guest-first VPN backend with 24-hour free access via rewarded ads.

> အမြန်ဆုံး၊ ဘေးကင်းလုံခြုံဆုံး ကိုယ်ပိုင် VPN — မြန်မာနိုင်ငံအတွက်။

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://go.dev)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-336791?logo=postgresql)](https://postgresql.org)
[![WireGuard](https://img.shields.io/badge/WireGuard-1.x-88171A?logo=wireguard)](https://wireguard.com)

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Tech Stack](#-tech-stack)
- [Quick Start](#-quick-start)
- [Project Structure](#-project-structure)
- [Environment Variables](#-environment-variables)
- [Database](#-database)
- [API Reference](#-api-reference)
- [Authentication](#-authentication)
- [Entitlement Model](#-entitlement-model)
- [AdMob SSV](#-admob-ssv)
- [VPN Peer Management](#-vpn-peer-management)
- [Background Jobs](#-background-jobs)
- [Security](#-security)
- [Deployment](#-deployment)
- [Troubleshooting](#-troubleshooting)
- [Roadmap](#-roadmap)

---

## 🎯 Overview

### What This Is

A REST API backend for a mobile VPN app that:
- Allows **guest usage** without registration
- Grants **24-hour access** per rewarded ad view
- Supports **optional account registration** for cross-device features
- Manages **WireGuard peers** programmatically
- Verifies **AdMob SSV callbacks** for ad revenue protection

### Model

| Aspect | Behavior |
|---|---|
| Identity | `X-Install-ID` header (guest) or `Authorization: Bearer` (user) |
| Access Duration | 24 hours per grant (configurable) |
| Grant Source | `rewarded_ad` / `manual` / `promo` |
| Stacking | ❌ No — new grant replaces, no extension |
| Enforcement | Server-side (client is untrusted) |
| Expiry Check | Background job every 5 min |
| Device Limit | 2 active peers per owner |
| Ad Network | Google AdMob (SSV) |

### Supported Flows

```
Guest:      Install app → Watch ad → Get 24h → Connect
Registered: Register → Watch ad → Get 24h → Connect (survives reinstall)
```

---

## 🏗 Architecture

```
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│  Android App │◄──HTTPS─►│  Go Backend  │◄────────►│  PostgreSQL  │
│  (Kotlin)    │         │  (REST API)  │         └──────────────┘
│  + Rust Core │         │              │
└──────┬───────┘         │              │◄────────►┌──────────────┐
       │                 │              │         │  WireGuard   │
       │ UDP 51820       │              │         │  (wg0)       │
       ▼                 └──────┬───────┘         └──────────────┘
┌──────────────┐                │
│  VPN Server  │                │ HTTPS (SSV callback)
│  (WireGuard) │         ┌──────▼───────┐
└──────────────┘         │ Google AdMob │
                         └──────────────┘
```

### Components

| Component | Responsibility |
|---|---|
| **Android App** | UI, VPN tunnel (Rust via JNI), ad display, API client |
| **Go Backend** | Auth, entitlement, VPN config, SSV verification |
| **PostgreSQL** | Persistent storage (users, installs, peers, entitlements) |
| **WireGuard** | Server-side tunnel (managed via `wgctrl`) |
| **AdMob** | Rewarded/Banner ads + server-side verification callbacks |

---

## 🛠 Tech Stack

| Layer | Technology | Version |
|---|---|---|
| Language | Go | 1.22+ |
| HTTP | `net/http` (stdlib) | — |
| Database | PostgreSQL | 15+ |
| DB Driver | `pgx/v5` | latest |
| JWT | `golang-jwt/jwt/v5` | latest |
| Password | `alexedwards/argon2id` | latest |
| WireGuard | `wgctrl` | latest |
| Email | `resend-go/v4` | latest |
| Env | `joho/godotenv` | latest |
| Migrations | `golang-migrate` | latest |
| Reverse Proxy | Caddy | 2.x |
| OS | Ubuntu | 22.04 / 24.04 |

---

## 🚀 Quick Start

### Prerequisites

- Go 1.22+
- PostgreSQL 15+
- WireGuard (`wg`, `wg-quick`)
- Root/sudo access (for WireGuard operations)

### Setup

```bash
# 1. Clone
git clone <your-repo> && cd vpn-backend

# 2. Download deps
go mod download

# 3. Configure
cp .env.example .env
# Edit .env with your values

# 4. Database
createdb vpndb
migrate -path internal/db/migrations -database "$DATABASE_URL" up

# 5. WireGuard
sudo apt install wireguard
sudo wg-quick up wg0

# 6. Run
go run ./cmd/server
```

### Verify

```bash
curl http://localhost:8080/healthz
# → ok
```

---

## 📁 Project Structure

```
vpn-backend/
├── cmd/
│   └── server/
│       └── main.go                 # Entry point
├── internal/
│   ├── config/
│   │   └── config.go               # Env loading + validation
│   ├── db/
│   │   ├── db.go                   # pgxpool connection
│   │   └── migrations/             # SQL migrations
│   ├── auth/
│   │   ├── password.go             # Argon2id hash/verify
│   │   ├── jwt.go                  # Token pair + rotation
│   │   └── middleware.go           # Identity + route guards
│   ├── handlers/
│   │   ├── helpers.go              # Shared response helpers
│   │   ├── auth_handler.go         # Register/Login/Refresh/Logout
│   │   ├── entitlement_handler.go  # GET /api/entitlement
│   │   ├── reward_handler.go       # POST /api/reward/ssv
│   │   └── vpn_handler.go          # GET /api/vpn/config
│   ├── services/
│   │   ├── email_service.go        # Resend integration
│   │   ├── ssv_verification.go     # AdMob ECDSA verify
│   │   └── wireguard_service.go    # wgctrl wrapper
│   ├── jobs/
│   │   └── expiry_job.go           # 24h expiry + cleanup
│   └── models/
│       └── models.go               # Shared domain structs
├── .env                            # (gitignored)
├── .env.example
├── .gitignore
├── go.mod
├── go.sum
└── README.md                       # ← this file
```

### Design Principles

- **`handlers`** — HTTP layer only (parse → call service → respond)
- **`services`** — Business logic + external integrations
- **`jobs`** — Background tasks
- **`models`** — Shared structs (no logic beyond helpers)
- **`auth`** — Security primitives (isolated, testable)

---

## 🔐 Environment Variables

Copy `.env.example` to `.env` and fill:

```env
# ===== Server =====
PORT=8080
APP_URL=https://api.yourdomain.com

# ===== Database =====
DATABASE_URL=postgres://vpnuser:password@localhost:5432/vpndb?sslmode=disable

# ===== JWT =====
# Generate with: openssl rand -base64 32
JWT_SECRET=at-least-32-bytes-random-secret-change-me
ACCESS_TOKEN_TTL=15m
REFRESH_TOKEN_TTL=720h

# ===== WireGuard =====
WG_INTERFACE=wg0
WG_SERVER_PUBLIC_KEY=<output of: sudo wg show wg0 public-key>
WG_ENDPOINT=vpn.yourdomain.com
WG_PORT=51820
WG_DNS=1.1.1.1

# ===== Email (Resend) =====
RESEND_API_KEY=re_xxxxxxxxxxxx
EMAIL_FROM=VPN App <noreply@yourdomain.com>
```

### ⚠️ Security Notes

- **Never commit `.env`** — add to `.gitignore`
- `JWT_SECRET` must be ≥ 32 random bytes
- Use a secret manager in production (AWS Secrets Manager, Vault)

---

## 🗄 Database

### Migration Commands

```bash
# Install migrate tool
go install -tags 'postgres' \
  github.com/golang-migrate/migrate/v4/cmd/migrate@latest

# Run all
migrate -path internal/db/migrations -database "$DATABASE_URL" up

# Rollback 1
migrate -path internal/db/migrations -database "$DATABASE_URL" down 1

# Check version
migrate -path internal/db/migrations -database "$DATABASE_URL" version
```

### Tables

| Table | Purpose | Cardinality |
|---|---|---|
| `users` | Registered users | Low |
| `anonymous_installs` | Guest installs | High |
| `devices` | User-owned devices | Medium |
| `vpn_peers` | WireGuard peers | High |
| `entitlements` | 24h grants | High |
| `ad_config` | Ad settings (singleton) | 1 row |
| `refresh_tokens` | JWT refresh tokens | Medium |
| `email_tokens` | Verify/reset tokens | Medium |
| `audit_log` | Admin actions | Medium |

### Critical Constraints

**Owner check** on `vpn_peers` and `entitlements`:

```sql
CHECK (
  (user_id IS NOT NULL AND install_id IS NULL) OR
  (user_id IS NULL AND install_id IS NOT NULL)
)
```

A peer/entitlement belongs to **either** a registered user **or** a guest install — never both.

**Replay protection**:

```sql
-- entitlements
ad_transaction_id TEXT UNIQUE
```

---

## 📡 API Reference

### Base URLs

```
Development: http://localhost:8080
Production:  https://api.yourdomain.com
```

### Common Headers

| Header | When Required |
|---|---|
| `Content-Type: application/json` | POST / PATCH |
| `Authorization: Bearer <access_token>` | Registered users |
| `X-Install-ID: <uuid>` | Guest installs |

> **Generate `X-Install-ID` once per install** using UUID v4 and persist in encrypted SharedPreferences / Android Keystore.

### Endpoints

#### Public

| Method | Path | Description |
|---|---|---|
| `GET` | `/healthz` | Health check |
| `POST` | `/auth/register` | Create account |
| `POST` | `/auth/login` | Sign in |
| `POST` | `/auth/refresh` | Rotate tokens |
| `POST` | `/auth/logout` | Revoke refresh token |
| `POST` | `/api/reward/ssv` | AdMob SSV callback (Google-only) |

#### Protected (Guest OR User)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/entitlement` | Current 24h status |
| `GET` | `/api/vpn/config` | WireGuard config (if entitled) |

#### User-Only

| Method | Path | Status |
|---|---|---|
| `GET` | `/api/me` | Implemented — current user profile |
| `GET` | `/api/devices` | Implemented — list the user's devices |
| `DELETE` | `/api/devices/{id}` | Implemented — remove a device |
| `DELETE` | `/auth/account` | Implemented — delete the authenticated account |

#### Admin (⚠️ TODO)

| Method | Path | Status |
|---|---|---|
| `GET` | `/admin/users` | Not implemented |
| `GET` | `/admin/peers` | Not implemented |
| `PATCH` | `/admin/ad-config` | Not implemented |

### Examples

#### Register

```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123",
    "install_id": "a1b2c3d4-..."
  }'
```

**Response 201:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "rt_abc123...",
  "expires_at": "2026-10-18T10:15:00Z"
}
```

#### Login and Get Current User

```bash
response=$(curl -sS -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"SecurePass123"}')
access_token=$(printf '%s' "$response" | jq -r '.access_token')

curl -H "Authorization: Bearer $access_token" \
  http://localhost:8080/api/me
```

Login is limited to 5 requests per minute per IP. Five failed password attempts lock the account for 15 minutes; a locked-login response includes a `Retry-After` header.

#### Get Entitlement (Guest)

```bash
curl -H "X-Install-ID: a1b2c3d4-..." \
  http://localhost:8080/api/entitlement
```

**Response 200 — Active:**
```json
{
  "active": true,
  "expires_at": "2026-10-19T10:00:00Z",
  "remaining_seconds": 82800,
  "granted_by": "rewarded_ad"
}
```

#### Get VPN Config

```bash
curl -H "X-Install-ID: a1b2c3d4-..." \
  http://localhost:8080/api/vpn/config
```

**Response 200:**
```json
{
  "config": "[Interface]\nPrivateKey = ...\n...",
  "allowed_ip": "10.0.0.5",
  "endpoint": "vpn.yourdomain.com:51820"
}
```

**Response 403:**
```json
{ "error": "no_entitlement" }
```

---

## 🔑 Authentication

### Guest Flow

```
1. App first launch:
   installID = UUIDv4()
   save to encrypted storage

2. Every API call:
   Header: X-Install-ID: <installID>

3. Backend:
   SELECT from anonymous_installs
   ├─ Not found → auto-create
   └─ Found → update last_seen_at
```

### Registered User Flow

```
1. Register/Login → TokenPair
   { access_token (15m), refresh_token (30d) }

2. Client stores:
   - access_token  → memory
   - refresh_token → Android Keystore

3. Every API call:
   Authorization: Bearer <access_token>

4. On 401 (expired):
   POST /auth/refresh { refresh_token }
   → new pair (old revoked)
   → retry original request

5. Logout:
   POST /auth/logout { refresh_token }
   → revoke refresh
   → clear local storage
```

### Token Rotation

- Refresh tokens are **one-time use**
- Each refresh revokes the old token and issues a new one
- Reuse detection → all tokens for user revoked (attack response)

---

## ⏱ Entitlement Model

### Grant Flow

```
User → Rewarded Ad → Completes view
  → AdMob → SSV callback to backend
    → Signature verified (ECDSA)
    → transaction_id checked (replay)
    → INSERT entitlements (expires_at = NOW() + 24h)
  → Client → GET /api/entitlement
    → 200 active
```

### Expiry Flow

```
Background job (every 5 min):
  1. Find active peers with no entitlement > (NOW() + 10min grace)
  2. Remove from WireGuard (wgctrl)
  3. Mark vpn_peers.is_active = FALSE
  4. Client's next /api/vpn/config → 403
```

### Grace Period: 10 Minutes

**Why**: If a user's ad completes a few seconds after their previous 24h expires, we don't want to tear down their tunnel. Also protects against network blips.

### Server-Side Enforcement

**Never trust the client.** The client displays remaining time for UX, but access is enforced by:
1. `GET /api/vpn/config` requires active entitlement
2. Background job tears down expired peers
3. WireGuard itself rejects removed peers

---

## 📺 AdMob SSV

### What is SSV?

**Server-Side Verification** — Google notifies your backend directly when a user completes a rewarded ad, signed with Google's ECDSA key.

**Why needed**: The app cannot be trusted to say "I watched the ad." SSV provides cryptographic proof from Google.

### Setup

1. **AdMob Console** → Rewarded Ad Unit → Enable **Server-side verification**
2. **Callback URL**: `https://api.yourdomain.com/api/reward/ssv`
3. **Custom data** (set in app):

```kotlin
// Guest
val customData = "install:$installId"

// Registered user
val customData = "user:$userId"

val options = ServerSideVerificationOptions.Builder()
    .setCustomData(customData)
    .build()
```

### Verification Logic

```
1. Fetch Google public keys (cache 24h)
   https://www.gstatic.com/admob/reward/verifier-keys.json
2. Find key by key_id
3. Message = RawQuery (signature + key_id removed)
4. SHA-256 hash
5. ECDSA verify
```

### Replay Protection

```sql
-- entitlements.ad_transaction_id UNIQUE
INSERT ... ad_transaction_id = 'txn_abc123'
-- Second attempt → unique violation → "already_processed"
```

### ⚠️ Development Testing

Google cannot reach `localhost`, so testing SSV locally requires a tunnel (ngrok, Cloudflare Tunnel) or temporarily disabling signature verification:

```go
// DEV ONLY — never in production
if os.Getenv("SSV_DEV_SKIP") == "true" {
    return nil
}
```

**Never set `SSV_DEV_SKIP` in production.**

---

## 🔗 VPN Peer Management

### Peer Lifecycle

```
No peer
  ↓ GET /api/vpn/config (with entitlement)
Creating
  ├─ Generate key pair + PSK
  ├─ Allocate IP (10.0.0.2 – 10.0.0.254)
  ├─ wg set wg0 peer <pubkey> (via wgctrl)
  └─ INSERT vpn_peers (is_active = TRUE)
  ↓
Active
  ↓ 24h expires (+ 10min grace)
Expired
  ├─ wg set wg0 peer <pubkey> remove
  └─ UPDATE vpn_peers SET is_active = FALSE
  ↓ Re-reward
Active (new peer created)
```

### Device Limit

| Owner Type | Max Active Peers |
|---|---|
| Guest (install) | 2 |
| Registered user | 2 |

**On exceeding**: oldest peer is auto-removed.

### IP Allocation

```
10.0.0.1       → Server
10.0.0.2-254   → Clients (253 max)
10.0.0.255     → Broadcast (unused)
```

**Strategy**: scan existing `allowed_ip` values, return lowest free.

### Client Config Format

```ini
[Interface]
PrivateKey = <client_private_key>
Address = 10.0.0.5/32
DNS = 1.1.1.1

[Peer]
PublicKey = <server_public_key>
PresharedKey = <psk>
Endpoint = vpn.yourdomain.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

### Why `wgctrl` (not `exec wg`)

- Native Go — faster, no shell injection
- Automatic kernel/userspace mode selection
- Better error handling

**Required privilege**:

```ini
# systemd
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
```

---

## ⚙️ Background Jobs

### Expiry Job

**File**: `internal/jobs/expiry_job.go`
**Frequency**: Every 5 minutes + once on startup

**Tasks**:

| Task | Description |
|---|---|
| `expirePeers` | Remove peers with no active entitlement |
| `cleanupRefreshTokens` | Delete revoked/expired tokens |
| `cleanupEmailTokens` | Delete used/expired tokens |
| `cleanupStaleInstalls` | Delete 30-day inactive guests |

### Multi-Instance Deployment

⚠️ **If running > 1 instance**, add a PostgreSQL advisory lock:

```go
var locked bool
_ = db.QueryRow(ctx, `SELECT pg_try_advisory_lock(987654321)`).Scan(&locked)
if !locked {
    return // another instance is running
}
defer db.Exec(ctx, `SELECT pg_advisory_unlock(987654321)`)
```

### Log Output

```
expiry_job: starting (interval=5m0s, grace=10m0s)
expiry_job: 5 expired peer(s) to revoke
expiry_job: revoked 5/5 peers
expiry_job: deleted 12 old revoked refresh_tokens
```

---

## 🛡 Security

### Implemented

| Control | Status |
|---|---|
| HTTPS only | ⚠️ Caddy (deploy config) |
| Password hashing (Argon2id) | ✅ |
| JWT secret ≥ 32 bytes | ✅ |
| Refresh token rotation | ✅ |
| Refresh tokens hashed in DB | ✅ |
| Brute-force protection | ✅ (5 fails → 15min lock) |
| Login lockout `Retry-After` header | ✅ |
| Per-IP rate limiting | ✅ |
| Timing attack prevention | ✅ (dummy hash verify) |
| SSV signature verification | ✅ ECDSA |
| SSV replay protection | ✅ UNIQUE constraint |
| SQL injection prevention | ✅ pgx prepared statements |

### TODO

| Control | Priority |
|---|---|
| Admin TOTP 2FA | 🟡 Medium |
| Encrypt `client_private_key` at rest | 🔴 High (production) |
| Input validation middleware | 🟡 Medium |
| CORS (if web client added) | 🟢 Low |

### Rate Limits

Limits are in-memory and applied per client IP.

| Endpoint | Limit |
|---|---|
| `POST /auth/login` | 5 / min / IP |
| `POST /auth/register` | 3 / hour / IP |
| `POST /auth/refresh` | 10 / min / IP |

### Privacy

Document in your **Privacy Policy**:
- No VPN traffic is logged
- AdMob SDK collects device identifiers
- VPN traffic is **never** shared with ad networks

⚠️ **Apple Guideline 5.4** requires this disclosure.

---

## 🚢 Deployment

### Production Checklist

| Item | Action |
|---|---|
| Server | Oracle Cloud ARM (Singapore/Japan) |
| OS | Ubuntu 22.04 |
| Go | 1.22+ |
| Postgres | 15+, localhost binding only |
| WireGuard | Kernel module enabled |
| Reverse Proxy | Caddy (auto HTTPS) |
| Process Manager | systemd |
| Firewall | UFW (22, 80, 443, 51820/udp) |
| Backup | Daily `pg_dump` + `wg0.conf` |
| Monitoring | Netdata / Prometheus (optional) |

### Systemd Unit

```ini
# /etc/systemd/system/vpn-backend.service
[Unit]
Description=VPN Backend
After=network.target postgresql.service

[Service]
Type=simple
User=vpn-backend
WorkingDirectory=/opt/vpn-backend
EnvironmentFile=/opt/vpn-backend/.env
ExecStart=/opt/vpn-backend/vpn-server
Restart=on-failure
RestartSec=5s

AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/etc/wireguard

[Install]
WantedBy=multi-user.target
```

### Caddy Config

```
# /etc/caddy/Caddyfile
api.yourdomain.com {
    reverse_proxy localhost:8080
    encode gzip
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options "nosniff"
    }
}
```

### Build & Deploy

```bash
# Local build (Linux ARM64 for Oracle ARM)
GOOS=linux GOARCH=arm64 go build -o vpn-server ./cmd/server

# Upload
scp vpn-server user@vm:/opt/vpn-backend/

# Restart
ssh user@vm 'sudo systemctl restart vpn-backend'
```

---

## 🔧 Troubleshooting

### Common Errors

| Error | Fix |
|---|---|
| `password authentication failed` | Check `DATABASE_URL` password |
| `no such device` (WireGuard) | `sudo wg-quick up wg0` |
| `operation not permitted` (wgctrl) | Add `CAP_NET_ADMIN` or run as root |
| `JWT_SECRET must be at least 32 bytes` | Use a longer secret |
| `SSV invalid_signature` | Check callback URL, or `SSV_DEV_SKIP=true` (dev only) |
| `no_entitlement` | User must watch ad first |

### Debug Commands

```bash
# DB tables
psql "$DATABASE_URL" -c "\dt"

# Active peers
sudo wg show wg0

# Backend logs
sudo journalctl -u vpn-backend -f

# Postgres logs
sudo tail -f /var/log/postgresql/postgresql-15-main.log

# DB connection test
psql "$DATABASE_URL" -c "SELECT NOW();"
```

### Manual Expiry Test

```sql
-- Create test peer with expired entitlement
INSERT INTO anonymous_installs (install_id) VALUES ('test-expire');
INSERT INTO vpn_peers (install_id, public_key, allowed_ip, client_private_key)
SELECT id, 'testpub==', '10.0.0.99', 'testpriv=='
FROM anonymous_installs WHERE install_id = 'test-expire';

INSERT INTO entitlements (install_id, granted_by, expires_at)
SELECT id, 'rewarded_ad', NOW() - INTERVAL '1 hour'
FROM anonymous_installs WHERE install_id = 'test-expire';

-- Wait 5 min OR trigger manually in dev
-- Verify:
SELECT id, is_active FROM vpn_peers WHERE public_key = 'testpub==';
-- → is_active = false
```

---

## 🗺 Roadmap

### MVP (Current)

- [x] Guest mode (`install_id`)
- [x] Registered users (email + password)
- [x] JWT + refresh tokens
- [x] 24h entitlement (server-enforced)
- [x] AdMob SSV integration
- [x] WireGuard peer management
- [x] Expiry background job
- [x] Device limit (2 per owner)

### Next

- [x] Rate limiting for login, registration, and token refresh
- [ ] Admin endpoints (`/admin/users`, `/admin/peers`, `/admin/ad-config`)
- [ ] Admin TOTP 2FA
- [x] `/api/me`, `/api/devices`
- [x] Account deletion endpoint
- [ ] Encrypt `client_private_key` at rest
- [ ] Email verification flow (currently default `TRUE`)
- [ ] Password reset flow

### Future

- [ ] Google Sign-In
- [ ] Web admin dashboard (React)
- [ ] Multiple server regions
- [ ] Prometheus metrics
- [ ] Subscription tier (paid)

---

## 📎 Appendix

### Glossary

| Term | Meaning |
|---|---|
| **SSV** | Server-Side Verification (AdMob) |
| **PSK** | Pre-Shared Key (WireGuard) |
| **Entitlement** | 24-hour access grant |
| **Peer** | WireGuard client |
| **Guest** | Non-registered user (install_id) |
| **Owner** | Peer/entitlement owner (`user` or `install`) |

### Related Files

- Migration SQL: `internal/db/migrations/`
- Models: `internal/models/models.go`
- Handlers: `internal/handlers/`

### Contributing

1. Create a feature branch
2. Write migration for any schema change
3. Update `README.md` for new endpoints
4. Add tests (TODO)
5. Submit PR

---

**Last Updated**: 2026-10-22
**Version**: 1.0.0
**Maintainer**: [Your Name]