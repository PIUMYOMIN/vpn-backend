User → [Connect button]
  │
  ▼
App → GET /api/vpn/config
      Header: X-Install-ID: <uuid>
  │
  ▼
Backend (IdentityMiddleware):
  1. Read X-Install-ID
  2. UPSERT anonymous_installs (auto-create if missing)
  3. Set Identity{InstallID} in context
  │
  ▼
VPNHandler.GetConfig:
  1. Entitlement စစ် (expires_at > NOW())
     ├─ မရှိ → 403 no_entitlement
     └─ ရှိ → ဆက်
  2. Active peer ရှာ
     ├─ ရှိ → config generate
     └─ မရှိ → အသစ်ဖန်တီး:
          a. Device limit စစ် (max 2) → အဟောင်းဆုံး ဖျက်
          b. WireGuard key pair + PSK generate
          c. IP allocate (10.0.0.2–254)
          d. wgctrl → AddPeer
          e. INSERT vpn_peers (is_active=TRUE)
  3. Client config generate
  │
  ▼
App → Rust core → WireGuard tunnel ချိတ်
  │
  ▼
[Connected state]