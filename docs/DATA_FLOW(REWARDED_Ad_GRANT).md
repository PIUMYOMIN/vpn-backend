User → [Connect button] → entitlement မရှိ → Dialog
  │
  ▼
App → AdMob Rewarded Ad ပြ
  │
  ▼ (user ကြည့်ပြီး)
AdMob → App (onUserEarnedReward) — UX only, NOT trusted
  │
  ▼
AdMob → Backend (SSV callback, server-to-server)
  POST /api/reward/ssv
  ?transaction_id=abc123
  &custom_data=user:<uuid> | install:<uuid>
  &signature=<base64>
  &key_id=1
  &...
  │
  ▼
RewardHandler.SSVCallback:
  1. ECDSA verify (Google public keys, cached 24h)
  2. transaction_id replay စစ် (UNIQUE constraint)
  3. ad_config.reward_hours ဖတ် (24)
  4. custom_data parse → user / install
  5. INSERT entitlements (expires_at = NOW() + 24h)
  │
  ▼
App → GET /api/entitlement → 200 active
  │
  ▼
App → GET /api/vpn/config → tunnel ချိတ်