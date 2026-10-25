Guest က app သုံးနေတယ် (install_id, peers, entitlements ရှိ)
  │
  ▼
User → Register (email, password, install_id)
  │
  ▼
AuthHandler.Register:
  1. Password hash (Argon2id)
  2. INSERT users
  3. BEGIN transaction:
     a. UPDATE entitlements SET user_id = new, install_id = NULL
        WHERE install_id = <install UUID> AND expires_at > NOW()
     b. UPDATE vpn_peers SET user_id = new, install_id = NULL
        WHERE install_id = <install UUID>
     c. DELETE anonymous_installs
     COMMIT
  4. Generate token pair
  5. Return tokens
  │
  ▼
Guest → User အဖြစ် ကူးပြောင်း (entitlement မ ပျက်)