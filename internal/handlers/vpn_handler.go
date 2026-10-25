package handlers

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/piumyomin/vpn-backend/internal/auth"
)

// WireGuardService wraps wg operations.
// Implementation: internal/services/wireguard_service.go
type WireGuardService interface {
	GenerateKeyPair() (privateKey, publicKey string, err error)
	GeneratePresharedKey() (string, error)
	AddPeer(publicKey, presharedKey, allowedIP string) error
	RemovePeer(publicKey string) error
}

// VPNConfig holds server-side WireGuard parameters.
type VPNConfig struct {
	ServerPublicKey string
	Endpoint        string
	Port            int
	DNS             string
	Subnet          string // e.g. "10.0.0"
}

type VPNHandler struct {
	db     *pgxpool.Pool
	wgSvc  WireGuardService
	cfg    VPNConfig
	maxPer int // max peers per owner (device limit)
}

func NewVPNHandler(db *pgxpool.Pool, wgSvc WireGuardService, cfg VPNConfig) *VPNHandler {
	if cfg.Subnet == "" {
		cfg.Subnet = "10.0.0"
	}
	return &VPNHandler{db: db, wgSvc: wgSvc, cfg: cfg, maxPer: 2}
}

type peerRow struct {
	ID               string
	PublicKey        string
	PresharedKey     string
	AllowedIP        string
	ClientPrivateKey string
}

// GET /api/vpn/config
// Entitlement ရှိမှ WireGuard client config ပေး
func (h *VPNHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	ident := auth.GetIdentity(r)
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	// 1. Entitlement check
	hasEnt := false
	var err error
	if ident.IsUser() {
		err = h.db.QueryRow(ctx, `
      SELECT EXISTS(
        SELECT 1 FROM entitlements
        WHERE user_id = $1 AND expires_at > NOW()
      )
    `, ident.UserID).Scan(&hasEnt)
	} else {
		err = h.db.QueryRow(ctx, `
      SELECT EXISTS(
        SELECT 1 FROM entitlements e
        JOIN anonymous_installs a ON a.id = e.install_id
        WHERE a.install_id = $1 AND e.expires_at > NOW()
      )
    `, ident.InstallID).Scan(&hasEnt)
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "db_error")
		return
	}
	if !hasEnt {
		respondError(w, http.StatusForbidden, "no_entitlement")
		return
	}

	// 2. Get or create peer
	peer, err := h.getOrCreatePeer(ctx, ident)
	if err != nil {
		log.Printf("vpn: getOrCreatePeer failed: %v", err)
		respondError(w, http.StatusInternalServerError, "peer_error")
		return
	}

	// 3. Build client config
	clientCfg := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32
DNS = %s

[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = %s:%d
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`,
		peer.ClientPrivateKey,
		peer.AllowedIP,
		h.cfg.DNS,
		h.cfg.ServerPublicKey,
		peer.PresharedKey,
		h.cfg.Endpoint,
		h.cfg.Port,
	)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"config":     clientCfg,
		"allowed_ip": peer.AllowedIP,
		"endpoint":   fmt.Sprintf("%s:%d", h.cfg.Endpoint, h.cfg.Port),
	})
}

// getOrCreatePeer returns an active peer or creates one if needed.
func (h *VPNHandler) getOrCreatePeer(ctx context.Context, ident auth.Identity) (*peerRow, error) {
	var (
		peer peerRow
		err  error
	)
	// Existing active peer?
	if ident.IsUser() {
		err = h.db.QueryRow(ctx, `
      SELECT id, public_key, COALESCE(preshared_key, ''), allowed_ip,
             COALESCE(client_private_key, '')
      FROM vpn_peers
      WHERE user_id = $1 AND is_active = TRUE
      ORDER BY created_at ASC LIMIT 1
    `, ident.UserID).Scan(&peer.ID, &peer.PublicKey, &peer.PresharedKey, &peer.AllowedIP, &peer.ClientPrivateKey)
	} else {
		err = h.db.QueryRow(ctx, `
      SELECT p.id, p.public_key, COALESCE(p.preshared_key, ''), p.allowed_ip,
             COALESCE(p.client_private_key, '')
      FROM vpn_peers p
      JOIN anonymous_installs a ON a.id = p.install_id
      WHERE a.install_id = $1 AND p.is_active = TRUE
      ORDER BY p.created_at ASC LIMIT 1
    `, ident.InstallID).Scan(&peer.ID, &peer.PublicKey, &peer.PresharedKey, &peer.AllowedIP, &peer.ClientPrivateKey)
	}

	if err == nil && peer.ClientPrivateKey != "" {
		return &peer, nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	// Enforce device/peer limit (oldest get removed)
	if err := h.enforcePeerLimit(ctx, ident); err != nil {
		return nil, err
	}

	// Generate keys
	priv, pub, err := h.wgSvc.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	psk, err := h.wgSvc.GeneratePresharedKey()
	if err != nil {
		return nil, err
	}
	nextIP, err := h.nextAvailableIP(ctx)
	if err != nil {
		return nil, err
	}

	// Add on WireGuard server
	if err := h.wgSvc.AddPeer(pub, psk, nextIP); err != nil {
		return nil, err
	}

	// Persist
	peer = peerRow{
		PublicKey:        pub,
		PresharedKey:     psk,
		AllowedIP:        nextIP,
		ClientPrivateKey: priv,
	}

	if ident.IsUser() {
		err = h.db.QueryRow(ctx, `
      INSERT INTO vpn_peers
        (user_id, public_key, preshared_key, allowed_ip, client_private_key)
      VALUES ($1, $2, $3, $4, $5) RETURNING id
    `, ident.UserID, pub, psk, nextIP, priv).Scan(&peer.ID)
	} else {
		err = h.db.QueryRow(ctx, `
      INSERT INTO vpn_peers
        (install_id, public_key, preshared_key, allowed_ip, client_private_key)
      SELECT a.id, $2, $3, $4, $5
      FROM anonymous_installs a WHERE a.install_id = $1
      RETURNING id
    `, ident.InstallID, pub, psk, nextIP, priv).Scan(&peer.ID)
	}
	if err != nil {
		// rollback WG change
		_ = h.wgSvc.RemovePeer(pub)
		return nil, err
	}
	return &peer, nil
}

// enforcePeerLimit removes oldest peers if limit exceeded.
func (h *VPNHandler) enforcePeerLimit(ctx context.Context, ident auth.Identity) error {
	var rows pgx.Rows
	var err error

	if ident.IsUser() {
		rows, err = h.db.Query(ctx, `
      SELECT id, public_key FROM vpn_peers
      WHERE user_id = $1 AND is_active = TRUE
      ORDER BY created_at ASC
    `, ident.UserID)
	} else {
		rows, err = h.db.Query(ctx, `
      SELECT p.id, p.public_key FROM vpn_peers p
      JOIN anonymous_installs a ON a.id = p.install_id
      WHERE a.install_id = $1 AND p.is_active = TRUE
      ORDER BY p.created_at ASC
    `, ident.InstallID)
	}
	if err != nil {
		return err
	}
	defer rows.Close()

	type p struct{ id, pub string }
	var peers []p
	for rows.Next() {
		var it p
		if err := rows.Scan(&it.id, &it.pub); err != nil {
			return err
		}
		peers = append(peers, it)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	// remove oldest until count < maxPer
	for len(peers) >= h.maxPer {
		oldest := peers[0]
		peers = peers[1:]
		_ = h.wgSvc.RemovePeer(oldest.pub)
		_, _ = h.db.Exec(ctx, `DELETE FROM vpn_peers WHERE id = $1`, oldest.id)
	}
	return nil
}

// nextAvailableIP scans existing allowed_ip and returns next free 10.0.0.X.
func (h *VPNHandler) nextAvailableIP(ctx context.Context) (string, error) {
	rows, err := h.db.Query(ctx, `SELECT allowed_ip FROM vpn_peers`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	used := map[int]bool{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			continue
		}
		var a, b, c, d int
		if _, err := fmt.Sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d); err == nil {
			used[d] = true
		}
	}
	for i := 2; i <= 254; i++ { // 10.0.0.1 = server, skip
		if !used[i] {
			return fmt.Sprintf("%s.%d", h.cfg.Subnet, i), nil
		}
	}
	return "", errors.New("no available IP")
}
