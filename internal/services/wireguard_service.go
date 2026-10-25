package services

import (
  "encoding/base64"
  "fmt"
  "log"
  "net"

  "golang.zx2c4.com/wireguard/wgctrl"
  "golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WireGuardService is the interface used by handlers and background jobs.
// Two implementations exist:
//   - wgctrlService       : real WireGuard (Linux with kernel module)
//   - NoopWireGuardService: no-op for local dev on Windows / macOS
type WireGuardService interface {
  Close() error
  GenerateKeyPair() (privateKey, publicKey string, err error)
  GeneratePresharedKey() (string, error)
  AddPeer(publicKey, presharedKey, allowedIP string) error
  RemovePeer(publicKey string) error
}

// ------------------------------------------------------------------
// Real implementation (Linux)
// ------------------------------------------------------------------

type wgctrlService struct {
  client    *wgctrl.Client
  iface     string
  serverPub wgtypes.Key
}

// NewWireGuardService connects to the WireGuard interface via wgctrl.
// On Linux this requires CAP_NET_ADMIN (or root) and an active wg0 interface.
func NewWireGuardService(iface string) (WireGuardService, error) {
  client, err := wgctrl.New()
  if err != nil {
    return nil, fmt.Errorf("wgctrl new: %w", err)
  }
  dev, err := client.Device(iface)
  if err != nil {
    _ = client.Close()
    return nil, fmt.Errorf("get device %q: %w", iface, err)
  }
  log.Printf("wg: connected to interface %q (server pubkey=%s)",
    iface, trunc(dev.PublicKey.String()))
  return &wgctrlService{
    client:    client,
    iface:     iface,
    serverPub: dev.PublicKey,
  }, nil
}

func (s *wgctrlService) Close() error {
  return s.client.Close()
}

func (s *wgctrlService) GenerateKeyPair() (string, string, error) {
  priv, err := wgtypes.GeneratePrivateKey()
  if err != nil {
    return "", "", err
  }
  pub := priv.PublicKey()
  return base64.StdEncoding.EncodeToString(priv[:]),
    base64.StdEncoding.EncodeToString(pub[:]), nil
}

func (s *wgctrlService) GeneratePresharedKey() (string, error) {
  key, err := wgtypes.GenerateKey()
  if err != nil {
    return "", err
  }
  return base64.StdEncoding.EncodeToString(key[:]), nil
}

func (s *wgctrlService) AddPeer(pubKeyB64, pskB64, allowedIP string) error {
  pub, err := wgtypes.ParseKey(pubKeyB64)
  if err != nil {
    return fmt.Errorf("parse public key: %w", err)
  }
  psk, err := wgtypes.ParseKey(pskB64)
  if err != nil {
    return fmt.Errorf("parse psk: %w", err)
  }
  _, ipNet, err := net.ParseCIDR(allowedIP + "/32")
  if err != nil {
    return fmt.Errorf("parse allowed ip %q: %w", allowedIP, err)
  }

  cfg := wgtypes.Config{
    Peers: []wgtypes.PeerConfig{{
      PublicKey:         pub,
      PresharedKey:      &psk,
      AllowedIPs:        []net.IPNet{*ipNet},
      ReplaceAllowedIPs: true,
    }},
  }
  if err := s.client.ConfigureDevice(s.iface, cfg); err != nil {
    return fmt.Errorf("configure device: %w", err)
  }
  log.Printf("wg: added peer %s allowed_ip=%s", trunc(pubKeyB64), allowedIP)
  return nil
}

func (s *wgctrlService) RemovePeer(pubKeyB64 string) error {
  pub, err := wgtypes.ParseKey(pubKeyB64)
  if err != nil {
    return fmt.Errorf("parse public key: %w", err)
  }
  cfg := wgtypes.Config{
    Peers: []wgtypes.PeerConfig{{
      PublicKey: pub,
      Remove:    true,
    }},
  }
  if err := s.client.ConfigureDevice(s.iface, cfg); err != nil {
    return fmt.Errorf("remove peer: %w", err)
  }
  log.Printf("wg: removed peer %s", trunc(pubKeyB64))
  return nil
}

// ------------------------------------------------------------------
// Noop implementation (Windows / macOS / local dev)
// ------------------------------------------------------------------// NoopWireGuardService implements WireGuardService without touching any
// real WireGuard interface. It still generates real (pure-Go) keys so the
// rest of the flow — client config generation, DB persistence, expiry
// job — behaves exactly like production.
//
// Use this on platforms where WireGuard kernel support is unavailable
// (Windows, macOS) or when you want to run the backend without a VPN
// server for development.
type NoopWireGuardService struct{}

func (s *NoopWireGuardService) Close() error { return nil }

func (s *NoopWireGuardService) GenerateKeyPair() (string, string, error) {
  priv, err := wgtypes.GeneratePrivateKey()
  if err != nil {
    return "", "", err
  }
  pub := priv.PublicKey()
  return base64.StdEncoding.EncodeToString(priv[:]),
    base64.StdEncoding.EncodeToString(pub[:]), nil
}

func (s *NoopWireGuardService) GeneratePresharedKey() (string, error) {
  key, err := wgtypes.GenerateKey()
  if err != nil {
    return "", err
  }
  return base64.StdEncoding.EncodeToString(key[:]), nil
}

func (s *NoopWireGuardService) AddPeer(pubKeyB64, pskB64, allowedIP string) error {
  log.Printf("noop-wg: AddPeer pub=%s ip=%s (skipped — no kernel WG)",
    trunc(pubKeyB64), allowedIP)
  return nil
}

func (s *NoopWireGuardService) RemovePeer(pubKeyB64 string) error {
  log.Printf("noop-wg: RemovePeer pub=%s (skipped — no kernel WG)",
    trunc(pubKeyB64))
  return nil
}

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

func trunc(s string) string {
  if len(s) > 8 {
    return s[:8] + "…"
  }
  return s
}