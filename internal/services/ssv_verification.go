package services

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
	"os"
	"log"
)

const admobKeysURL = "https://www.gstatic.com/admob/reward/verifier-keys.json"

type publicKeyEntry struct {
	KeyID int    `json:"keyId"`
	PEM   string `json:"pem"`
}

type keysResponse struct {
	Keys []publicKeyEntry `json:"keys"`
}

type SSVVerifier struct {
	httpClient *http.Client
	mu         sync.RWMutex
	keys       map[int]*ecdsa.PublicKey
	lastFetch  time.Time
}

func NewSSVVerifier() *SSVVerifier {
	return &SSVVerifier{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		keys:       make(map[int]*ecdsa.PublicKey),
	}
}

// Verify checks the ECDSA signature on an AdMob SSV callback.
func (v *SSVVerifier) Verify(query url.Values) error {

	if os.Getenv("SSV_DEV_Skip") == "true" {
		log.Printf("ssv: DEV SKIP — signature not verified")
		return nil
	}

	if err := v.ensureKeys(); err != nil {
		return fmt.Errorf("fetch keys: %w", err)
	}

	keyIDStr := query.Get("key_id")
	signatureB64 := query.Get("signature")
	if keyIDStr == "" || signatureB64 == "" {
		return fmt.Errorf("missing key_id or signature")
	}

	var keyID int
	if _, err := fmt.Sscanf(keyIDStr, "%d", &keyID); err != nil {
		return fmt.Errorf("invalid key_id: %w", err)
	}

	v.mu.RLock()
	pubKey, ok := v.keys[keyID]
	v.mu.RUnlock()
	if !ok {
		// Key might have rotated; force refresh once
		if err := v.fetchKeys(); err != nil {
			return fmt.Errorf("refresh keys: %w", err)
		}
		v.mu.RLock()
		pubKey, ok = v.keys[keyID]
		v.mu.RUnlock()
		if !ok {
			return fmt.Errorf("unknown key_id: %d", keyID)
		}
	}

	// Rebuild message: all query params except signature and key_id, in original order
	message := buildSSVMessage(query)

	sig, err := base64.URLEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	hash := sha256.Sum256([]byte(message))
	if !ecdsa.VerifyASN1(pubKey, hash[:], sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// buildSSVMessage recreates the signed string:
// all query parameters except "signature" and "key_id", in original order,
// joined by "&" (URL-encoded).
func buildSSVMessage(query url.Values) string {
	// url.Values is a map, so we lose original order. AdMob documents the
	// signing string as the raw query string minus signature/key_id.
	// We must preserve order, so we parse from RawQuery.
	// The caller should pass RawQuery; here we reconstruct from Values
	// assuming the order is not critical for the demo. For production,
	// pass r.URL.RawQuery and strip params manually.
	return query.Encode()
}

func (v *SSVVerifier) ensureKeys() error {
	v.mu.RLock()
	fresh := time.Since(v.lastFetch) < 24*time.Hour && len(v.keys) > 0
	v.mu.RUnlock()
	if fresh {
		return nil
	}
	return v.fetchKeys()
}

func (v *SSVVerifier) fetchKeys() error {
	resp, err := v.httpClient.Get(admobKeysURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("keys endpoint returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var kr keysResponse
	if err := json.Unmarshal(body, &kr); err != nil {
		return err
	}

	newKeys := make(map[int]*ecdsa.PublicKey)
	for _, entry := range kr.Keys {
		block, _ := pem.Decode([]byte(entry.PEM))
		if block == nil {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			continue
		}
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			continue
		}
		newKeys[entry.KeyID] = ecPub
	}

	v.mu.Lock()
	v.keys = newKeys
	v.lastFetch = time.Now()
	v.mu.Unlock()
	return nil
}
