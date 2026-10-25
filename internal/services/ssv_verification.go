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
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
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

func ssvDevSkip() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("SSV_DEV_SKIP")))
	if v == "true" || v == "1" {
		return true
	}
	// legacy misspelling from earlier local .env files
	v = strings.ToLower(strings.TrimSpace(os.Getenv("SSV_DEV_Skip")))
	return v == "true" || v == "1"
}

// Verify checks the ECDSA signature on an AdMob SSV callback.
func (v *SSVVerifier) Verify(rawQuery string, query url.Values) error {
	if ssvDevSkip() {
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

	message := buildSSVMessage(rawQuery)
	sig, err := decodeSSVSignature(signatureB64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	hash := sha256.Sum256([]byte(message))
	if !ecdsa.VerifyASN1(pubKey, hash[:], sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// buildSSVMessage keeps query params in original order, minus signature and key_id.
func buildSSVMessage(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	parts := strings.Split(rawQuery, "&")
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		key := p
		if i := strings.IndexByte(p, '='); i >= 0 {
			key = p[:i]
		}
		decoded, err := url.QueryUnescape(key)
		if err != nil {
			decoded = key
		}
		if decoded == "signature" || decoded == "key_id" {
			continue
		}
		kept = append(kept, p)
	}
	return strings.Join(kept, "&")
}

func decodeSSVSignature(signatureB64 string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.StdEncoding,
		base64.RawStdEncoding,
	}
	var lastErr error
	for _, enc := range encodings {
		sig, err := enc.DecodeString(signatureB64)
		if err == nil {
			return sig, nil
		}
		lastErr = err
	}
	return nil, lastErr
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
