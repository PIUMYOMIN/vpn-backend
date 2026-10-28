package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	Port              string
	AppURL            string
	DatabaseURL       string
	JWTSecret         string
	JWTAccessTTL      string // e.g. "15m"
	JWTRefreshTTL     string // e.g. "720h"
	WGInterface       string // e.g. "wg0"
	WGNoop            bool
	WGServerPublicKey string
	WGEndpoint        string
	WGPort            int
	WGDNS             string
	ResendAPIKey      string
	EmailFrom         string // e.g. "VPN App <noreply@yourdomain.com>"
}

func Load() (*Config, error) {
	_ = godotenv.Load() // .env optional

	wgPort, _ := strconv.Atoi(getEnv("WG_PORT", "51820"))
	wgNoop, _ := strconv.ParseBool(getEnv("WG_NOOP", "false"))

	cfg := &Config{
		Port:              getEnv("PORT", "8080"),
		AppURL:            getEnv("APP_URL", "http://localhost:8080"),
		DatabaseURL:       os.Getenv("DATABASE_URL"),
		JWTSecret:         os.Getenv("JWT_SECRET"),
		JWTAccessTTL:      getEnv("ACCESS_TOKEN_TTL", "15m"),
		JWTRefreshTTL:     getEnv("REFRESH_TOKEN_TTL", "720h"),
		WGInterface:       getEnv("WG_INTERFACE", "wg0"),
		WGNoop:            wgNoop,
		WGServerPublicKey: os.Getenv("WG_SERVER_PUBLIC_KEY"),
		WGEndpoint:        os.Getenv("WG_ENDPOINT"),
		WGPort:            wgPort,
		WGDNS:             getEnv("WG_DNS", "1.1.1.1"),
		ResendAPIKey:      os.Getenv("RESEND_API_KEY"),
		EmailFrom:         getEnv("EMAIL_FROM", "VPN App <noreply@example.com>"),
	}

	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}
	if cfg.JWTSecret == "" {
		return nil, fmt.Errorf("JWT_SECRET is required")
	}
	if len(cfg.JWTSecret) < 32 {
		return nil, fmt.Errorf("JWT_SECRET must be at least 32 bytes")
	}
	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
