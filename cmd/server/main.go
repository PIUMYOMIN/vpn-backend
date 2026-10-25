package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/piumyomin/vpn-backend/internal/auth"
	"github.com/piumyomin/vpn-backend/internal/config"
	"github.com/piumyomin/vpn-backend/internal/db"
	"github.com/piumyomin/vpn-backend/internal/handlers"
	"github.com/piumyomin/vpn-backend/internal/jobs"
	"github.com/piumyomin/vpn-backend/internal/services"
)

func main() {
	// ============================================================
	// 1. Config
	// ============================================================
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// ============================================================
	// 2. Root context (cancel on SIGINT/SIGTERM)
	// ============================================================
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// ============================================================
	// 3. Database
	// ============================================================
	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer pool.Close()
	log.Printf("db: connected")

	// ============================================================
	// 4. JWT service
	// ============================================================
	accessTTL, err := time.ParseDuration(cfg.JWTAccessTTL)
	if err != nil {
		log.Fatalf("parse ACCESS_TOKEN_TTL: %v", err)
	}
	refreshTTL, err := time.ParseDuration(cfg.JWTRefreshTTL)
	if err != nil {
		log.Fatalf("parse REFRESH_TOKEN_TTL: %v", err)
	}
	jwtSvc := auth.NewJWTService(cfg.JWTSecret, accessTTL, refreshTTL, pool)

	// ============================================================
	// 5. External services
	// ============================================================

	// --- Email ---
	emailSvc := services.NewEmailService(
		cfg.ResendAPIKey,
		cfg.EmailFrom,
		cfg.AppURL,
	)

	// --- AdMob SSV verifier ---
	ssvVerifier := services.NewSSVVerifier()

	// --- WireGuard (real on Linux, noop on Windows/dev) ---
	var wgSvc services.WireGuardService

	if runtime.GOOS == "windows" {
		log.Printf("wg: running on Windows — using NOOP (dev mode)")
		wgSvc = &services.NoopWireGuardService{}
	} else if cfg.WGEndpoint == "" || cfg.WGEndpoint == "placeholder" {
		log.Printf("wg: WG_ENDPOINT not set — using NOOP (dev mode)")
		wgSvc = &services.NoopWireGuardService{}
	} else {
		realSvc, err := services.NewWireGuardService(cfg.WGInterface)
		if err != nil {
			log.Fatalf("wireguard: %v (set WG_ENDPOINT=placeholder to use noop)", err)
		}
		wgSvc = realSvc
	}
	defer wgSvc.Close()

	// ============================================================
	// 6. Handlers
	// ============================================================
	authHandler := handlers.NewAuthHandler(pool, jwtSvc, emailSvc)
	entHandler := handlers.NewEntitlementHandler(pool)
	rewHandler := handlers.NewRewardHandler(pool, ssvVerifier)
	userHandler := handlers.NewUserHandler(pool)
	deviceHandler := handlers.NewDeviceHandler(pool)
	vpnHandler := handlers.NewVPNHandler(pool, wgSvc, handlers.VPNConfig{
		ServerPublicKey: cfg.WGServerPublicKey,
		Endpoint:        cfg.WGEndpoint,
		Port:            cfg.WGPort,
		DNS:             cfg.WGDNS,
		Subnet:          "10.0.0",
	})
	adminHandler := handlers.NewAdminHandler(pool, wgSvc)

	// ============================================================
	// 7. Rate limiters (per-IP, in-memory)
	// ============================================================
	loginLimiter := auth.NewRateLimiter(5, 1*time.Minute)    // 5 / min / IP
	registerLimiter := auth.NewRateLimiter(3, 1*time.Hour)   // 3 / hour / IP
	forgotLimiter := auth.NewRateLimiter(3, 1*time.Hour)     // 3 / hour / IP
	resetLimiter := auth.NewRateLimiter(5, 1*time.Hour)      // 5 / hour / IP
	refreshLimiter := auth.NewRateLimiter(10, 1*time.Minute) // 10 / min / IP

	// ============================================================
	// 8. Routes
	// ============================================================
	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Public auth (with rate limiting)
	mux.Handle("POST /auth/register", registerLimiter.Middleware(http.HandlerFunc(authHandler.Register)))
	mux.Handle("POST /auth/login", loginLimiter.Middleware(http.HandlerFunc(authHandler.Login)))
	mux.Handle("POST /auth/refresh", refreshLimiter.Middleware(http.HandlerFunc(authHandler.Refresh)))
	mux.HandleFunc("POST /auth/logout", authHandler.Logout)
	mux.Handle("POST /auth/forgot-password", forgotLimiter.Middleware(http.HandlerFunc(authHandler.ForgotPassword)))
	mux.Handle("POST /auth/reset-password", resetLimiter.Middleware(http.HandlerFunc(authHandler.ResetPassword)))

	// Guest OR registered user
	mux.Handle("GET /api/entitlement", auth.RequireIdentity(http.HandlerFunc(entHandler.Get)))
	mux.Handle("GET /api/vpn/config", auth.RequireIdentity(http.HandlerFunc(vpnHandler.GetConfig)))

	// User-only
	mux.Handle("GET /api/me", auth.RequireUser(http.HandlerFunc(userHandler.Me)))
	mux.Handle("GET /api/devices", auth.RequireUser(http.HandlerFunc(deviceHandler.List)))
	mux.Handle("DELETE /api/devices/{id}", auth.RequireUser(http.HandlerFunc(deviceHandler.Delete)))
	mux.Handle("DELETE /auth/account", auth.RequireUser(http.HandlerFunc(authHandler.DeleteAccount)))

	// AdMob SSV (server-to-server; no auth header — verified by ECDSA signature)
	mux.HandleFunc("POST /api/reward/ssv", rewHandler.SSVCallback)

	// ============================================================
	// Admin (role=admin required)
	// ============================================================
	mux.Handle("GET /admin/users", auth.RequireAdmin(http.HandlerFunc(adminHandler.ListUsers)))
	mux.Handle("PATCH /admin/users/{id}", auth.RequireAdmin(http.HandlerFunc(adminHandler.UpdateUser)))
	mux.Handle("POST /admin/users/{id}/grant", auth.RequireAdmin(http.HandlerFunc(adminHandler.GrantEntitlement)))
	mux.Handle("GET /admin/peers", auth.RequireAdmin(http.HandlerFunc(adminHandler.ListPeers)))
	mux.Handle("DELETE /admin/peers/{id}", auth.RequireAdmin(http.HandlerFunc(adminHandler.DeletePeer)))
	mux.Handle("GET /admin/ad-config", auth.RequireAdmin(http.HandlerFunc(adminHandler.GetAdConfig)))
	mux.Handle("PATCH /admin/ad-config", auth.RequireAdmin(http.HandlerFunc(adminHandler.UpdateAdConfig)))
	mux.Handle("GET /admin/stats", auth.RequireAdmin(http.HandlerFunc(adminHandler.Stats)))

	// Wrap everything with IdentityMiddleware
	// root := auth.IdentityMiddleware(jwtSvc, pool)(mux)

	root := auth.RequestLogger(
		auth.IdentityMiddleware(jwtSvc, pool)(mux),
	)

	// ============================================================
	// 9. Background job (24h expiry)
	// ============================================================
	expiryJob := jobs.NewExpiryJob(pool, wgSvc)
	go expiryJob.Start(ctx)

	// ============================================================
	// 10. HTTP server
	// ============================================================
	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           root,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("server listening on :%s", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	// ============================================================
	// 11. Graceful shutdown
	// ============================================================
	<-ctx.Done()
	log.Printf("shutdown signal received")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown: %v", err)
	}
	log.Printf("server stopped")
}
