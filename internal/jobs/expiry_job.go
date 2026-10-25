package jobs

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PeerRemover is the subset of WireGuardService needed by this job.
// (Same interface shape as handlers.WireGuardService.)
type PeerRemover interface {
	RemovePeer(publicKey string) error
}

type ExpiryJob struct {
	db          *pgxpool.Pool
	wg          PeerRemover
	interval    time.Duration
	gracePeriod time.Duration // ဒီအချိန်အတွင်း re-grant လုပ်ရင် peer ကို မဖြုတ်
}

func NewExpiryJob(db *pgxpool.Pool, wg PeerRemover) *ExpiryJob {
	return &ExpiryJob{
		db:          db,
		wg:          wg,
		interval:    5 * time.Minute,
		gracePeriod: 10 * time.Minute, // network flakiness ကာကွယ်ဖို့
	}
}

// Start runs the job in a goroutine and exits when ctx is cancelled.
func (j *ExpiryJob) Start(ctx context.Context) {
	log.Printf("expiry_job: starting (interval=%s, grace=%s)", j.interval, j.gracePeriod)
	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()

	// Optional: run once at startup
	j.RunOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Printf("expiry_job: shutting down: %v", ctx.Err())
			return
		case <-ticker.C:
			j.RunOnce(ctx)
		}
	}
}

// RunOnce executes all cleanup steps once.
func (j *ExpiryJob) RunOnce(ctx context.Context) {
	runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	if err := j.expirePeers(runCtx); err != nil {
		log.Printf("expiry_job: expirePeers: %v", err)
	}
	if err := j.cleanupRefreshTokens(runCtx); err != nil {
		log.Printf("expiry_job: cleanupRefreshTokens: %v", err)
	}
	if err := j.cleanupEmailTokens(runCtx); err != nil {
		log.Printf("expiry_job: cleanupEmailTokens: %v", err)
	}
	if err := j.cleanupStaleInstalls(runCtx); err != nil {
		log.Printf("expiry_job: cleanupStaleInstalls: %v", err)
	}
}

// ------------------------------------------------------------------
// Step 1: Remove peers whose owner has no active entitlement
// ------------------------------------------------------------------

// expiredPeerRow represents an active peer whose owner has no entitlement
// that expires after NOW() + gracePeriod.
type expiredPeerRow struct {
	ID        string
	PublicKey string
	OwnerKey  string // "user:<id>" or "install:<id>" (for logging)
}

func (j *ExpiryJob) expirePeers(ctx context.Context) error {
	// Find active peers whose owner has no entitlement valid beyond (now + grace)
	// This handles both user-owned and install-owned peers in one query.
	rows, err := j.db.Query(ctx, `
    SELECT p.id, p.public_key,
           CASE
               WHEN p.user_id IS NOT NULL THEN 'user:' || p.user_id::text
               ELSE 'install:' || p.install_id::text
           END AS owner_key
    FROM vpn_peers p
    WHERE p.is_active = TRUE
      AND NOT EXISTS (
          SELECT 1 FROM entitlements e
          WHERE e.expires_at > NOW() + $1::interval
            AND (
                (p.user_id    IS NOT NULL AND e.user_id    = p.user_id) OR
                (p.install_id IS NOT NULL AND e.install_id = p.install_id)
            )
      )
  `, j.gracePeriod.String())
	if err != nil {
		return fmt.Errorf("query expired peers: %w", err)
	}
	defer rows.Close()

	var peers []expiredPeerRow
	for rows.Next() {
		var p expiredPeerRow
		if err := rows.Scan(&p.ID, &p.PublicKey, &p.OwnerKey); err != nil {
			return fmt.Errorf("scan: %w", err)
		}
		peers = append(peers, p)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("rows err: %w", err)
	}

	if len(peers) == 0 {
		return nil
	}

	log.Printf("expiry_job: %d expired peer(s) to revoke", len(peers))

	revoked := 0
	for _, p := range peers {
		// 1) Remove from WireGuard interface
		if err := j.wg.RemovePeer(p.PublicKey); err != nil {
			// keep DB active so we retry next tick
			log.Printf("expiry_job: RemovePeer(%s) failed: %v", p.OwnerKey, err)
			continue
		}
		// 2) Mark inactive in DB
		//    (delete on next cleanup once rows older than gracePeriod)
		tag, err := j.db.Exec(ctx, `
      UPDATE vpn_peers
      SET is_active = FALSE, updated_at = NOW()
      WHERE id = $1 AND is_active = TRUE
    `, p.ID)
		if err != nil {
			log.Printf("expiry_job: mark inactive %s failed: %v", p.ID, err)
			continue
		}
		if tag.RowsAffected() > 0 {
			revoked++
		}
	}

	log.Printf("expiry_job: revoked %d/%d peers", revoked, len(peers))
	return nil
}

// ------------------------------------------------------------------
// Step 2: Cleanup expired refresh tokens
// ------------------------------------------------------------------

func (j *ExpiryJob) cleanupRefreshTokens(ctx context.Context) error {
	// Hard-delete tokens that are revoked or long-expired.
	// Keep expired-but-not-revoked for a short window so we can detect
	// token-reuse attacks (optional).
	tag, err := j.db.Exec(ctx, `
    DELETE FROM refresh_tokens
    WHERE revoked_at IS NOT NULL
      AND revoked_at < NOW() - INTERVAL '7 days'
  `)
	if err != nil {
		return err
	}
	if n := tag.RowsAffected(); n > 0 {
		log.Printf("expiry_job: deleted %d old revoked refresh_tokens", n)
	}

	tag, err = j.db.Exec(ctx, `
    DELETE FROM refresh_tokens
    WHERE revoked_at IS NULL
      AND expires_at < NOW() - INTERVAL '30 days'
  `)
	if err != nil {
		return err
	}
	if n := tag.RowsAffected(); n > 0 {
		log.Printf("expiry_job: deleted %d long-expired refresh_tokens", n)
	}
	return nil
}

// ------------------------------------------------------------------
// Step 3: Cleanup used/expired email_tokens
// ------------------------------------------------------------------

func (j *ExpiryJob) cleanupEmailTokens(ctx context.Context) error {
	tag, err := j.db.Exec(ctx, `
    DELETE FROM email_tokens
    WHERE used_at IS NOT NULL
       OR expires_at < NOW() - INTERVAL '1 day'
  `)
	if err != nil {
		return err
	}
	if n := tag.RowsAffected(); n > 0 {
		log.Printf("expiry_job: deleted %d stale email_tokens", n)
	}
	return nil
}

// ------------------------------------------------------------------
// Step 4: Cleanup stale anonymous_installs (no activity, no entitlement)
// ------------------------------------------------------------------

// cleanupStaleInstalls removes guest installs that have not been active
// for STALE_DAYS and have no active entitlement. Cascades will delete
// their entitlements and peers. This keeps table sizes bounded.
func (j *ExpiryJob) cleanupStaleInstalls(ctx context.Context) error {
	const staleDays = 30

	tag, err := j.db.Exec(ctx, `
    DELETE FROM anonymous_installs a
    WHERE a.last_seen_at < NOW() - make_interval(days => $1)
      AND NOT EXISTS (
          SELECT 1 FROM entitlements e
          WHERE e.install_id = a.id
            AND e.expires_at > NOW()
      )
  `, staleDays)
	if err != nil {
		return err
	}
	if n := tag.RowsAffected(); n > 0 {
		log.Printf("expiry_job: deleted %d stale anonymous_installs", n)
	}
	return nil
}
