package handlers

import (
	"testing"
	"time"
)

func TestStackedExpiry(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	add := 24 * time.Hour

	t.Run("no current grant starts from now", func(t *testing.T) {
		got := stackedExpiry(now, nil, add)
		if !got.Equal(now.Add(add)) {
			t.Fatalf("got %s want %s", got, now.Add(add))
		}
	})

	t.Run("expired grant starts from now", func(t *testing.T) {
		expired := now.Add(-time.Hour)
		got := stackedExpiry(now, &expired, add)
		if !got.Equal(now.Add(add)) {
			t.Fatalf("got %s want %s", got, now.Add(add))
		}
	})

	t.Run("active remaining stacks on current expiry", func(t *testing.T) {
		// 12h 24m remaining → 36h 24m after another 24h ad
		current := now.Add(12*time.Hour + 24*time.Minute)
		got := stackedExpiry(now, &current, add)
		want := current.Add(add)
		if !got.Equal(want) {
			t.Fatalf("got %s want %s", got, want)
		}
		remaining := got.Sub(now)
		if remaining != 36*time.Hour+24*time.Minute {
			t.Fatalf("remaining %s want 36h24m", remaining)
		}
	})
}
