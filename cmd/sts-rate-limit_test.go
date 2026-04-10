package cmd

import (
	"fmt"
	"sync"
	"testing"
)

func TestSTSAuthRateLimiterAllow(t *testing.T) {
	rl := &stsAuthRateLimiter{
		limiters: make(map[string]*rateLimiterEntry),
	}

	// Burst of 20 should be allowed immediately.
	for i := 0; i < stsAuthBurst; i++ {
		if !rl.Allow("10.0.0.1") {
			t.Fatalf("request %d should have been allowed within burst", i+1)
		}
	}

	// Next request should be denied (burst exhausted, no time to refill).
	if rl.Allow("10.0.0.1") {
		t.Fatal("request after burst should have been denied")
	}
}

func TestSTSAuthRateLimiterPerIP(t *testing.T) {
	rl := &stsAuthRateLimiter{
		limiters: make(map[string]*rateLimiterEntry),
	}

	// Exhaust burst for one IP.
	for i := 0; i < stsAuthBurst; i++ {
		rl.Allow("10.0.0.1")
	}

	// A different IP should still be allowed.
	if !rl.Allow("10.0.0.2") {
		t.Fatal("different IP should not be affected by rate limit of another IP")
	}
}

func TestSTSAuthRateLimiterConcurrent(t *testing.T) {
	rl := &stsAuthRateLimiter{
		limiters: make(map[string]*rateLimiterEntry),
	}

	var wg sync.WaitGroup
	// Hammer from multiple goroutines to verify no races.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				rl.Allow(ip)
			}
		}(fmt.Sprintf("10.0.0.%d", i%10))
	}
	wg.Wait()
}

func TestSTSAuthRateLimiterCleanup(t *testing.T) {
	rl := &stsAuthRateLimiter{
		limiters: make(map[string]*rateLimiterEntry),
	}

	// Create an entry.
	rl.Allow("10.0.0.1")

	rl.mu.Lock()
	if len(rl.limiters) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(rl.limiters))
	}
	// Backdate the entry so cleanup considers it stale.
	rl.limiters["10.0.0.1"].lastSeen = rl.limiters["10.0.0.1"].lastSeen.Add(-15 * 60 * 1e9) // 15 minutes ago
	rl.mu.Unlock()

	// Add a fresh entry that should survive cleanup.
	rl.Allow("10.0.0.2")

	// Run cleanup logic inline.
	rl.mu.Lock()
	cutoff := rl.limiters["10.0.0.2"].lastSeen.Add(-10 * 60 * 1e9) // 10 minutes before the fresh entry
	for ip, entry := range rl.limiters {
		if entry.lastSeen.Before(cutoff) {
			delete(rl.limiters, ip)
		}
	}
	rl.mu.Unlock()

	rl.mu.Lock()
	defer rl.mu.Unlock()
	if _, ok := rl.limiters["10.0.0.1"]; ok {
		t.Fatal("stale entry should have been cleaned up")
	}
	if _, ok := rl.limiters["10.0.0.2"]; !ok {
		t.Fatal("fresh entry should have survived cleanup")
	}
}
