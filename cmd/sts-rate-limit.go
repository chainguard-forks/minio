package cmd

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// stsAuthRateLimiter provides per-IP rate limiting for STS authentication
// endpoints to mitigate brute-force attacks.
type stsAuthRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rateLimiterEntry
}

type rateLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// Per-IP: 10 attempts per second with a burst of 20.
const (
	stsAuthRateLimit = rate.Limit(10)
	stsAuthBurst     = 20
)

var globalSTSAuthRateLimiter = newSTSAuthRateLimiter()

func newSTSAuthRateLimiter() *stsAuthRateLimiter {
	rl := &stsAuthRateLimiter{
		limiters: make(map[string]*rateLimiterEntry),
	}
	go rl.cleanup()
	return rl
}

// Allow returns true if the request from the given IP should be allowed.
func (rl *stsAuthRateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	entry, ok := rl.limiters[ip]
	if !ok {
		entry = &rateLimiterEntry{
			limiter: rate.NewLimiter(stsAuthRateLimit, stsAuthBurst),
		}
		rl.limiters[ip] = entry
	}
	entry.lastSeen = time.Now()
	rl.mu.Unlock()

	return entry.limiter.Allow()
}

// cleanup periodically removes stale entries.
func (rl *stsAuthRateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-10 * time.Minute)
		for ip, entry := range rl.limiters {
			if entry.lastSeen.Before(cutoff) {
				delete(rl.limiters, ip)
			}
		}
		rl.mu.Unlock()
	}
}
