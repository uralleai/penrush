package registry

import (
	"context"
	"sync"
	"time"
)

// tokenBucket is a minimal per-ecosystem rate governor (SD.4/SD.5/SD.10).
// crates.io binds callers to 1 rps (RFC 3463); RubyGems to 10 rps. The bucket
// refills at `rate` tokens/sec up to `burst`. Wait blocks (respecting ctx)
// until a token is available, so a resolver never bursts past the registry's
// published ceiling even under concurrent gate checks.
//
// Stdlib-only by design (A.2 zero-dep budget): golang.org/x/time/rate would do
// this, but it is a third-party import we are not permitted to add.
type tokenBucket struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64 // max accumulated tokens
	tokens  float64
	last    time.Time
	nowFn   func() time.Time // injectable for deterministic tests
	sleepFn func(context.Context, time.Duration) error
}

// newTokenBucket builds a bucket that starts full.
func newTokenBucket(ratePerSec, burst float64) *tokenBucket {
	return &tokenBucket{
		rate:    ratePerSec,
		burst:   burst,
		tokens:  burst,
		last:    time.Now(),
		nowFn:   time.Now,
		sleepFn: sleepCtx,
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Wait blocks until one token is available or ctx is done. It refills based on
// elapsed wall time, then either consumes a token immediately or sleeps for the
// exact deficit. Returns ctx.Err() if the context is cancelled while waiting.
func (b *tokenBucket) Wait(ctx context.Context) error {
	b.mu.Lock()
	now := b.nowFn()
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		b.mu.Unlock()
		return nil
	}
	// Deficit: time to accumulate the missing fraction of a token.
	deficit := 1 - b.tokens
	waitFor := time.Duration(deficit / b.rate * float64(time.Second))
	// Reserve the token now so concurrent callers queue behind us.
	b.tokens--
	b.last = now.Add(waitFor)
	b.mu.Unlock()
	return b.sleepFn(ctx, waitFor)
}
