package verificationcache

import (
	"sync"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type serviceLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	burst    float64
	now      func() time.Time
	services map[detector_typepb.DetectorType]*serviceLimitState
}

type serviceLimitState struct {
	tokens       float64
	lastRefill   time.Time
	penaltyUntil time.Time
}

func newServiceLimiter(interval time.Duration, burst int, now func() time.Time) *serviceLimiter {
	if interval <= 0 {
		return nil
	}
	return &serviceLimiter{
		interval: interval,
		burst:    float64(burst),
		now:      now,
		services: make(map[detector_typepb.DetectorType]*serviceLimitState),
	}
}

func (l *serviceLimiter) wait(ctx context.Context, service detector_typepb.DetectorType) error {
	if l == nil {
		return nil
	}
	for {
		now := l.now()
		delay := l.reserve(service, now)
		if delay <= 0 {
			return nil
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (l *serviceLimiter) reserve(service detector_typepb.DetectorType, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	state, ok := l.services[service]
	if !ok {
		state = &serviceLimitState{tokens: l.burst, lastRefill: now}
		l.services[service] = state
	}

	if now.Before(state.penaltyUntil) {
		return state.penaltyUntil.Sub(now)
	}

	if l.interval > 0 {
		elapsed := now.Sub(state.lastRefill)
		state.tokens += float64(elapsed) / float64(l.interval)
		if state.tokens > l.burst {
			state.tokens = l.burst
		}
		state.lastRefill = now
	}

	if state.tokens >= 1 {
		state.tokens--
		return 0
	}

	needed := 1 - state.tokens
	return time.Duration(needed * float64(l.interval))
}

func (l *serviceLimiter) penalize(service detector_typepb.DetectorType, delay time.Duration) {
	if l == nil || delay <= 0 {
		return
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	state, ok := l.services[service]
	if !ok {
		state = &serviceLimitState{tokens: l.burst, lastRefill: now}
		l.services[service] = state
	}
	until := now.Add(delay)
	if until.After(state.penaltyUntil) {
		state.penaltyUntil = until
	}
	state.tokens = 0
}
