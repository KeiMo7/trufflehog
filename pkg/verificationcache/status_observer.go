package verificationcache

import (
	"sync"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

type attemptStatusObserver struct {
	mu   sync.Mutex
	last int
}

func (o *attemptStatusObserver) ObserveHTTPStatus(statusCode int) {
	o.mu.Lock()
	o.last = statusCode
	o.mu.Unlock()
}

func (o *attemptStatusObserver) Last() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.last
}

func (v *VerificationCache) withStatusObserver(ctx context.Context, observer *attemptStatusObserver) context.Context {
	if !v.config.TrackOutcomes && v.auditSink == nil {
		return ctx
	}
	return context.WithValue(ctx, common.HTTPStatusObserverContextKey, observer)
}
