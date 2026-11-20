package verificationcache

import (
	"sync/atomic"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

// InMemoryMetrics is a MetricsReporter that stores reported metrics in memory for retrieval at the end of a scan.
type InMemoryMetrics struct {
	CredentialVerificationsSaved atomic.Int32
	FromDataVerifyTimeSpentMS    atomic.Int64
	ResultCacheHits              atomic.Int32
	ResultCacheHitsWasted        atomic.Int32
	ResultCacheMisses            atomic.Int32

	VerificationCandidates       atomic.Int64
	VerificationRequests         atomic.Int64
	VerificationRetries          atomic.Int64
	VerificationRateLimited      atomic.Int64
	VerificationCacheUnavailable atomic.Int64
	VerifiedOutcomes             atomic.Int64
	InvalidOutcomes              atomic.Int64
	UnverifiedOutcomes           atomic.Int64
	PendingManualOutcomes        atomic.Int64
	RateLimitedUnverified        atomic.Int64
	RateLimitedPendingManual     atomic.Int64
}

var _ MetricsReporter = (*InMemoryMetrics)(nil)
var _ OutcomeMetricsReporter = (*InMemoryMetrics)(nil)

func (m *InMemoryMetrics) AddCredentialVerificationsSaved(count int) {
	m.CredentialVerificationsSaved.Add(int32(count))
}

func (m *InMemoryMetrics) AddFromDataVerifyTimeSpent(wallTime time.Duration) {
	m.FromDataVerifyTimeSpentMS.Add(wallTime.Milliseconds())
}

func (m *InMemoryMetrics) AddResultCacheHits(count int) {
	m.ResultCacheHits.Add(int32(count))
}

func (m *InMemoryMetrics) AddResultCacheMisses(count int) {
	m.ResultCacheMisses.Add(int32(count))
}

func (m *InMemoryMetrics) AddResultCacheHitsWasted(count int) {
	m.ResultCacheHitsWasted.Add(int32(count))
}

func (m *InMemoryMetrics) AddVerificationCandidate() {
	m.VerificationCandidates.Add(1)
}

func (m *InMemoryMetrics) AddVerificationRequest() {
	m.VerificationRequests.Add(1)
}

func (m *InMemoryMetrics) AddVerificationRetry() {
	m.VerificationRetries.Add(1)
}

func (m *InMemoryMetrics) AddVerificationRateLimited() {
	m.VerificationRateLimited.Add(1)
}

func (m *InMemoryMetrics) AddVerificationCacheUnavailable() {
	m.VerificationCacheUnavailable.Add(1)
}

func (m *InMemoryMetrics) AddVerificationOutcome(status detectors.VerificationStatus, rateLimited bool) {
	switch status {
	case detectors.VerificationStatusValid:
		m.VerifiedOutcomes.Add(1)
	case detectors.VerificationStatusInvalid:
		m.InvalidOutcomes.Add(1)
	case detectors.VerificationStatusPendingManualConfirmation:
		m.PendingManualOutcomes.Add(1)
		if rateLimited {
			m.RateLimitedPendingManual.Add(1)
		}
	default:
		m.UnverifiedOutcomes.Add(1)
		if rateLimited {
			m.RateLimitedUnverified.Add(1)
		}
	}
}
