package verificationcache

import "github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

// OutcomeMetricsReporter is an optional extension implemented by metrics reporters that can retain classification and
// scheduler counters. Existing MetricsReporter implementations do not need to change.
type OutcomeMetricsReporter interface {
	AddVerificationCandidate()
	AddVerificationRequest()
	AddVerificationRetry()
	AddVerificationRateLimited()
	AddVerificationCacheUnavailable()
	AddVerificationOutcome(status detectors.VerificationStatus, rateLimited bool)
}

func (v *VerificationCache) recordCandidate() {
	if m, ok := v.metrics.(OutcomeMetricsReporter); ok {
		m.AddVerificationCandidate()
	}
}

func (v *VerificationCache) recordRequest() {
	if m, ok := v.metrics.(OutcomeMetricsReporter); ok {
		m.AddVerificationRequest()
	}
}

func (v *VerificationCache) recordRetry() {
	if m, ok := v.metrics.(OutcomeMetricsReporter); ok {
		m.AddVerificationRetry()
	}
}

func (v *VerificationCache) recordRateLimited() {
	if m, ok := v.metrics.(OutcomeMetricsReporter); ok {
		m.AddVerificationRateLimited()
	}
}

func (v *VerificationCache) recordCacheUnavailable() {
	if m, ok := v.metrics.(OutcomeMetricsReporter); ok {
		m.AddVerificationCacheUnavailable()
	}
}

func (v *VerificationCache) recordOutcome(status detectors.VerificationStatus, rateLimited bool) {
	if m, ok := v.metrics.(OutcomeMetricsReporter); ok {
		m.AddVerificationOutcome(status, rateLimited)
	}
}
