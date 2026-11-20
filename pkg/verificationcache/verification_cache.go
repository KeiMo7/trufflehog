package verificationcache

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/hasher"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

var (
	errInvalidCredentialFormat = errors.New("credential failed local format validation")
	errSideEffectVerification  = errors.New("verification has provider side effects and is disabled")
)

// VerificationCache is a structure that can be used to cache verification results from detectors so that a given
// credential does not trigger multiple identical remote verification attempts.
type VerificationCache struct {
	metrics         MetricsReporter
	resultCache     ResultCache
	detectorMetrics DetectorMetricsReporter // optional
	config          Config
	limiter         *serviceLimiter
	auditSink       AuditSink

	hashMu sync.Mutex
	hasher hasher.Hasher

	cacheUnavailableOnce sync.Once
}

// New creates a verification cache with the historical behavior. Use NewWithConfig to enable rate limiting, retries,
// expanded outcome tracking, or auditing.
func New(resultCache ResultCache, metrics MetricsReporter) *VerificationCache {
	return NewWithConfig(resultCache, metrics, Config{})
}

// NewWithConfig creates a verification cache with the provided scheduler and outcome configuration.
func NewWithConfig(resultCache ResultCache, metrics MetricsReporter, cfg Config) *VerificationCache {
	if metrics == nil {
		metrics = &InMemoryMetrics{}
	}
	cfg = cfg.normalized()
	detectorMetrics, _ := metrics.(DetectorMetricsReporter)

	return &VerificationCache{
		metrics:         metrics,
		resultCache:     resultCache,
		detectorMetrics: detectorMetrics,
		config:          cfg,
		limiter:         newServiceLimiter(cfg.RateLimitInterval, cfg.RateLimitBurst, cfg.Now),
		auditSink:       cfg.AuditSink,
		hasher:          hasher.NewBlake2B(),
	}
}

func (v *VerificationCache) now() time.Time {
	return v.config.Now()
}

// recordVerifyTime reports one remote verification pass to both metric views: the cross-detector aggregate and, when
// the reporter opted in, the per-detector histogram. Used by the paths where a single detector.FromData call with
// verify=true is the whole verification pass.
func (v *VerificationCache) recordVerifyTime(detectorType detector_typepb.DetectorType, wallTime time.Duration) {
	v.metrics.AddFromDataVerifyTimeSpent(wallTime)
	v.recordDetectorVerifyTime(detectorType, wallTime)
}

// recordDetectorVerifyTime reports one verification sample to the per-detector view. It is a no-op for reporters that
// do not implement DetectorMetricsReporter.
func (v *VerificationCache) recordDetectorVerifyTime(detectorType detector_typepb.DetectorType, wallTime time.Duration) {
	if v.detectorMetrics != nil {
		v.detectorMetrics.AddDetectorVerifyTimeSpent(detectorType, wallTime)
	}
}

// FromData is a cache-aware facade in front of the provided detector's FromData method.
//
// With the historical configuration (New), behavior is unchanged: extraction runs with verify=false, cache hits are
// served directly, and a chunk with any miss is verified by re-running the detector with verify=true.
//
// NewWithConfig additionally enforces per-service rate limits, retries rate-limited requests with exponential
// backoff, classifies outcomes into valid/invalid/unverified/pending-manual states, and emits audit records.
func (v *VerificationCache) FromData(
	ctx context.Context,
	detector detectors.Detector,
	verify bool,
	forceCacheUpdate bool,
	data []byte,
) ([]detectors.Result, error) {
	if !verify {
		if v.resultCache != nil && forceCacheUpdate {
			results, err := detector.FromData(ctx, false, data)
			if err != nil {
				return nil, err
			}
			v.cacheResults(results)
			return results, nil
		}
		return detector.FromData(ctx, false, data)
	}

	if v.resultCache == nil && !v.needsManagedPath(detector) {
		start := time.Now()
		results, err := detector.FromData(ctx, true, data)
		v.recordVerifyTime(detector.Type(), time.Since(start))
		return results, err
	}

	if v.resultCache == nil {
		v.cacheUnavailableOnce.Do(func() {
			v.recordCacheUnavailable()
			ctx.Logger().Info(
				"verification cache is unavailable; every unique candidate will be verified remotely",
				"cost_warning", true,
			)
		})
	}

	if forceCacheUpdate {
		return v.forceVerify(ctx, detector, data)
	}

	extracted, err := detector.FromData(ctx, false, data)
	if err != nil {
		return nil, err
	}
	if resultVerifier, ok := detector.(detectors.ResultVerifier); ok {
		return v.verifyCacheMisses(ctx, detector, resultVerifier, extracted, forceCacheUpdate)
	}
	return v.verifyWholeChunk(ctx, detector, extracted, forceCacheUpdate, data)
}

func (v *VerificationCache) forceVerify(
	ctx context.Context,
	detector detectors.Detector,
	data []byte,
) ([]detectors.Result, error) {
	_, hasResultSideEffects := detector.(detectors.ResultSideEffectVerifier)
	_, hasValidator := detector.(detectors.ResultValidator)
	if hasValidator || (!v.config.AllowSideEffectVerification && (detectorHasSideEffects(detector) || hasResultSideEffects)) {
		return v.forceVerifyWithLocalRules(ctx, detector, data)
	}
	return v.forceVerifyCall(ctx, detector, data)
}

func (v *VerificationCache) forceVerifyWithLocalRules(
	ctx context.Context,
	detector detectors.Detector,
	data []byte,
) ([]detectors.Result, error) {
	extracted, err := detector.FromData(ctx, false, data)
	if err != nil {
		return nil, err
	}
	now := v.now()
	sideEffects := detectorHasSideEffects(detector)
	validator, _ := detector.(detectors.ResultValidator)
	terminal := make(map[string]detectors.Result)
	needVerification := false

	for i := range extracted {
		v.recordCandidate()
		fingerprint, _ := v.credentialFingerprint(extracted[i])
		key := string(mustCacheKey(v, extracted[i]))
		if validator != nil {
			if err := validator.ValidateResult(&extracted[i]); err != nil {
				v.markInvalid(&extracted[i], now)
				v.auditSkipped(detector.Type(), fingerprint, errInvalidCredentialFormat)
				v.cacheResultForKey(key, &extracted[i])
				v.recordOutcome(detectors.VerificationStatusInvalid, false)
				terminal[key] = extracted[i]
				continue
			}
		}
		if !v.config.AllowSideEffectVerification && (sideEffects || resultHasSideEffects(detector, extracted[i])) {
			v.markSideEffectPending(&extracted[i], now)
			v.auditSkipped(detector.Type(), fingerprint, errSideEffectVerification)
			v.cacheResultForKey(key, &extracted[i])
			v.recordOutcome(detectors.VerificationStatusPendingManualConfirmation, false)
			terminal[key] = extracted[i]
			continue
		}
		needVerification = true
	}
	if !needVerification {
		return extracted, nil
	}

	verified, err := v.forceVerifyCall(ctx, detector, data)
	if err != nil {
		return nil, err
	}
	for i := range verified {
		key := string(mustCacheKey(v, verified[i]))
		if prior, ok := terminal[key]; ok {
			verified[i].CopyVerificationInfo(&prior)
			verified[i].VerificationSkipped = prior.VerificationSkipped
			v.cacheResultForKey(key, &verified[i])
		}
	}
	return verified, nil
}

func (v *VerificationCache) forceVerifyCall(
	ctx context.Context,
	detector detectors.Detector,
	data []byte,
) ([]detectors.Result, error) {
	if err := v.limiter.wait(ctx, detector.Type()); err != nil {
		return nil, err
	}
	v.recordRequest()
	observer := &attemptStatusObserver{}
	start := time.Now()
	results, err := detector.FromData(v.withStatusObserver(ctx, observer), true, data)
	v.recordVerifyTime(detector.Type(), time.Since(start))
	if err != nil {
		v.auditAttempt(
			AuditActionRequest,
			detector.Type(),
			"",
			1,
			observer.Last(),
			detectors.VerificationStatusUnverified,
			false,
			err,
		)
		return nil, err
	}

	now := v.now()
	for i := range results {
		if results[i].Verified {
			results[i].ClearVerificationError()
		}
		if len(results) == 1 && results[i].VerificationStatusCode == 0 && observer.Last() > 0 {
			results[i].VerificationStatusCode = observer.Last()
		}
		fingerprint, _ := v.credentialFingerprint(results[i])
		status, code, rateLimited := classifyVerification(&results[i])
		v.finalizeOutcome(&results[i], status, code, rateLimited, now)
		v.auditAttempt(
			AuditActionRequest,
			detector.Type(),
			fingerprint,
			1,
			code,
			results[i].VerificationStatus,
			rateLimited,
			results[i].VerificationError(),
		)
		v.recordCandidate()
		v.recordOutcome(results[i].VerificationStatus, rateLimited)
		key, keyErr := v.getResultCacheKey(results[i])
		if keyErr == nil {
			v.cacheResultForKey(string(key), &results[i])
		}
	}
	return results, nil
}

func (v *VerificationCache) needsManagedPath(detector detectors.Detector) bool {
	if v.config.trackOutcomes() || v.auditSink != nil || v.limiter != nil {
		return true
	}
	if _, ok := detector.(detectors.ResultValidator); ok {
		return true
	}
	if _, ok := detector.(detectors.ResultSideEffectVerifier); ok {
		return true
	}
	if sideEffect, ok := detector.(detectors.SideEffectVerifier); ok && sideEffect.VerificationHasSideEffects() {
		return true
	}
	return false
}

// verifyCacheMisses serves the results whose verification status is already cached and remotely verifies only the
// misses.
func (v *VerificationCache) verifyCacheMisses(
	ctx context.Context,
	detector detectors.Detector,
	resultVerifier detectors.ResultVerifier,
	results []detectors.Result,
	forceCacheUpdate bool,
) ([]detectors.Result, error) {
	var timeSpentVerifying time.Duration
	defer func() {
		if timeSpentVerifying > 0 {
			v.metrics.AddFromDataVerifyTimeSpent(timeSpentVerifying)
		}
	}()

	sideEffects := detectorHasSideEffects(detector)
	validator, _ := detector.(detectors.ResultValidator)
	now := v.now()

	for i := range results {
		v.recordCandidate()
		fingerprint, keyErr := v.credentialFingerprint(results[i])
		key := string(mustCacheKey(v, results[i]))

		if validator != nil {
			if err := validator.ValidateResult(&results[i]); err != nil {
				v.markInvalid(&results[i], now)
				v.auditSkipped(detector.Type(), fingerprint, errInvalidCredentialFormat)
				v.cacheResultForKey(key, &results[i])
				v.recordOutcome(detectors.VerificationStatusInvalid, false)
				continue
			}
		}

		if !forceCacheUpdate && keyErr == nil {
			if cacheHit, ok := v.getUsableCache(key); ok {
				results[i].CopyVerificationInfo(&cacheHit)
				results[i].VerificationFromCache = true
				v.metrics.AddResultCacheHits(1)
				v.metrics.AddCredentialVerificationsSaved(1)
				status, rateLimited := cachedOutcome(results[i])
				v.auditCacheHit(detector.Type(), fingerprint, results[i].VerificationStatusCode, status)
				v.recordOutcome(status, rateLimited)
				continue
			}
			v.metrics.AddResultCacheMisses(1)
		}

		if keyErr != nil {
			ctx.Logger().Error(keyErr, "error getting result cache key for verification caching",
				"operation", "read")
		}

		if !v.config.AllowSideEffectVerification && (sideEffects || resultHasSideEffects(detector, results[i])) {
			v.markSideEffectPending(&results[i], now)
			v.auditSkipped(detector.Type(), fingerprint, errSideEffectVerification)
			v.cacheResultForKey(key, &results[i])
			v.recordOutcome(detectors.VerificationStatusPendingManualConfirmation, false)
			continue
		}

		elapsed, status, code, rateLimited := v.verifyOneWithRetry(
			ctx,
			resultVerifier,
			detector.Type(),
			fingerprint,
			&results[i],
		)
		timeSpentVerifying += elapsed
		v.finalizeOutcome(&results[i], status, code, rateLimited, now)
		v.cacheResultForKey(key, &results[i])
		v.recordOutcome(results[i].VerificationStatus, rateLimited)
	}

	return results, nil
}

func (v *VerificationCache) verifyOneWithRetry(
	ctx context.Context,
	resultVerifier detectors.ResultVerifier,
	detectorType detector_typepb.DetectorType,
	fingerprint string,
	result *detectors.Result,
) (time.Duration, detectors.VerificationStatus, int, bool) {
	var total time.Duration
	attempts := 0

	for {
		if err := v.limiter.wait(ctx, detectorType); err != nil {
			result.SetVerificationError(err)
			status, code, _ := classifyVerification(result)
			return total, status, code, false
		}

		attempts++
		v.recordRequest()
		observer := &attemptStatusObserver{}
		attemptStart := time.Now()
		resultVerifier.VerifyResult(v.withStatusObserver(ctx, observer), result)
		elapsed := time.Since(attemptStart)
		total += elapsed
		v.recordDetectorVerifyTime(detectorType, elapsed)
		if result.VerificationStatusCode == 0 && observer.Last() > 0 {
			result.VerificationStatusCode = observer.Last()
		}
		if result.Verified {
			result.ClearVerificationError()
		}

		status, code, rateLimited := classifyVerification(result)
		action := AuditActionRequest
		if attempts > 1 {
			action = AuditActionRetry
		}
		v.auditAttempt(action, detectorType, fingerprint, attempts, code, status, rateLimited, result.VerificationError())

		if !rateLimited {
			if status == detectors.VerificationStatusPendingManualConfirmation {
				v.finalizeOutcome(result, status, code, true, v.now())
			}
			return total, status, code, false
		}

		v.recordRateLimited()
		if attempts-1 >= v.config.MaxRetries {
			return total, detectors.VerificationStatusPendingManualConfirmation, code, true
		}

		delay := v.retryDelay(attempts)
		v.limiter.penalize(detectorType, delay)
		v.recordRetry()
		if err := sleepContext(ctx, delay); err != nil {
			result.SetVerificationError(err)
			return total, detectors.VerificationStatusUnverified, code, false
		}
	}
}

func (v *VerificationCache) verifyWholeChunk(
	ctx context.Context,
	detector detectors.Detector,
	extracted []detectors.Result,
	forceCacheUpdate bool,
	data []byte,
) ([]detectors.Result, error) {
	sideEffects := detectorHasSideEffects(detector)
	validator, _ := detector.(detectors.ResultValidator)
	now := v.now()

	type savedOutcome struct {
		result detectors.Result
	}
	saved := make(map[string]savedOutcome, len(extracted))
	needRemote := false
	cacheHits := 0

	for i := range extracted {
		v.recordCandidate()
		fingerprint, keyErr := v.credentialFingerprint(extracted[i])
		key := string(mustCacheKey(v, extracted[i]))

		if validator != nil {
			if err := validator.ValidateResult(&extracted[i]); err != nil {
				v.markInvalid(&extracted[i], now)
				v.auditSkipped(detector.Type(), fingerprint, errInvalidCredentialFormat)
				if keyErr == nil {
					v.cacheResultForKey(key, &extracted[i])
					saved[key] = savedOutcome{result: extracted[i]}
				}
				v.recordOutcome(detectors.VerificationStatusInvalid, false)
				continue
			}
		}

		if !forceCacheUpdate && keyErr == nil {
			if cacheHit, ok := v.getUsableCache(key); ok {
				extracted[i].CopyVerificationInfo(&cacheHit)
				extracted[i].VerificationFromCache = true
				v.metrics.AddResultCacheHits(1)
				cacheHits++
				status, rateLimited := cachedOutcome(extracted[i])
				v.auditCacheHit(detector.Type(), fingerprint, extracted[i].VerificationStatusCode, status)
				v.recordOutcome(status, rateLimited)
				continue
			}
			v.metrics.AddResultCacheMisses(1)
		}

		if !v.config.AllowSideEffectVerification && (sideEffects || resultHasSideEffects(detector, extracted[i])) {
			v.markSideEffectPending(&extracted[i], now)
			v.auditSkipped(detector.Type(), fingerprint, errSideEffectVerification)
			if keyErr == nil {
				v.cacheResultForKey(key, &extracted[i])
				saved[key] = savedOutcome{result: extracted[i]}
			}
			v.recordOutcome(detectors.VerificationStatusPendingManualConfirmation, false)
			continue
		}

		needRemote = true
	}

	if !needRemote {
		v.metrics.AddCredentialVerificationsSaved(cacheHits)
		return extracted, nil
	}
	v.metrics.AddResultCacheHitsWasted(cacheHits)

	var (
		remote        []detectors.Result
		attempts      int
		lastRateLimit bool
	)
	for {
		if err := v.limiter.wait(ctx, detector.Type()); err != nil {
			return nil, err
		}
		attempts++
		v.recordRequest()
		observer := &attemptStatusObserver{}
		start := time.Now()
		var err error
		remote, err = detector.FromData(v.withStatusObserver(ctx, observer), true, data)
		v.recordVerifyTime(detector.Type(), time.Since(start))
		if err != nil {
			v.auditAttempt(
				AuditActionRequest,
				detector.Type(),
				"",
				attempts,
				observer.Last(),
				detectors.VerificationStatusUnverified,
				false,
				err,
			)
			return nil, err
		}

		lastRateLimit = false
		for i := range remote {
			if remote[i].Verified {
				remote[i].ClearVerificationError()
			}
			if len(remote) == 1 && remote[i].VerificationStatusCode == 0 && observer.Last() > 0 {
				remote[i].VerificationStatusCode = observer.Last()
			}
			status, code, rateLimited := classifyVerification(&remote[i])
			lastRateLimit = lastRateLimit || rateLimited
			fingerprint, _ := v.credentialFingerprint(remote[i])
			action := AuditActionRequest
			if attempts > 1 {
				action = AuditActionRetry
			}
			v.auditAttempt(action, detector.Type(), fingerprint, attempts, code, status, rateLimited, remote[i].VerificationError())
		}
		if !lastRateLimit {
			break
		}
		v.recordRateLimited()
		if attempts-1 >= v.config.MaxRetries {
			break
		}
		delay := v.retryDelay(attempts)
		v.limiter.penalize(detector.Type(), delay)
		v.recordRetry()
		if err := sleepContext(ctx, delay); err != nil {
			return nil, err
		}
	}

	now = v.now()
	exhausted := lastRateLimit && attempts-1 >= v.config.MaxRetries
	for i := range remote {
		key := string(mustCacheKey(v, remote[i]))
		if prior, ok := saved[key]; ok {
			remote[i].CopyVerificationInfo(&prior.result)
			if v.config.TrackOutcomes {
				remote[i].VerificationSkipped = prior.result.VerificationSkipped
			}
			continue
		}

		status, code, rateLimited := classifyVerification(&remote[i])
		v.finalizeOutcome(&remote[i], status, code, rateLimited && exhausted, now)
		v.cacheResultForKey(key, &remote[i])
		v.recordOutcome(remote[i].VerificationStatus, rateLimited)
	}

	return remote, nil
}

func (v *VerificationCache) retryDelay(attempt int) time.Duration {
	delay := v.config.BackoffInitial
	for i := 1; i < attempt; i++ {
		if delay >= v.config.BackoffMaximum/2 {
			return v.config.BackoffMaximum
		}
		delay *= 2
	}
	if delay > v.config.BackoffMaximum {
		return v.config.BackoffMaximum
	}
	return delay
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func detectorHasSideEffects(detector detectors.Detector) bool {
	sideEffect, ok := detector.(detectors.SideEffectVerifier)
	return ok && sideEffect.VerificationHasSideEffects()
}

func resultHasSideEffects(detector detectors.Detector, result detectors.Result) bool {
	if result.VerificationSideEffects {
		return true
	}
	if sideEffect, ok := detector.(detectors.ResultSideEffectVerifier); ok {
		return sideEffect.VerificationHasSideEffectsForResult(result)
	}
	return false
}

func (v *VerificationCache) markInvalid(result *detectors.Result, now time.Time) {
	result.Verified = false
	result.ClearVerificationError()
	result.VerificationSkipped = true
	if v.config.TrackOutcomes {
		result.VerificationStatus = detectors.VerificationStatusInvalid
		result.VerificationStatusCode = 0
		result.VerificationCheckedAt = now
		result.VerificationExpiresAt = now.Add(v.config.InvalidCooldown)
		result.VerificationRetryAfter = result.VerificationExpiresAt
	}
}

func (v *VerificationCache) markSideEffectPending(result *detectors.Result, now time.Time) {
	result.Verified = false
	result.VerificationSkipped = true
	result.SetVerificationError(errSideEffectVerification)
	if v.config.TrackOutcomes {
		result.VerificationStatus = detectors.VerificationStatusPendingManualConfirmation
		result.VerificationStatusCode = 0
		result.VerificationCheckedAt = now
		result.VerificationExpiresAt = now.Add(v.config.CacheTTL)
		result.VerificationRetryAfter = result.VerificationExpiresAt
	}
}

func (v *VerificationCache) finalizeOutcome(
	result *detectors.Result,
	status detectors.VerificationStatus,
	code int,
	exhaustedRateLimit bool,
	now time.Time,
) {
	if exhaustedRateLimit || status == detectors.VerificationStatusPendingManualConfirmation {
		status = detectors.VerificationStatusPendingManualConfirmation
		result.Verified = false
		result.SetVerificationError(pendingRateLimitError(v.config.MaxRetries + 1))
	}
	if !v.config.TrackOutcomes {
		return
	}

	result.VerificationStatus = status
	result.VerificationStatusCode = code
	result.VerificationCheckedAt = now
	switch status {
	case detectors.VerificationStatusValid:
		result.VerificationExpiresAt = now.Add(v.config.CacheTTL)
		result.VerificationRetryAfter = time.Time{}
	case detectors.VerificationStatusInvalid:
		result.VerificationExpiresAt = now.Add(v.config.InvalidCooldown)
		result.VerificationRetryAfter = result.VerificationExpiresAt
	case detectors.VerificationStatusPendingManualConfirmation:
		result.VerificationExpiresAt = now.Add(v.config.CacheTTL)
		result.VerificationRetryAfter = result.VerificationExpiresAt
	default:
		result.VerificationStatus = detectors.VerificationStatusUnverified
		result.VerificationExpiresAt = now.Add(v.config.CacheTTL)
		result.VerificationRetryAfter = now
	}
}

func cachedOutcome(result detectors.Result) (detectors.VerificationStatus, bool) {
	status := result.VerificationStatus
	if status == detectors.VerificationStatusUnspecified {
		status, _, _ = classifyVerification(&result)
	}
	if status == detectors.VerificationStatusUnverified {
		_, _, rateLimited := classifyVerification(&result)
		return status, rateLimited
	}
	return status, false
}

func (v *VerificationCache) getUsableCache(key string) (detectors.Result, bool) {
	if v.resultCache == nil {
		return detectors.Result{}, false
	}
	cached, ok := v.resultCache.Get(key)
	if !ok {
		return detectors.Result{}, false
	}
	if !v.config.TrackOutcomes || cached.VerificationStatus == detectors.VerificationStatusUnspecified {
		return cached, true
	}

	// Transient failures are retained in the cache so their existence and classification remain visible, but they are
	// never served as a reusable verdict. A later round may try the credential again.
	if cached.VerificationStatus == detectors.VerificationStatusUnverified {
		return detectors.Result{}, false
	}
	if !cached.VerificationExpiresAt.IsZero() && !v.now().Before(cached.VerificationExpiresAt) {
		v.resultCache.Delete(key)
		return detectors.Result{}, false
	}
	return cached, true
}

func (v *VerificationCache) cacheResults(results []detectors.Result) {
	for i := range results {
		key, err := v.getResultCacheKey(results[i])
		if err != nil {
			continue
		}
		v.cacheResultForKey(string(key), &results[i])
	}
}

func (v *VerificationCache) cacheResultForKey(key string, result *detectors.Result) {
	if v.resultCache == nil || key == "" {
		return
	}
	copyForCaching := *result
	copyForCaching.ClearSecrets()
	v.resultCache.Set(key, copyForCaching)
	fingerprint, _ := v.credentialFingerprint(*result)
	v.audit(AuditRecord{
		Timestamp:             v.now(),
		Action:                AuditActionCacheStore,
		DetectorType:          result.DetectorType,
		Service:               result.DetectorType.String(),
		CredentialFingerprint: fingerprint,
		HTTPStatusCode:        result.VerificationStatusCode,
		Outcome:               result.VerificationStatus.String(),
	})
}

func (v *VerificationCache) auditAttempt(
	action AuditAction,
	detectorType detector_typepb.DetectorType,
	fingerprint string,
	attempt int,
	statusCode int,
	status detectors.VerificationStatus,
	rateLimited bool,
	err error,
) {
	record := AuditRecord{
		Timestamp:             v.now(),
		Action:                action,
		DetectorType:          detectorType,
		Service:               detectorType.String(),
		CredentialFingerprint: fingerprint,
		Attempt:               attempt,
		HTTPStatusCode:        statusCode,
		Outcome:               status.String(),
		RateLimited:           rateLimited,
	}
	if err != nil {
		record.Error = "verification request failed"
	}
	v.audit(record)
}

func (v *VerificationCache) auditSkipped(
	detectorType detector_typepb.DetectorType,
	fingerprint string,
	err error,
) {
	v.audit(AuditRecord{
		Timestamp:             v.now(),
		Action:                AuditActionSkipped,
		DetectorType:          detectorType,
		Service:               detectorType.String(),
		CredentialFingerprint: fingerprint,
		Error:                 err.Error(),
	})
}

func (v *VerificationCache) auditCacheHit(
	detectorType detector_typepb.DetectorType,
	fingerprint string,
	statusCode int,
	status detectors.VerificationStatus,
) {
	v.audit(AuditRecord{
		Timestamp:             v.now(),
		Action:                AuditActionCacheHit,
		DetectorType:          detectorType,
		Service:               detectorType.String(),
		CredentialFingerprint: fingerprint,
		HTTPStatusCode:        statusCode,
		Outcome:               status.String(),
		CacheHit:              true,
	})
}

func (v *VerificationCache) audit(record AuditRecord) {
	if v.auditSink != nil {
		v.auditSink.Record(record)
	}
}

func (v *VerificationCache) credentialFingerprint(result detectors.Result) (string, error) {
	fingerprint, err := v.credentialFingerprintBytes(result)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(fingerprint), nil
}

func (v *VerificationCache) credentialFingerprintBytes(result detectors.Result) ([]byte, error) {
	v.hashMu.Lock()
	defer v.hashMu.Unlock()

	keyBytes := bytes.Join([][]byte{result.Raw, result.RawV2}, nil)
	return v.hasher.Hash(keyBytes)
}

func mustCacheKey(v *VerificationCache, result detectors.Result) []byte {
	key, err := v.getResultCacheKey(result)
	if err != nil {
		return nil
	}
	return key
}

func (v *VerificationCache) getResultCacheKey(result detectors.Result) ([]byte, error) {
	fingerprint, err := v.credentialFingerprintBytes(result)
	if err != nil {
		return nil, err
	}
	keyBytes, err := binary.Append(fingerprint, binary.BigEndian, result.DetectorType)
	if err != nil {
		return nil, err
	}

	v.hashMu.Lock()
	defer v.hashMu.Unlock()
	return v.hasher.Hash(keyBytes)
}

// Fingerprint returns the opaque, one-way credential fingerprint used by the audit log and cache key.
func (v *VerificationCache) Fingerprint(result detectors.Result) (string, error) {
	return v.credentialFingerprint(result)
}

func (v *VerificationCache) Summary() Summary {
	summary := Summary{}
	if m, ok := v.metrics.(*InMemoryMetrics); ok {
		summary.Candidates = m.VerificationCandidates.Load()
		summary.VerificationRequests = m.VerificationRequests.Load()
		summary.Retries = m.VerificationRetries.Load()
		summary.RateLimitedAttempts = m.VerificationRateLimited.Load()
		summary.CacheUnavailable = m.VerificationCacheUnavailable.Load()
		summary.Valid = m.VerifiedOutcomes.Load()
		summary.Invalid = m.InvalidOutcomes.Load()
		summary.Unverified = m.UnverifiedOutcomes.Load()
		summary.PendingManual = m.PendingManualOutcomes.Load()
		summary.RateLimitedUnverified = m.RateLimitedUnverified.Load()
		summary.RateLimitedPendingManual = m.RateLimitedPendingManual.Load()
	}
	return summary
}

// Summary is a snapshot of verification scheduling and classification counters.
type Summary struct {
	Candidates               int64
	VerificationRequests     int64
	Retries                  int64
	RateLimitedAttempts      int64
	CacheUnavailable         int64
	Valid                    int64
	Invalid                  int64
	Unverified               int64
	PendingManual            int64
	RateLimitedUnverified    int64
	RateLimitedPendingManual int64
}

func (s Summary) String() string {
	return fmt.Sprintf(
		"candidates=%d requests=%d retries=%d rate_limited_attempts=%d valid=%d invalid=%d unverified=%d pending_manual=%d rate_limited_unverified=%d rate_limited_pending_manual=%d cache_unavailable=%d",
		s.Candidates,
		s.VerificationRequests,
		s.Retries,
		s.RateLimitedAttempts,
		s.Valid,
		s.Invalid,
		s.Unverified,
		s.PendingManual,
		s.RateLimitedUnverified,
		s.RateLimitedPendingManual,
		s.CacheUnavailable,
	)
}
