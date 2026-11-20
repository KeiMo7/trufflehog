package verificationcache

import (
	stdContext "context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type scriptedReply struct {
	statusCode int
	err        error
}

type scriptedResultVerifier struct {
	results []detectors.Result
	replies map[string][]scriptedReply

	verifyCalls []string
	mu          sync.Mutex
}

func (d *scriptedResultVerifier) FromData(_ stdContext.Context, verify bool, _ []byte) ([]detectors.Result, error) {
	out := make([]detectors.Result, len(d.results))
	for i, result := range d.results {
		out[i] = result
		if !verify {
			out[i].Verified = false
			out[i].ClearVerificationError()
			out[i].VerificationStatusCode = 0
		}
	}
	return out, nil
}

func (d *scriptedResultVerifier) VerifyResult(_ stdContext.Context, result *detectors.Result) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.verifyCalls = append(d.verifyCalls, result.Redacted)
	replies := d.replies[result.Redacted]
	if len(replies) == 0 {
		result.Verified = false
		result.SetVerificationError(errors.New("connection refused"))
		return
	}
	reply := replies[0]
	d.replies[result.Redacted] = replies[1:]

	if reply.err != nil {
		result.Verified = false
		result.SetVerificationError(reply.err)
		return
	}
	if reply.statusCode >= 200 && reply.statusCode < 300 {
		result.Verified = true
		result.ClearVerificationError()
		return
	}
	result.Verified = false
	result.SetVerificationError(fmt.Errorf("unexpected HTTP response status %d", reply.statusCode))
}

func (d *scriptedResultVerifier) Keywords() []string { return nil }
func (d *scriptedResultVerifier) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Github
}
func (d *scriptedResultVerifier) Description() string { return "" }

var (
	_ detectors.Detector       = (*scriptedResultVerifier)(nil)
	_ detectors.ResultVerifier = (*scriptedResultVerifier)(nil)
)

type sideEffectResultVerifier struct {
	scriptedResultVerifier
}

func (*sideEffectResultVerifier) VerificationHasSideEffects() bool { return true }

var _ detectors.SideEffectVerifier = (*sideEffectResultVerifier)(nil)

type validatingResultVerifier struct {
	scriptedResultVerifier
}

func (*validatingResultVerifier) ValidateResult(result *detectors.Result) error {
	if string(result.Raw) == "malformed" {
		return errors.New("bad shape")
	}
	return nil
}

var _ detectors.ResultValidator = (*validatingResultVerifier)(nil)

type httpStatusResultVerifier struct {
	url    string
	client *http.Client
}

func (d *httpStatusResultVerifier) FromData(_ stdContext.Context, _ bool, _ []byte) ([]detectors.Result, error) {
	return []detectors.Result{oneResult("http")}, nil
}

func (d *httpStatusResultVerifier) VerifyResult(ctx stdContext.Context, result *detectors.Result) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.url, nil)
	if err != nil {
		result.SetVerificationError(err)
		return
	}
	resp, err := d.client.Do(req)
	if err != nil {
		result.SetVerificationError(err)
		return
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	result.Verified = resp.StatusCode >= 200 && resp.StatusCode < 300
	if !result.Verified {
		result.SetVerificationError(fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode))
	}
}

func (d *httpStatusResultVerifier) Keywords() []string { return nil }
func (d *httpStatusResultVerifier) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Github
}
func (d *httpStatusResultVerifier) Description() string { return "" }

var _ detectors.ResultVerifier = (*httpStatusResultVerifier)(nil)

func testConfig(audit AuditSink, now func() time.Time) Config {
	return Config{
		CacheTTL:        time.Hour,
		InvalidCooldown: time.Hour,
		MaxRetries:      2,
		BackoffInitial:  time.Millisecond,
		BackoffMaximum:  5 * time.Millisecond,
		TrackOutcomes:   true,
		AuditSink:       audit,
		Now:             now,
	}
}

func oneResult(raw string) detectors.Result {
	return detectors.Result{
		DetectorType: detector_typepb.DetectorType_Github,
		Raw:          []byte(raw),
		RawV2:        []byte(raw + "-v2"),
		Redacted:     raw,
	}
}

func TestVerificationCache_DuplicateCandidateUsesOneRequest(t *testing.T) {
	detector := &scriptedResultVerifier{
		results: []detectors.Result{oneResult("duplicate"), oneResult("duplicate")},
		replies: map[string][]scriptedReply{
			"duplicate": {{statusCode: 200}},
		},
	}
	metrics := &InMemoryMetrics{}
	cache := NewWithConfig(simple.NewCache[detectors.Result](), metrics, testConfig(nil, time.Now))

	results, err := cache.FromData(logContext.Background(), detector, true, false, nil)
	require.NoError(t, err)
	require.Len(t, results, 2)
	assert.Len(t, detector.verifyCalls, 1)
	assert.True(t, results[0].Verified)
	assert.True(t, results[1].Verified)
	assert.True(t, results[1].VerificationFromCache)
	assert.Equal(t, int64(1), metrics.VerificationRequests.Load())
	assert.Equal(t, int64(2), metrics.VerificationCandidates.Load())
}

func TestVerificationCache_RateLimitRetriesThenSucceeds(t *testing.T) {
	audit := NewMemoryAuditLog()
	detector := &scriptedResultVerifier{
		results: []detectors.Result{oneResult("retry")},
		replies: map[string][]scriptedReply{
			"retry": {{statusCode: 429}, {statusCode: 429}, {statusCode: 200}},
		},
	}
	metrics := &InMemoryMetrics{}
	cache := NewWithConfig(simple.NewCache[detectors.Result](), metrics, testConfig(audit, time.Now))

	results, err := cache.FromData(logContext.Background(), detector, true, false, nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.True(t, results[0].Verified)
	assert.Equal(t, detectors.VerificationStatusValid, results[0].VerificationStatus)
	assert.Len(t, detector.verifyCalls, 3)
	assert.Equal(t, int64(3), metrics.VerificationRequests.Load())
	assert.Equal(t, int64(2), metrics.VerificationRateLimited.Load())
	assert.Equal(t, int64(2), metrics.VerificationRetries.Load())

	records := audit.Records()
	require.NotEmpty(t, records)
	var codes []int
	for _, record := range records {
		if record.Action == AuditActionRequest || record.Action == AuditActionRetry {
			codes = append(codes, record.HTTPStatusCode)
		}
	}
	assert.Equal(t, []int{429, 429, 200}, codes)
}

func TestVerificationCache_RateLimitExhaustionMarksPendingManual(t *testing.T) {
	detector := &scriptedResultVerifier{
		results: []detectors.Result{oneResult("throttled")},
		replies: map[string][]scriptedReply{
			"throttled": {{statusCode: 429}, {statusCode: 429}},
		},
	}
	metrics := &InMemoryMetrics{}
	cfg := testConfig(nil, time.Now)
	cfg.MaxRetries = 1
	cache := NewWithConfig(simple.NewCache[detectors.Result](), metrics, cfg)

	results, err := cache.FromData(logContext.Background(), detector, true, false, nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.False(t, results[0].Verified)
	assert.Equal(t, detectors.VerificationStatusPendingManualConfirmation, results[0].VerificationStatus)
	assert.Equal(t, int64(1), metrics.PendingManualOutcomes.Load())
	assert.Equal(t, int64(2), metrics.VerificationRequests.Load())
}

func TestVerificationCache_UnreachableIsUnverifiedAndRetriedNextRound(t *testing.T) {
	detector := &scriptedResultVerifier{
		results: []detectors.Result{oneResult("unreachable")},
		replies: map[string][]scriptedReply{
			"unreachable": {
				{err: errors.New("dial tcp: connection refused")},
				{err: errors.New("dial tcp: connection refused")},
			},
		},
	}
	metrics := &InMemoryMetrics{}
	cache := NewWithConfig(simple.NewCache[detectors.Result](), metrics, testConfig(nil, time.Now))

	first, err := cache.FromData(logContext.Background(), detector, true, false, nil)
	require.NoError(t, err)
	require.Len(t, first, 1)
	assert.Equal(t, detectors.VerificationStatusUnverified, first[0].VerificationStatus)

	second, err := cache.FromData(logContext.Background(), detector, true, false, nil)
	require.NoError(t, err)
	require.Len(t, second, 1)
	assert.Equal(t, detectors.VerificationStatusUnverified, second[0].VerificationStatus)
	assert.Len(t, detector.verifyCalls, 2)
	assert.Equal(t, int64(2), metrics.UnverifiedOutcomes.Load())
}

func TestVerificationCache_InvalidCooldownAndExpiry(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	detector := &scriptedResultVerifier{
		results: []detectors.Result{oneResult("invalid")},
		replies: map[string][]scriptedReply{
			"invalid": {{statusCode: 401}, {statusCode: 401}},
		},
	}
	cache := NewWithConfig(
		simple.NewCache[detectors.Result](),
		&InMemoryMetrics{},
		testConfig(nil, func() time.Time { return now }),
	)

	first, err := cache.FromData(logContext.Background(), detector, true, false, nil)
	require.NoError(t, err)
	assert.Equal(t, detectors.VerificationStatusInvalid, first[0].VerificationStatus)

	now = now.Add(30 * time.Minute)
	second, err := cache.FromData(logContext.Background(), detector, true, false, nil)
	require.NoError(t, err)
	assert.True(t, second[0].VerificationFromCache)
	assert.Len(t, detector.verifyCalls, 1)

	now = now.Add(31 * time.Minute)
	third, err := cache.FromData(logContext.Background(), detector, true, false, nil)
	require.NoError(t, err)
	assert.Equal(t, detectors.VerificationStatusInvalid, third[0].VerificationStatus)
	assert.Len(t, detector.verifyCalls, 2)
}

func TestVerificationCache_InvalidFormatSkipsRequest(t *testing.T) {
	detector := &validatingResultVerifier{scriptedResultVerifier{
		results: []detectors.Result{oneResult("malformed"), oneResult("valid")},
		replies: map[string][]scriptedReply{
			"valid": {{statusCode: 200}},
		},
	}}
	cache := NewWithConfig(
		simple.NewCache[detectors.Result](),
		&InMemoryMetrics{},
		testConfig(nil, time.Now),
	)

	results, err := cache.FromData(logContext.Background(), detector, true, false, nil)
	require.NoError(t, err)
	require.Len(t, results, 2)
	assert.Equal(t, detectors.VerificationStatusInvalid, results[0].VerificationStatus)
	assert.Equal(t, []string{"valid"}, detector.verifyCalls)
}

func TestVerificationCache_SideEffectVerificationIsSkippedByDefault(t *testing.T) {
	detector := &sideEffectResultVerifier{scriptedResultVerifier{
		results: []detectors.Result{oneResult("refresh")},
		replies: map[string][]scriptedReply{
			"refresh": {{statusCode: 200}},
		},
	}}
	cache := NewWithConfig(
		simple.NewCache[detectors.Result](),
		&InMemoryMetrics{},
		testConfig(nil, time.Now),
	)

	results, err := cache.FromData(logContext.Background(), detector, true, false, nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Empty(t, detector.verifyCalls)
	assert.True(t, results[0].VerificationSkipped)
	assert.Equal(t, detectors.VerificationStatusPendingManualConfirmation, results[0].VerificationStatus)

	cfg := testConfig(nil, time.Now)
	cfg.AllowSideEffectVerification = true
	allowed := NewWithConfig(simple.NewCache[detectors.Result](), &InMemoryMetrics{}, cfg)
	results, err = allowed.FromData(logContext.Background(), detector, true, false, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"refresh"}, detector.verifyCalls)
	assert.Equal(t, detectors.VerificationStatusValid, results[0].VerificationStatus)
}

func TestVerificationCache_AcceptanceDistribution(t *testing.T) {
	results := []detectors.Result{
		oneResult("valid-1"),
		oneResult("valid-2"),
		oneResult("invalid-1"),
		oneResult("unreachable-1"),
		oneResult("valid-1"),
		oneResult("throttled-1"),
		oneResult("valid-3"),
		oneResult("valid-2"),
		oneResult("invalid-1"),
		oneResult("unreachable-1"),
		oneResult("valid-3"),
		oneResult("valid-1"),
	}
	detector := &scriptedResultVerifier{
		results: results,
		replies: map[string][]scriptedReply{
			"valid-1":       {{statusCode: 200}},
			"valid-2":       {{statusCode: 200}},
			"valid-3":       {{statusCode: 200}},
			"invalid-1":     {{statusCode: 401}},
			"unreachable-1": {{err: errors.New("connection refused")}, {err: errors.New("connection refused")}},
			"throttled-1":   {{statusCode: 429}, {statusCode: 429}},
		},
	}
	metrics := &InMemoryMetrics{}
	cfg := testConfig(nil, time.Now)
	cfg.MaxRetries = 1
	cache := NewWithConfig(simple.NewCache[detectors.Result](), metrics, cfg)

	got, err := cache.FromData(logContext.Background(), detector, true, false, nil)
	require.NoError(t, err)
	require.Len(t, got, len(results))

	summary := cache.Summary()
	t.Logf("acceptance summary: %s", summary.String())
	assert.Equal(t, int64(12), summary.Candidates)
	assert.Equal(t, int64(8), summary.VerificationRequests)
	assert.Equal(t, int64(2), summary.RateLimitedAttempts)
	assert.Equal(t, int64(7), summary.Valid)
	assert.Equal(t, int64(2), summary.Invalid)
	assert.Equal(t, int64(2), summary.Unverified)
	assert.Equal(t, int64(1), summary.PendingManual)
	assert.Equal(t, int64(0), summary.RateLimitedUnverified)
	assert.Equal(t, int64(1), summary.RateLimitedPendingManual)
}

func TestVerificationCache_AuditUsesObservedHTTPStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	audit := NewMemoryAuditLog()
	detector := &httpStatusResultVerifier{
		url:    server.URL,
		client: common.SaneHttpClient(),
	}
	cache := NewWithConfig(
		simple.NewCache[detectors.Result](),
		&InMemoryMetrics{},
		testConfig(audit, time.Now),
	)

	results, err := cache.FromData(logContext.Background(), detector, true, false, nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, http.StatusNoContent, results[0].VerificationStatusCode)

	var requestCodes []int
	for _, record := range audit.Records() {
		if record.Action == AuditActionRequest {
			requestCodes = append(requestCodes, record.HTTPStatusCode)
		}
	}
	assert.Equal(t, []int{http.StatusNoContent}, requestCodes)
}
