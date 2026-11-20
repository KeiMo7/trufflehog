package verificationcache

import "time"

const (
	DefaultCacheTTL       = 12 * time.Hour
	DefaultBackoffInitial = time.Second
	DefaultBackoffMaximum = 30 * time.Second
	defaultRateLimitBurst = 1
)

// Config controls the optional verification scheduler features. The zero value is normalized to the historical
// behavior: no rate limiting, no retries, and cache entries that only carry the verification verdict.
type Config struct {
	// CacheTTL is how long a definitive verification result remains reusable.
	CacheTTL time.Duration
	// InvalidCooldown is how long a definitive invalid result remains reusable. A shorter cooldown lets a credential be
	// rechecked sooner without treating transient provider failures as definitive.
	InvalidCooldown time.Duration
	// RateLimitInterval is the minimum interval between remote verification operations for the same detector service.
	// Zero disables per-service rate limiting.
	RateLimitInterval time.Duration
	// RateLimitBurst is the maximum number of immediate operations allowed for a service. Values below one use one.
	RateLimitBurst int
	// MaxRetries is the number of retries after the initial attempt when a provider rate limits the request. Zero
	// disables retry-on-429.
	MaxRetries int
	// BackoffInitial and BackoffMaximum bound the exponential delay used between rate-limited attempts.
	BackoffInitial time.Duration
	BackoffMaximum time.Duration
	// AllowSideEffectVerification permits detectors marked SideEffectVerifier to run. It is false by default.
	AllowSideEffectVerification bool
	// TrackOutcomes stores and reports the expanded verification status model. The legacy New constructor leaves this
	// false so existing callers retain their exact result shape.
	TrackOutcomes bool
	// AuditSink receives one record for every remote verification attempt, cache hit, cache write, and skipped attempt.
	AuditSink AuditSink
	// Now is injectable for tests. Nil means time.Now.
	Now func() time.Time
}

func defaultConfig() Config {
	return Config{
		CacheTTL:        DefaultCacheTTL,
		InvalidCooldown: DefaultCacheTTL,
		RateLimitBurst:  defaultRateLimitBurst,
		BackoffInitial:  DefaultBackoffInitial,
		BackoffMaximum:  DefaultBackoffMaximum,
	}
}

func (c Config) normalized() Config {
	defaults := defaultConfig()
	if c.CacheTTL <= 0 {
		c.CacheTTL = defaults.CacheTTL
	}
	if c.InvalidCooldown <= 0 {
		c.InvalidCooldown = c.CacheTTL
	}
	if c.RateLimitBurst <= 0 {
		c.RateLimitBurst = defaults.RateLimitBurst
	}
	if c.BackoffInitial <= 0 {
		c.BackoffInitial = defaults.BackoffInitial
	}
	if c.BackoffMaximum <= 0 {
		c.BackoffMaximum = defaults.BackoffMaximum
	}
	if c.BackoffMaximum < c.BackoffInitial {
		c.BackoffMaximum = c.BackoffInitial
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

func (c Config) trackOutcomes() bool {
	return c.TrackOutcomes || c.RateLimitInterval > 0 || c.MaxRetries > 0
}
