package verificationcache

import (
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

// AuditAction identifies a verification lifecycle event.
type AuditAction string

const (
	AuditActionRequest    AuditAction = "request"
	AuditActionRetry      AuditAction = "retry"
	AuditActionCacheHit   AuditAction = "cache_hit"
	AuditActionCacheStore AuditAction = "cache_store"
	AuditActionSkipped    AuditAction = "skipped"
)

// AuditRecord is deliberately credential-free: CredentialFingerprint is a one-way hash and never the raw secret.
type AuditRecord struct {
	Timestamp             time.Time                    `json:"timestamp"`
	Action                AuditAction                  `json:"action"`
	DetectorType          detector_typepb.DetectorType `json:"detector_type"`
	Service               string                       `json:"service"`
	CredentialFingerprint string                       `json:"credential_fingerprint"`
	Attempt               int                          `json:"attempt,omitempty"`
	HTTPStatusCode        int                          `json:"http_status_code,omitempty"`
	Outcome               string                       `json:"outcome,omitempty"`
	RateLimited           bool                         `json:"rate_limited,omitempty"`
	CacheHit              bool                         `json:"cache_hit,omitempty"`
	Error                 string                       `json:"error,omitempty"`
}

// AuditSink receives verification audit records. Implementations must be safe for concurrent use.
type AuditSink interface {
	Record(AuditRecord)
}

type auditSinkFunc func(AuditRecord)

func (f auditSinkFunc) Record(record AuditRecord) { f(record) }

// NewAuditSinkFunc adapts a function to AuditSink.
func NewAuditSinkFunc(fn func(AuditRecord)) AuditSink {
	if fn == nil {
		return nil
	}
	return auditSinkFunc(fn)
}

// MemoryAuditLog keeps the full audit trail in memory.
type MemoryAuditLog struct {
	mu      sync.RWMutex
	records []AuditRecord
}

func NewMemoryAuditLog() *MemoryAuditLog {
	return &MemoryAuditLog{}
}

func (m *MemoryAuditLog) Record(record AuditRecord) {
	m.mu.Lock()
	m.records = append(m.records, record)
	m.mu.Unlock()
}

func (m *MemoryAuditLog) Records() []AuditRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]AuditRecord(nil), m.records...)
}

// JSONLAuditLog writes one JSON object per line.
type JSONLAuditLog struct {
	mu      sync.Mutex
	encoder *json.Encoder
}

func NewJSONLAuditLog(w io.Writer) *JSONLAuditLog {
	return &JSONLAuditLog{encoder: json.NewEncoder(w)}
}

func (j *JSONLAuditLog) Record(record AuditRecord) {
	j.mu.Lock()
	defer j.mu.Unlock()
	_ = j.encoder.Encode(record)
}

// MultiAuditSink fans a record out to every non-nil sink.
type MultiAuditSink []AuditSink

func (m MultiAuditSink) Record(record AuditRecord) {
	for _, sink := range m {
		if sink != nil {
			sink.Record(record)
		}
	}
}
