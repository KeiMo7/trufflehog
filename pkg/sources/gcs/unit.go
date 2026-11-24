package gcs

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// SourceUnitKindBucket is the kind of a GCS unit that covers a whole bucket.
const SourceUnitKindBucket sources.SourceUnitKind = "bucket"

// SourceUnitKindPrefix is the kind of a GCS unit that covers one prefix of a
// bucket when the connection configures unit prefixes.
const SourceUnitKindPrefix sources.SourceUnitKind = "prefix"

// unitIDSeparator joins the bucket and prefix halves of a unit ID. S3 keys and
// bucket names may both contain it, but a GCS bucket name may not contain "|",
// so splitting on the first one is unambiguous.
const unitIDSeparator = "|"

// GCSObjectUnit is one independently scannable piece of a GCS source: either a
// whole bucket, or one prefix within a bucket.
//
// The zero Prefix means the unit covers the whole bucket, which keeps a unit
// scanned before prefixes were configurable identical to one enumerated after.
type GCSObjectUnit struct {
	Bucket string `json:"bucket"`
	// Prefix is the key prefix that bounds the unit's objects. It is empty for a
	// whole-bucket unit.
	Prefix string `json:"prefix,omitempty"`
}

var _ sources.SourceUnit = GCSObjectUnit{}

// SourceUnitID returns a stable identity built only from the bucket and prefix,
// so the same configuration enumerates the same IDs on every run, in any order.
// The kind distinguishes a whole-bucket unit from a prefix unit even when the
// prefix is empty.
func (u GCSObjectUnit) SourceUnitID() (string, sources.SourceUnitKind) {
	if u.Prefix == "" {
		return u.Bucket, SourceUnitKindBucket
	}
	return u.Bucket + unitIDSeparator + u.Prefix, SourceUnitKindPrefix
}

// Display is the human readable form of the unit. It never carries object
// content, only the bucket and the configured prefix.
func (u GCSObjectUnit) Display() string {
	if u.Prefix == "" {
		return u.Bucket
	}
	return fmt.Sprintf("Bucket=%s Prefix=%s", u.Bucket, u.Prefix)
}

// unitEnvelope is the JSON shape a host application persists for an enumerated
// unit between the enumerate and scan passes: the SourceUnit proto marshalled
// with encoding/json, where unit_data carries the original unit as
// base64-encoded bytes.
type unitEnvelope struct {
	ID       string `json:"id"`
	Kind     string `json:"kind,omitempty"`
	Display  string `json:"display,omitempty"`
	UnitData string `json:"unit_data,omitempty"`
}

// UnmarshalSourceUnit implements SourceUnitUnmarshaller. It accepts three
// shapes: the persisted envelope carrying unit_data (round-trips the unit
// exactly), the envelope without unit_data (rebuilt from id), and a bare
// GCSObjectUnit.
func (s *Source) UnmarshalSourceUnit(data []byte) (sources.SourceUnit, error) {
	var envelope unitEnvelope
	if err := json.Unmarshal(data, &envelope); err == nil && envelope.Kind != "" {
		if envelope.UnitData != "" {
			if decoded, err := base64.StdEncoding.DecodeString(envelope.UnitData); err == nil {
				var unit GCSObjectUnit
				if json.Unmarshal(decoded, &unit) == nil && unit.Bucket != "" {
					return unit, nil
				}
			}
		}
		if envelope.ID != "" && (envelope.Kind == string(SourceUnitKindBucket) || envelope.Kind == string(SourceUnitKindPrefix)) {
			return unitFromID(envelope.ID, sources.SourceUnitKind(envelope.Kind))
		}
	}

	var unit GCSObjectUnit
	if err := json.Unmarshal(data, &unit); err != nil {
		return nil, err
	}
	if unit.Bucket == "" {
		return nil, fmt.Errorf("not a GCSObjectUnit")
	}
	return unit, nil
}

// unitFromID rebuilds a unit from its ID alone. A prefix unit's ID is
// "<bucket>|<prefix>"; a bucket unit's is the bare bucket name.
func unitFromID(id string, kind sources.SourceUnitKind) (sources.SourceUnit, error) {
	if kind == SourceUnitKindBucket {
		if id == "" {
			return nil, fmt.Errorf("empty bucket unit ID")
		}
		return GCSObjectUnit{Bucket: id}, nil
	}
	bucket, prefix, found := strings.Cut(id, unitIDSeparator)
	if !found || bucket == "" || prefix == "" {
		return nil, fmt.Errorf("malformed prefix unit ID %q", id)
	}
	return GCSObjectUnit{Bucket: bucket, Prefix: prefix}, nil
}
