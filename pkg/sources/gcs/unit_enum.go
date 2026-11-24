package gcs

import (
	"fmt"
	"slices"
	"strings"

	"google.golang.org/api/iterator"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// unitPrefixesFromConn normalizes the configured unit prefixes into the
// canonical list used for enumeration. It sorts them, trims blanks, and drops a
// prefix that another configured prefix already covers, so two overlapping
// prefixes never put the same object in two units. The result depends only on
// the configuration, never on the bucket contents, which is what makes a unit
// set reproducible.
func unitPrefixesFromConn(conn *sourcespb.GCS) []string {
	if conn == nil {
		return nil
	}
	return canonicalUnitPrefixes(conn.GetUnitPrefixes())
}

// canonicalUnitPrefixes sorts, trims, deduplicates, and removes nested
// prefixes. A prefix that starts with another kept prefix covers a subset of
// it, so it is dropped rather than enumerated as a second unit.
func canonicalUnitPrefixes(prefixes []string) []string {
	cleaned := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		if trimmed := strings.TrimSpace(prefix); trimmed != "" {
			cleaned = append(cleaned, trimmed)
		}
	}
	if len(cleaned) == 0 {
		return nil
	}

	slices.Sort(cleaned)
	kept := cleaned[:0]
	for _, prefix := range cleaned {
		if len(kept) > 0 && strings.HasPrefix(prefix, kept[len(kept)-1]) {
			continue
		}
		kept = append(kept, prefix)
	}
	return slices.Clone(kept)
}

// unitsForBucket covers bucket when no unit prefixes are configured and each
// prefix otherwise. It is a pure function of the configuration, so the same
// config always yields the same units.
func (s *Source) unitsForBucket(bucket string) []GCSObjectUnit {
	if len(s.unitPrefixes) == 0 {
		return []GCSObjectUnit{{Bucket: bucket}}
	}
	units := make([]GCSObjectUnit, len(s.unitPrefixes))
	for i, prefix := range s.unitPrefixes {
		units[i] = GCSObjectUnit{Bucket: bucket, Prefix: prefix}
	}
	return units
}

// validateUnitPrefixes rejects a prefix list that cannot form unambiguous units.
// A blank entry is a configuration mistake rather than a request for the whole
// bucket, so it is reported instead of being silently dropped.
func validateUnitPrefixes(prefixes []string) error {
	for _, prefix := range prefixes {
		if strings.TrimSpace(prefix) == "" {
			return fmt.Errorf("gcs: unit_prefixes contains a blank prefix")
		}
	}
	return nil
}

// Enumerate implements the SourceUnitEnumerator interface. Each configured
// bucket becomes one unit, or one unit per configured prefix. Buckets come from
// the connection when it lists them, so enumeration does not depend on whether
// the credentials can list every bucket in the project: a bucket that cannot be
// listed is still reported as a unit, and its failure surfaces when that unit is
// scanned rather than failing the whole enumeration.
func (s *Source) Enumerate(ctx context.Context, reporter sources.UnitReporter) error {
	gm, ok := s.gcsManager.(*gcsManager)
	if !ok {
		return fmt.Errorf("gcs: enumeration requires a configured manager")
	}

	buckets, err := gm.enumerableBuckets(ctx)
	if err != nil {
		// Without a bucket list there is nothing to enumerate.
		if reportErr := reporter.UnitErr(ctx, err); reportErr != nil {
			return reportErr
		}
		return nil
	}

	for _, bucket := range buckets {
		if common.IsDone(ctx) {
			return ctx.Err()
		}
		for _, unit := range s.unitsForBucket(bucket) {
			if err := reporter.UnitOk(ctx, unit); err != nil {
				return err
			}
		}
	}
	return nil
}

// enumerableBuckets returns the buckets enumeration should cover, in a stable
// order. With include buckets configured it uses those, matching exactly the
// targets the scan would attempt; otherwise it lists the project's buckets and
// applies the exclude globs. A bucket that does not exist keeps its place in
// the list so scanning it reports a config error against its own unit.
func (g *gcsManager) enumerableBuckets(ctx context.Context) ([]string, error) {
	if g.withoutAuth || len(g.includeBuckets) > 0 {
		buckets := make([]string, 0, len(g.includeBuckets))
		for name := range g.includeBuckets {
			buckets = append(buckets, name)
		}
		slices.Sort(buckets)
		ctx.Logger().V(1).Info("Enumerating configured buckets", "buckets", len(buckets))
		return buckets, nil
	}

	bkts := g.client.Buckets(ctx, g.projectID)
	var buckets []string
	for {
		bkt, err := bkts.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, classifyUnitError(fmt.Errorf("failed to list buckets: %w", err), "list buckets", "", "")
		}
		if !g.shouldIncludeBucket(ctx, bkt.Name) || g.shouldExcludeBucket(ctx, bkt.Name) {
			ctx.Logger().V(4).Info("Skipping bucket", "bucket", bkt.Name, "reason", "matches filter")
			continue
		}
		buckets = append(buckets, bkt.Name)
	}
	slices.Sort(buckets)
	return buckets, nil
}
