package gcs

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"cloud.google.com/go/storage"
	"golang.org/x/sync/errgroup"
	"google.golang.org/api/iterator"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// errUnitIncomplete is the sentinel wrapped by a unit scan that listed its scope
// but could not read every object in it.
var errUnitIncomplete = errors.New("unit scan incomplete")

// ChunkUnit implements the SourceUnitChunker interface. It scans one unit, a
// whole bucket or one prefix of it, and confines any failure to that unit.
//
// The returned error is classified so the manager can record it against the
// unit: a sources.UnitIncompleteError means the unit was scanned but not in
// full, so the unit is not counted finished and a later run will cover it. Any
// other error is a setup failure before the unit's content was read. Context
// cancellation is returned untouched, because the manager treats it as an
// interruption of the whole job rather than a unit failure.
func (s *Source) ChunkUnit(ctx context.Context, unit sources.SourceUnit, reporter sources.ChunkReporter) error {
	gcsUnit, ok := unit.(GCSObjectUnit)
	if !ok {
		return fmt.Errorf("unsupported unit type: %T", unit)
	}
	gm, ok := s.gcsManager.(*gcsManager)
	if !ok {
		return fmt.Errorf("gcs: unit scan requires a configured manager")
	}

	unitID, kind := gcsUnit.SourceUnitID()
	ctx = context.WithValues(ctx, "unit_kind", kind, "unit", unitID)
	ctx.Logger().V(3).Info("Scanning unit")

	progress := newUnitProgress(unitID, &s.Progress)
	err := s.scanUnit(ctx, gm, gcsUnit, reporter, progress)
	if ctx.Err() != nil {
		// Cancellation is not a failure of this unit's content; leave its
		// progress unsettled so a resumed run continues it.
		progress.finish(false)
		return ctx.Err()
	}
	if err != nil {
		progress.finish(false)
		// Report the failure against the unit, then mark it incomplete so the
		// manager records it but neither fails the whole scan nor counts the
		// unit as finished.
		if reportErr := reporter.ChunkErr(ctx, err); reportErr != nil {
			return reportErr
		}
		return sources.UnitIncompleteError{Err: err}
	}
	progress.finish(true)
	return nil
}

// scanUnit streams a unit's listing and scans each object as it is listed, so
// the object name set is never held in memory. Filtered and skipped objects are
// left out of the unit entirely. Every downloaded object is deduplicated by
// content within the unit, and a read failure is recorded without stopping the
// rest of the unit.
func (s *Source) scanUnit(
	ctx context.Context,
	gm *gcsManager,
	unit GCSObjectUnit,
	reporter sources.ChunkReporter,
	progress *unitProgress,
) error {
	bkt := s.unitBucketHandle(ctx, gm, unit.Bucket)

	q, err := unitObjectQuery(unit)
	if err != nil {
		return classifyUnitError(err, "list objects", unit.Bucket, unit.Prefix)
	}

	// Content this unit scanned in an earlier run is skipped, so a rescan only
	// covers what is left. Newly scanned keys are persisted in batches as the
	// scan goes so an interruption does not lose all of them.
	seen := newContentSet(s.unitResumeKeys(ctx, unit))
	persist := newUnitResumeWriter(s, unit)
	persist.seed(seen.keys())
	defer persist.flush()

	var (
		scanned atomic.Uint64
		failed  atomic.Uint64
		pool    errgroup.Group
		listErr error
	)
	pool.SetLimit(max(s.concurrency, 1))

	objects := bkt.Objects(ctx, q)
	for {
		obj, iterErr := objects.Next()
		if iterErr == iterator.Done {
			break
		}
		if iterErr != nil {
			listErr = classifyUnitError(fmt.Errorf("listing objects: %w", iterErr), "list objects", unit.Bucket, unit.Prefix)
			break
		}
		if obj == nil {
			continue
		}

		octx := context.WithValues(ctx, "bucket", obj.Bucket, "object", obj.Name)
		// Objects an exclude rule removes belong to no unit and are not counted.
		if !gm.shouldIncludeObject(ctx, obj.Name) || gm.shouldExcludeObject(ctx, obj.Name) {
			octx.Logger().V(4).Info("Skipping object", "reason", "matches filter")
			continue
		}

		// Objects the scan never reads are out of the unit's work: neither their
		// count nor their bytes appear in its stats.
		if reason := gm.objectSkipReason(octx, obj); reason != "" {
			octx.Logger().V(4).Info("Skipping object", "reason", reason)
			continue
		}
		progress.addTotal(obj.Size)

		key := objectContentKey(obj)
		if !seen.reserve(key) {
			octx.Logger().V(4).Info("Skipping object", "reason", "already scanned")
			progress.objectDone(0)
			continue
		}

		pool.Go(func() error {
			defer common.RecoverWithExit(octx)
			if readErr := s.scanUnitObject(octx, bkt, obj, reporter); readErr != nil {
				failed.Add(1)
				// Release the reservation, so an identical object later in the unit
				// is still read rather than skipped as a duplicate of a failed one.
				seen.release(key)
				// The object stays in the total but not in the done count, so the
				// unit's numbers show it did not finish.
				// The classified error is safe to log: it names the unit and the
				// failure class, never the raw response or object body.
				classed := classifyUnitError(readErr, "read object", unit.Bucket, unit.Prefix)
				octx.Logger().V(2).Info("Could not read object", "error_kind", classed.Kind, "error", classed.Error())
				return nil
			}
			scanned.Add(1)
			seen.commit(key)
			persist.record(key)
			progress.objectDone(obj.Size)
			return nil
		})
	}
	_ = pool.Wait()

	if ctx.Err() != nil {
		return ctx.Err()
	}
	if listErr != nil {
		return listErr
	}
	if failed.Load() > 0 {
		return &UnitError{Kind: UnitErrorNetwork, Op: "read objects", Bucket: unit.Bucket, Prefix: unit.Prefix, err: errUnitIncomplete}
	}

	ctx.Logger().V(2).Info("Finished scanning unit", "objects_scanned", scanned.Load())
	// The unit's scanned content is kept, not cleared, so rescanning the unit
	// only reads what is new and matches how the legacy scan resumes.
	return nil
}

// unitBucketHandle returns a bucket handle with the manager's retry policy plus
// a hard attempt cap, so an object or listing that keeps failing ends after a
// bounded number of tries and fails its unit instead of retrying forever.
func (s *Source) unitBucketHandle(ctx context.Context, gm *gcsManager, name string) *storage.BucketHandle {
	bkt := &bucket{name: name}
	gm.setupBktHandle(ctx, bkt)
	return bkt.Retryer(storage.WithMaxAttempts(maxUnitRetryAttempts))
}

// maxUnitRetryAttempts bounds the retries of a single listing or object read, so
// a unit whose target is persistently failing gives up and reports the failure.
const maxUnitRetryAttempts = 3

// unitObjectQuery builds the streaming listing query for a unit. The prefix
// bounds the listing at the service, so no object outside the unit is fetched.
func unitObjectQuery(unit GCSObjectUnit) (*storage.Query, error) {
	q := &storage.Query{Prefix: unit.Prefix}
	if err := q.SetAttrSelection([]string{
		"Name",
		"Bucket",
		"ContentType",
		"Owner",
		"Size",
		"MD5",
		"Updated",
		"Created",
		"ACL",
		"MediaLink",
	}); err != nil {
		return nil, fmt.Errorf("failed to set attribute selection: %w", err)
	}
	return q, nil
}

// objectContentKey is the identity used to deduplicate object content within a
// unit. It uses the object's MD5 when the service reports one, and falls back to
// the bucket, name and generation otherwise.
func objectContentKey(obj *storage.ObjectAttrs) string {
	if len(obj.MD5) > 0 {
		return hex.EncodeToString(obj.MD5)
	}
	return fmt.Sprintf("%s/%s/%d", obj.Bucket, obj.Name, obj.Generation)
}

// objectSkipReason returns why the scan never reads an object, or "" if it
// reads it. It mirrors the legacy scan's size and file-type skips.
func (g *gcsManager) objectSkipReason(ctx context.Context, obj *storage.ObjectAttrs) string {
	if !isObjectTypeValid(ctx, obj.Name) {
		return "file type is skipped"
	}
	if !g.isObjectSizeValid(ctx, obj.Size) {
		return "size out of range"
	}
	return ""
}

// scanUnitObject reads one object and hands it to the file handler, so its
// chunks are reported against the unit the object belongs to.
func (s *Source) scanUnitObject(
	ctx context.Context,
	bkt *storage.BucketHandle,
	obj *storage.ObjectAttrs,
	reporter sources.ChunkReporter,
) error {
	reader, err := bkt.Object(obj.Name).NewReader(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = reader.Close() }()

	chunkSkel := &sources.Chunk{
		SourceName:   s.name,
		SourceType:   s.Type(),
		JobID:        s.jobId,
		SourceID:     s.sourceId,
		SourceVerify: s.verify,
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Gcs{
				Gcs: &source_metadatapb.GCS{
					Bucket:      sanitizer.UTF8(obj.Bucket),
					Filename:    sanitizer.UTF8(obj.Name),
					Link:        sanitizer.UTF8(obj.MediaLink),
					Email:       sanitizer.UTF8(obj.Owner),
					ContentType: sanitizer.UTF8(obj.ContentType),
					Acls:        objectACLs(obj.ACL),
					CreatedAt:   fmt.Sprintf("%d", obj.Created.Unix()),
					UpdatedAt:   obj.Updated.String(),
				},
			},
		},
	}

	return handlers.HandleFile(ctx, reader, chunkSkel, reporter)
}

// contentSet tracks the content keys of a unit: the ones already scanned and the
// ones being scanned now. Reserve marks a key while its object is downloading so
// a second object with the same content is not read twice; commit keeps the key
// once the download finished, and release lets an identical object be retried
// when the first download failed.
type contentSet struct {
	mu   sync.Mutex
	done map[string]struct{}
	busy map[string]struct{}
}

func newContentSet(done map[string]struct{}) *contentSet {
	if done == nil {
		done = make(map[string]struct{})
	}
	return &contentSet{done: done, busy: make(map[string]struct{})}
}

// reserve returns false if the key is already done or being scanned.
func (c *contentSet) reserve(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.done[key]; ok {
		return false
	}
	if _, ok := c.busy[key]; ok {
		return false
	}
	c.busy[key] = struct{}{}
	return true
}

// commit moves a reserved key to done.
func (c *contentSet) commit(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.busy, key)
	c.done[key] = struct{}{}
}

// release drops a reservation so the key can be tried again.
func (c *contentSet) release(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.busy, key)
}

// keys returns a copy of the done keys.
func (c *contentSet) keys() map[string]struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]struct{}, len(c.done))
	for key := range c.done {
		out[key] = struct{}{}
	}
	return out
}

// unitResumeKeys returns the content keys this unit scanned in an earlier run.
// A value that is not a list of keys is ignored, so an encoding from an older
// version never breaks the scan.
func (s *Source) unitResumeKeys(ctx context.Context, unit GCSObjectUnit) map[string]struct{} {
	unitID, _ := unit.SourceUnitID()
	raw := s.GetEncodedResumeInfoFor(unitID)
	seen := make(map[string]struct{})
	if raw == "" {
		return seen
	}
	var keys int
	for _, part := range strings.Split(raw, ",") {
		if !isContentKey(part) {
			continue
		}
		seen[part] = struct{}{}
		keys++
	}
	if keys > 0 {
		ctx.Logger().V(2).Info("Resuming unit scan", "already_scanned", keys, "unit", unitID)
	}
	return seen
}

// isContentKey reports whether a persisted value looks like the content key the
// unit writes: a hex MD5 or the bucket/name/generation fallback.
func isContentKey(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if len(value) == 32 {
		if _, err := hex.DecodeString(value); err == nil {
			return true
		}
	}
	return strings.Contains(value, "/")
}

// unitResumeWriter batches content keys and persists them at the same increment
// the legacy scan uses, so a long unit does not rewrite the resume encoding for
// every object. It owns the keys it has persisted so it never has to read them
// back while holding its lock.
type unitResumeWriter struct {
	source  *Source
	unitID  string
	mu      sync.Mutex
	written []string
	pending []string
}

func newUnitResumeWriter(s *Source, unit GCSObjectUnit) *unitResumeWriter {
	unitID, _ := unit.SourceUnitID()
	return &unitResumeWriter{source: s, unitID: unitID}
}

// seed sets the keys already persisted for the unit, so the next flush appends
// to them rather than replacing them.
func (w *unitResumeWriter) seed(keys map[string]struct{}) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.written = w.written[:0]
	for key := range keys {
		w.written = append(w.written, key)
	}
	sort.Strings(w.written)
}

func (w *unitResumeWriter) record(key string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pending = append(w.pending, key)
	if len(w.pending) >= defaultCachePersistIncrement {
		w.flushLocked()
	}
}

// flushLocked writes the pending keys. The caller holds the lock.
func (w *unitResumeWriter) flushLocked() {
	if len(w.pending) == 0 {
		return
	}
	w.written = append(w.written, w.pending...)
	w.pending = nil
	w.source.SetEncodedResumeInfoFor(w.unitID, strings.Join(w.written, ","))
}

func (w *unitResumeWriter) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.flushLocked()
}
