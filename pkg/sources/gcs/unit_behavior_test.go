package gcs

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log/logtest"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sourcestest"
)

// Enumerating with anonymous credentials and with static credentials yields the
// same units: unit division depends only on the configuration, not on how the
// source authenticated.
func TestEnumerate_SameUnitsAnonAndCredentialed(t *testing.T) {
	_, _ = newFakeGCSServer(t, map[string]fakeBucket{
		"alpha": {objects: map[string]fakeObject{"logs/a": {content: "a"}}},
		"beta":  {objects: nil},
	})
	configs := map[string]*sourcespb.GCS{
		"anonymous": {
			IncludeBuckets: []string{"alpha", "beta"},
			UnitPrefixes:   []string{"logs/", "keys/"},
			Credential:     &sourcespb.GCS_Unauthenticated{},
		},
		"credentialed": {
			ProjectId:      "test-project",
			IncludeBuckets: []string{"alpha", "beta"},
			UnitPrefixes:   []string{"keys/", "logs/"},
			Credential:     &sourcespb.GCS_ApiKey{},
		},
	}

	anonymous := listedUnits(t, newUnitTestSource(t, configs["anonymous"]))
	credentialed := listedUnits(t, newUnitTestSource(t, configs["credentialed"]))
	assert.Equal(t, anonymous, credentialed)
	assert.Equal(t, []string{"alpha|keys/", "alpha|logs/", "beta|keys/", "beta|logs/"}, anonymous)
}

// A configuration with an inaccessible bucket, a missing bucket and a healthy
// bucket scans the healthy one and reports each bad bucket against its own unit,
// distinguishing permission from a missing target.
func TestChunkUnit_MultiBucketMixedFailures(t *testing.T) {
	_, _ = newFakeGCSServer(t, map[string]fakeBucket{
		"denied": {listStatus: 403},
		"ok":     {objects: map[string]fakeObject{"a.txt": {content: "a"}}},
	})
	s := newUnitTestSource(t, &sourcespb.GCS{IncludeBuckets: []string{"denied", "missing", "ok"}})

	// The two bad units fail on their own and are marked incomplete.
	for bucket, wantKind := range map[string]UnitErrorKind{
		"denied":  UnitErrorPermission,
		"missing": UnitErrorConfig,
	} {
		reporter := sourcestest.SafeTestReporter{}
		err := s.ChunkUnit(context.Background(), GCSObjectUnit{Bucket: bucket}, &reporter)
		require.Error(t, err, bucket)
		assert.True(t, sources.IsUnitIncomplete(err), bucket)
		require.NotEmpty(t, reporter.ChunkErrs, bucket)
		kind, ok := unitErrorKind(reporter.ChunkErrs[0])
		require.True(t, ok, bucket)
		assert.Equal(t, wantKind, kind, bucket)
	}

	// The healthy unit is unaffected.
	reporter := sourcestest.SafeTestReporter{}
	require.NoError(t, s.ChunkUnit(context.Background(), GCSObjectUnit{Bucket: "ok"}, &reporter))
	assert.Len(t, reporter.Chunks, 1)
}

// Logs written while scanning a unit never contain object content, and never
// contain the raw credential the scan was configured with.
func TestChunkUnit_LogsRedacted(t *testing.T) {
	const secret = "gcs-unit-log-secret-do-not-print"
	_, _ = newFakeGCSServer(t, map[string]fakeBucket{
		"bkt": {objects: map[string]fakeObject{
			"config.txt": {content: "aws_secret = " + secret},
			"bad.txt":    {content: "more", readStatus: 500},
		}},
	})

	ctx, logs := logtest.SourceContext(true)
	conn := &sourcespb.GCS{
		IncludeBuckets: []string{"bkt"},
		Credential:     &sourcespb.GCS_Unauthenticated{},
	}
	anyConn, err := anypb.New(conn)
	require.NoError(t, err)
	s := &Source{}
	require.NoError(t, s.Init(ctx, "redaction test", 1, 1, false, anyConn, 2))

	reporter := sourcestest.SafeTestReporter{}
	_ = s.ChunkUnit(ctx, GCSObjectUnit{Bucket: "bkt"}, &reporter)

	logtest.CheckSourceLines(t, logs.All(), secret)
	for _, entry := range logs.All() {
		assert.NotContains(t, fmt.Sprint(entry.ContextMap()), secret)
	}
}

// A bucket with many objects is enumerated and scanned without reading every
// object name into memory first: the listing is consumed one page at a time and
// each object is scanned as it arrives. This checks the observable consequence:
// a scan that fails part way still reports the objects it got through.
func TestChunkUnit_StreamsLargeBucket(t *testing.T) {
	objects := make(map[string]fakeObject, 500)
	for i := 0; i < 500; i++ {
		objects[fmt.Sprintf("obj-%03d.txt", i)] = fakeObject{content: fmt.Sprintf("content-%d", i)}
	}
	fake, _ := newFakeGCSServer(t, map[string]fakeBucket{"big": {objects: objects}})
	s := newUnitTestSource(t, &sourcespb.GCS{IncludeBuckets: []string{"big"}})

	reporter := sourcestest.SafeTestReporter{}
	require.NoError(t, s.ChunkUnit(context.Background(), GCSObjectUnit{Bucket: "big"}, &reporter))
	assert.Len(t, reporter.Chunks, 500)

	got, ok := s.GetUnitProgressFor("big")
	require.True(t, ok)
	assert.Equal(t, sources.UnitProgressReady, got.State)
	assert.EqualValues(t, 500, got.ItemsTotal)
	assert.EqualValues(t, 500, got.ItemsDone)
	assert.Greater(t, fake.listCalls(), 0)
}

// A unit's progress is counted by the objects in the unit, not by the whole
// source's object count.
func TestChunkUnit_ProgressCountsUnitObjects(t *testing.T) {
	_, _ = newFakeGCSServer(t, map[string]fakeBucket{
		"bkt": {objects: map[string]fakeObject{
			"logs/a.txt": {content: "a"},
			"keys/b.txt": {content: "bb"},
		}},
	})
	s := newUnitTestSource(t, &sourcespb.GCS{
		IncludeBuckets: []string{"bkt"},
		UnitPrefixes:   []string{"logs/", "keys/"},
	})

	require.NoError(t, s.ChunkUnit(context.Background(), GCSObjectUnit{Bucket: "bkt", Prefix: "logs/"}, &sourcestest.SafeTestReporter{}))
	require.NoError(t, s.ChunkUnit(context.Background(), GCSObjectUnit{Bucket: "bkt", Prefix: "keys/"}, &sourcestest.SafeTestReporter{}))

	logs, ok := s.GetUnitProgressFor("bkt|logs/")
	require.True(t, ok)
	assert.EqualValues(t, 1, logs.ItemsTotal)
	assert.EqualValues(t, 1, logs.BytesTotal)

	keys, ok := s.GetUnitProgressFor("bkt|keys/")
	require.True(t, ok)
	assert.EqualValues(t, 1, keys.ItemsTotal)
	assert.EqualValues(t, 2, keys.BytesTotal)
}

// The persisted resume encoding keeps the shape other sources already use: a
// JSON object of unit ID to value, so an older encoding still reads.
func TestChunkUnit_ResumeEncodingStaysCompatible(t *testing.T) {
	_, _ = newFakeGCSServer(t, map[string]fakeBucket{
		"bkt": {objects: map[string]fakeObject{"a.txt": {content: "a"}}},
	})
	s := newUnitTestSource(t, &sourcespb.GCS{IncludeBuckets: []string{"bkt"}})

	// An encoding written by an older version, including a key for a unit this
	// run does not see, must not break the scan.
	s.EncodedResumeInfo = `{"other-unit":"legacy-value"}`

	require.NoError(t, s.ChunkUnit(context.Background(), GCSObjectUnit{Bucket: "bkt"}, &sourcestest.SafeTestReporter{}))

	// The legacy unit's entry survives, and the new encoding is still a JSON map.
	encoded := s.GetProgress().EncodedResumeInfo
	assert.True(t, strings.HasPrefix(encoded, "{"), "encoding stays a JSON map, got %q", encoded)
	var decoded map[string]string
	assert.NoError(t, json.Unmarshal([]byte(encoded), &decoded))
	assert.Contains(t, decoded, "other-unit")
}

// Without include buckets, enumeration lists the project's buckets and still
// reports a bucket as a unit even when listing its objects is later refused, so
// the bucket is covered by the scan and its failure is visible rather than the
// bucket silently disappearing.
func TestEnumerate_ProjectBucketsIncludeUnlistable(t *testing.T) {
	_, _ = newFakeGCSServer(t, map[string]fakeBucket{
		"readable": {objects: map[string]fakeObject{"a.txt": {content: "a"}}},
		"denied":   {listStatus: 403},
		"excluded": {},
	})
	s := newUnitTestSource(t, &sourcespb.GCS{
		ProjectId:      "test-project",
		ExcludeBuckets: []string{"excluded"},
		Credential:     &sourcespb.GCS_ApiKey{},
	})

	assert.Equal(t, []string{"denied", "readable"}, listedUnits(t, s))
}

// Enumeration must not depend on being able to list every object: a bucket whose
// objects cannot be listed is still a unit.
func TestEnumerate_DoesNotListObjects(t *testing.T) {
	fake, _ := newFakeGCSServer(t, map[string]fakeBucket{
		"bkt": {objects: map[string]fakeObject{"a.txt": {content: "a"}}},
	})
	s := newUnitTestSource(t, &sourcespb.GCS{IncludeBuckets: []string{"bkt"}})

	before := fake.objectListCalls()
	units := listedUnits(t, s)
	after := fake.objectListCalls()

	assert.Equal(t, []string{"bkt"}, units)
	assert.Equal(t, before, after, "enumeration must not list objects; the scan does")
}

// When an object with some content fails to read, its content is not recorded
// as scanned, so a rescan of the unit reads it again rather than skipping it.
// The unit is reported incomplete meanwhile.
func TestChunkUnit_FailedContentIsRetriedOnRescan(t *testing.T) {
	fake, _ := newFakeGCSServer(t, map[string]fakeBucket{
		"bkt": {objects: map[string]fakeObject{
			"a.txt": {content: "content-a"},
			"b.txt": {content: "content-b", readStatus: 500},
		}},
	})
	s := newUnitTestSource(t, &sourcespb.GCS{IncludeBuckets: []string{"bkt"}})

	unit := GCSObjectUnit{Bucket: "bkt"}
	err := s.ChunkUnit(context.Background(), unit, &sourcestest.SafeTestReporter{})
	require.Error(t, err, "one object failed, so the unit is incomplete")

	// Only the object that succeeded is remembered as scanned.
	unitID, _ := unit.SourceUnitID()
	resume := s.GetEncodedResumeInfoFor(unitID)
	assert.NotContains(t, resume, "content-b", "a failed read is not recorded as scanned")

	// Make the failing object readable and rescan: it is read this time.
	fake.setReadStatus("bkt", "b.txt", 0)
	reporter := &sourcestest.SafeTestReporter{}
	require.NoError(t, s.ChunkUnit(context.Background(), unit, reporter))
	assert.Equal(t, []string{"b.txt"}, chunkNames(reporter.Chunks),
		"the object that failed before is scanned on the rescan")
}

// Scanning every enumerated unit reports each object in exactly one unit, across
// buckets and prefixes, with no object reported twice.
func TestChunkUnit_EachObjectInOneUnit(t *testing.T) {
	_, _ = newFakeGCSServer(t, map[string]fakeBucket{
		"one": {objects: map[string]fakeObject{
			"logs/a.txt":   {content: "1a"},
			"logs/b.txt":   {content: "1b"},
			"secret/c.txt": {content: "1c"},
		}},
		"two": {objects: map[string]fakeObject{
			"logs/d.txt": {content: "2d"},
			"other.txt":  {content: "2e"},
		}},
	})
	s := newUnitTestSource(t, &sourcespb.GCS{
		IncludeBuckets: []string{"one", "two"},
		UnitPrefixes:   []string{"logs/", "secret/"},
	})

	reporter := &unitCollector{}
	require.NoError(t, s.Enumerate(context.Background(), reporter))

	// The "other.txt" object is under neither prefix, so it is in no unit.
	seen := map[string]int{}
	for _, unit := range reporter.units {
		chunkReporter := &sourcestest.SafeTestReporter{}
		require.NoError(t, s.ChunkUnit(context.Background(), unit, chunkReporter))
		for _, name := range chunkNames(chunkReporter.Chunks) {
			seen[name]++
		}
	}

	for name, count := range seen {
		assert.Equal(t, 1, count, "object %q was reported by %d units", name, count)
	}
	assert.Equal(t, map[string]int{
		"logs/a.txt":   1,
		"logs/b.txt":   1,
		"secret/c.txt": 1,
		"logs/d.txt":   1,
	}, seen)
}

// A resume encoding from the legacy scan is a bare comma-separated list of
// content hashes, not the JSON map the unit path uses. Reading it must not error;
// the unit just starts without per-unit resume state.
func TestChunkUnit_LegacyResumeEncodingDoesNotError(t *testing.T) {
	_, _ = newFakeGCSServer(t, map[string]fakeBucket{
		"bkt": {objects: map[string]fakeObject{"a.txt": {content: "a"}}},
	})
	s := newUnitTestSource(t, &sourcespb.GCS{IncludeBuckets: []string{"bkt"}})

	// The shape an older GCS build persisted: a flat CSV of md5 hashes.
	s.EncodedResumeInfo = "d41d8cd98f00b204e9800998ecf8427e,0cc175b9c0f1b6a831c399e269772661"

	reporter := &sourcestest.SafeTestReporter{}
	require.NoError(t, s.ChunkUnit(context.Background(), GCSObjectUnit{Bucket: "bkt"}, reporter))
	assert.Len(t, reporter.Chunks, 1, "the legacy value is ignored, so the object is scanned")
}
