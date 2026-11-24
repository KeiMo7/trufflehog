package gcs

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sourcestest"
)

func TestCanonicalUnitPrefixes(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{name: "empty", input: nil, want: nil},
		{name: "sorts", input: []string{"b/", "a/"}, want: []string{"a/", "b/"}},
		{name: "deduplicates", input: []string{"a/", "a/"}, want: []string{"a/"}},
		{name: "trims blanks", input: []string{"  a/  ", "", "   "}, want: []string{"a/"}},
		{name: "drops nested", input: []string{"src/", "src/vendor/"}, want: []string{"src/"}},
		{name: "keeps siblings that share a stem", input: []string{"src/", "tests/"}, want: []string{"src/", "tests/"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, canonicalUnitPrefixes(tt.input))
		})
	}
}

func TestValidateUnitPrefixes(t *testing.T) {
	assert.NoError(t, validateUnitPrefixes(nil))
	assert.NoError(t, validateUnitPrefixes([]string{"a/"}))
	assert.Error(t, validateUnitPrefixes([]string{"", "a/"}))
}

func TestGCSObjectUnitID(t *testing.T) {
	tests := []struct {
		name        string
		unit        GCSObjectUnit
		wantID      string
		wantKind    sources.SourceUnitKind
		wantDisplay string
	}{
		{
			name:        "bucket unit",
			unit:        GCSObjectUnit{Bucket: "b"},
			wantID:      "b",
			wantKind:    SourceUnitKindBucket,
			wantDisplay: "b",
		},
		{
			name:        "prefix unit",
			unit:        GCSObjectUnit{Bucket: "b", Prefix: "logs/"},
			wantID:      "b|logs/",
			wantKind:    SourceUnitKindPrefix,
			wantDisplay: "Bucket=b Prefix=logs/",
		},
		{
			name:        "special characters survive",
			unit:        GCSObjectUnit{Bucket: "b", Prefix: "dir/中文 %/"},
			wantID:      "b|dir/中文 %/",
			wantKind:    SourceUnitKindPrefix,
			wantDisplay: "Bucket=b Prefix=dir/中文 %/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, kind := tt.unit.SourceUnitID()
			assert.Equal(t, tt.wantID, id)
			assert.Equal(t, tt.wantKind, kind)
			assert.Equal(t, tt.wantDisplay, tt.unit.Display())
		})
	}
}

func TestUnmarshalGCSUnit(t *testing.T) {
	s := &Source{}

	t.Run("bare unit", func(t *testing.T) {
		unit, err := s.UnmarshalSourceUnit([]byte(`{"bucket":"b","prefix":"logs/"}`))
		require.NoError(t, err)
		assert.Equal(t, GCSObjectUnit{Bucket: "b", Prefix: "logs/"}, unit)
	})

	t.Run("envelope rebuilt from prefix id", func(t *testing.T) {
		unit, err := s.UnmarshalSourceUnit([]byte(`{"id":"b|logs/","kind":"prefix"}`))
		require.NoError(t, err)
		assert.Equal(t, GCSObjectUnit{Bucket: "b", Prefix: "logs/"}, unit)
	})

	t.Run("envelope rebuilt from bucket id", func(t *testing.T) {
		unit, err := s.UnmarshalSourceUnit([]byte(`{"id":"b","kind":"bucket"}`))
		require.NoError(t, err)
		assert.Equal(t, GCSObjectUnit{Bucket: "b"}, unit)
	})

	t.Run("envelope with unit data round-trips", func(t *testing.T) {
		// {"bucket":"b","prefix":"p/"} base64-encoded.
		data := []byte(`{"id":"b|p/","kind":"prefix","unit_data":"eyJidWNrZXQiOiJiIiwicHJlZml4IjoicC8ifQ=="}`)
		unit, err := s.UnmarshalSourceUnit(data)
		require.NoError(t, err)
		assert.Equal(t, GCSObjectUnit{Bucket: "b", Prefix: "p/"}, unit)
	})

	t.Run("missing bucket is rejected", func(t *testing.T) {
		_, err := s.UnmarshalSourceUnit([]byte(`{"prefix":"p/"}`))
		assert.Error(t, err)
	})

	t.Run("unit from another source is rejected, not misread", func(t *testing.T) {
		_, err := s.UnmarshalSourceUnit([]byte(`{"kind":"repo","id":"some-repo"}`))
		assert.Error(t, err)
	})
}

// A source with no unit prefixes reports one unit per bucket, so a whole bucket
// is independently scannable.
func TestEnumerate_BucketUnits(t *testing.T) {
	_, _ = newFakeGCSServer(t, map[string]fakeBucket{
		"alpha": {objects: map[string]fakeObject{"x": {content: "x"}}},
		"beta":  {objects: nil},
	})
	s := newUnitTestSource(t, &sourcespb.GCS{IncludeBuckets: []string{"alpha", "beta", "missing"}})

	assert.Equal(t, []string{"alpha", "beta", "missing"}, listedUnits(t, s))
}

// With unit prefixes configured, each bucket yields one unit per prefix, and two
// runs of the same config yield the same set.
func TestEnumerate_PrefixUnitsAreStable(t *testing.T) {
	_, _ = newFakeGCSServer(t, map[string]fakeBucket{
		"alpha": {objects: map[string]fakeObject{"logs/a": {content: "a"}}},
	})
	conn := &sourcespb.GCS{
		IncludeBuckets: []string{"alpha"},
		UnitPrefixes:   []string{"logs/", "secrets/", "logs/"},
	}

	first := listedUnits(t, newUnitTestSource(t, conn))
	second := listedUnits(t, newUnitTestSource(t, conn))

	assert.Equal(t, []string{"alpha|logs/", "alpha|secrets/"}, first)
	assert.Equal(t, first, second, "the same config must enumerate the same units")
}

// An empty bucket still yields a unit, so a bucket with no objects is covered
// rather than silently skipped.
func TestEnumerate_EmptyBucketStillHasUnit(t *testing.T) {
	_, _ = newFakeGCSServer(t, map[string]fakeBucket{"empty": {}})
	s := newUnitTestSource(t, &sourcespb.GCS{IncludeBuckets: []string{"empty"}})

	assert.Equal(t, []string{"empty"}, listedUnits(t, s))
}

// Buckets with only zero-byte objects still yield a unit, and scanning it
// completes without producing a fake object.
func TestChunkUnit_ZeroByteBucketCompletes(t *testing.T) {
	_, _ = newFakeGCSServer(t, map[string]fakeBucket{
		"zero": {objects: map[string]fakeObject{
			"a.txt":  {content: "", size: 0},
			"b.json": {content: "", size: 0},
		}},
	})
	s := newUnitTestSource(t, &sourcespb.GCS{IncludeBuckets: []string{"zero"}})

	reporter := sourcestest.SafeTestReporter{}
	err := s.ChunkUnit(context.Background(), GCSObjectUnit{Bucket: "zero"}, &reporter)
	require.NoError(t, err)
	assert.Empty(t, reporter.ChunkErrs)
	assert.Empty(t, reporter.Chunks, "a zero-byte object produces no chunk")
}

// Non-overlapping prefixes never put the same object in two units.
func TestChunkUnit_PrefixesDoNotOverlap(t *testing.T) {
	_, _ = newFakeGCSServer(t, map[string]fakeBucket{
		"bkt": {objects: map[string]fakeObject{
			"logs/a.txt": {content: "a"},
			"logs/b.txt": {content: "b"},
			"keys/c.txt": {content: "c"},
			"root.txt":   {content: "r"},
		}},
	})
	s := newUnitTestSource(t, &sourcespb.GCS{
		IncludeBuckets: []string{"bkt"},
		UnitPrefixes:   []string{"logs/", "keys/"},
	})

	seen := map[string][]string{}
	for _, prefix := range []string{"logs/", "keys/"} {
		reporter := sourcestest.SafeTestReporter{}
		require.NoError(t, s.ChunkUnit(context.Background(), GCSObjectUnit{Bucket: "bkt", Prefix: prefix}, &reporter))
		for _, chunk := range reporter.Chunks {
			name := chunk.SourceMetadata.GetGcs().GetFilename()
			seen[name] = append(seen[name], prefix)
		}
	}

	for name, prefixes := range seen {
		assert.Len(t, prefixes, 1, "object %q appeared in units %v", name, prefixes)
	}
	assert.Equal(t, map[string][]string{
		"logs/a.txt": {"logs/"},
		"logs/b.txt": {"logs/"},
		"keys/c.txt": {"keys/"},
	}, seen, "root.txt is outside every configured prefix")
}

// Objects an exclude rule removes belong to no unit and are missing from both
// the chunks and the unit's stats.
func TestChunkUnit_ExcludedObjectsOutOfUnit(t *testing.T) {
	_, _ = newFakeGCSServer(t, map[string]fakeBucket{
		"bkt": {objects: map[string]fakeObject{
			"keep/a.txt": {content: "a"},
			"skip/b.txt": {content: "b"},
		}},
	})
	s := newUnitTestSource(t, &sourcespb.GCS{
		IncludeBuckets: []string{"bkt"},
		ExcludeObjects: []string{"skip/*"},
	})

	reporter := sourcestest.SafeTestReporter{}
	require.NoError(t, s.ChunkUnit(context.Background(), GCSObjectUnit{Bucket: "bkt"}, &reporter))

	names := chunkNames(reporter.Chunks)
	assert.Equal(t, []string{"keep/a.txt"}, names)

	got, ok := s.GetUnitProgressFor("bkt")
	require.True(t, ok)
	assert.EqualValues(t, 1, got.ItemsTotal, "the excluded object is not in the unit total")
	assert.EqualValues(t, 1, got.ItemsDone)
}

// Two objects with identical content count once inside a unit.
func TestChunkUnit_DeduplicatesWithinUnit(t *testing.T) {
	_, _ = newFakeGCSServer(t, map[string]fakeBucket{
		"bkt": {objects: map[string]fakeObject{
			"a.txt": {content: "same"},
			"b.txt": {content: "same"},
			"c.txt": {content: "different"},
		}},
	})
	s := newUnitTestSource(t, &sourcespb.GCS{IncludeBuckets: []string{"bkt"}})

	reporter := sourcestest.SafeTestReporter{}
	require.NoError(t, s.ChunkUnit(context.Background(), GCSObjectUnit{Bucket: "bkt"}, &reporter))
	assert.Len(t, reporter.Chunks, 2, "the duplicate content is reported once")
}

// Object names with spaces, non-ASCII text, slashes and percent signs round-trip
// through the listing, the download and the chunk metadata.
func TestChunkUnit_SpecialCharacterNames(t *testing.T) {
	names := []string{
		"space name.txt",
		"中文/文件.txt",
		"nested/dir/file.txt",
		"percent%25name.txt",
		"plus+and&amp.txt",
	}
	objects := make(map[string]fakeObject, len(names))
	for _, name := range names {
		objects[name] = fakeObject{content: "content of " + name}
	}
	_, _ = newFakeGCSServer(t, map[string]fakeBucket{"bkt": {objects: objects}})
	s := newUnitTestSource(t, &sourcespb.GCS{IncludeBuckets: []string{"bkt"}})

	reporter := sourcestest.SafeTestReporter{}
	require.NoError(t, s.ChunkUnit(context.Background(), GCSObjectUnit{Bucket: "bkt"}, &reporter))

	assert.ElementsMatch(t, names, chunkNames(reporter.Chunks))
}

// A listing failure for one bucket fails only that unit; the other units still
// complete and are counted.
func TestChunkUnit_ListFailureIsolatedToUnit(t *testing.T) {
	_, _ = newFakeGCSServer(t, map[string]fakeBucket{
		"denied": {listStatus: 403},
		"ok":     {objects: map[string]fakeObject{"a.txt": {content: "a"}}},
	})
	s := newUnitTestSource(t, &sourcespb.GCS{IncludeBuckets: []string{"denied", "ok"}})

	deniedReporter := sourcestest.SafeTestReporter{}
	err := s.ChunkUnit(context.Background(), GCSObjectUnit{Bucket: "denied"}, &deniedReporter)
	require.Error(t, err, "the failing unit reports its failure")
	assert.True(t, sources.IsUnitIncomplete(err), "the failed unit is marked incomplete")

	okReporter := sourcestest.SafeTestReporter{}
	require.NoError(t, s.ChunkUnit(context.Background(), GCSObjectUnit{Bucket: "ok"}, &okReporter))
	assert.Len(t, okReporter.Chunks, 1, "the healthy unit is unaffected")
}

// A missing bucket is a configuration failure reported against its own unit.
func TestChunkUnit_MissingBucketIsConfigError(t *testing.T) {
	_, _ = newFakeGCSServer(t, map[string]fakeBucket{})
	s := newUnitTestSource(t, &sourcespb.GCS{IncludeBuckets: []string{"nope"}})

	reporter := sourcestest.SafeTestReporter{}
	err := s.ChunkUnit(context.Background(), GCSObjectUnit{Bucket: "nope"}, &reporter)
	require.Error(t, err)
	require.NotEmpty(t, reporter.ChunkErrs)

	kind, ok := unitErrorKind(reporter.ChunkErrs[0])
	require.True(t, ok)
	assert.Equal(t, UnitErrorConfig, kind)
}

// A read failure for one object marks the unit incomplete, so it is not counted
// as done, while the rest of its objects still finish.
func TestChunkUnit_ObjectReadFailureMarksUnitIncomplete(t *testing.T) {
	_, _ = newFakeGCSServer(t, map[string]fakeBucket{
		"bkt": {objects: map[string]fakeObject{
			"good.txt": {content: "good"},
			"bad.txt":  {content: "bad", readStatus: 500},
		}},
	})
	s := newUnitTestSource(t, &sourcespb.GCS{IncludeBuckets: []string{"bkt"}})

	reporter := sourcestest.SafeTestReporter{}
	err := s.ChunkUnit(context.Background(), GCSObjectUnit{Bucket: "bkt"}, &reporter)
	require.Error(t, err)
	assert.True(t, sources.IsUnitIncomplete(err))
	assert.Equal(t, []string{"good.txt"}, chunkNames(reporter.Chunks), "the other object still finishes")
}

// A rescan of a unit covers only that unit's scope, and skips content it already
// scanned.
func TestChunkUnit_RescanOnlyCoversItsScope(t *testing.T) {
	_, _ = newFakeGCSServer(t, map[string]fakeBucket{
		"bkt": {objects: map[string]fakeObject{
			"logs/a.txt": {content: "a"},
			"keys/b.txt": {content: "b"},
		}},
	})
	s := newUnitTestSource(t, &sourcespb.GCS{
		IncludeBuckets: []string{"bkt"},
		UnitPrefixes:   []string{"logs/", "keys/"},
	})

	logs := GCSObjectUnit{Bucket: "bkt", Prefix: "logs/"}
	reporter := sourcestest.SafeTestReporter{}
	require.NoError(t, s.ChunkUnit(context.Background(), logs, &reporter))
	assert.Equal(t, []string{"logs/a.txt"}, chunkNames(reporter.Chunks))

	// The unit's content is remembered, so rescanning it reads nothing new.
	unitID, _ := logs.SourceUnitID()
	assert.NotEmpty(t, s.GetEncodedResumeInfoFor(unitID))

	again := sourcestest.SafeTestReporter{}
	require.NoError(t, s.ChunkUnit(context.Background(), logs, &again))
	assert.Empty(t, again.Chunks, "content already scanned in this unit is skipped")
}

func chunkNames(chunks []sources.Chunk) []string {
	names := make([]string, 0, len(chunks))
	for _, chunk := range chunks {
		names = append(names, chunk.SourceMetadata.GetGcs().GetFilename())
	}
	return names
}

var _ = strings.TrimSpace
var _ = assert.ObjectsAreEqual
