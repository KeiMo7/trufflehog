package engine

import (
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/custom_detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// recordedResult stores just the fields these tests assert on.
type recordedResult struct {
	detectorName string
	detectorType string
}

// recordingPrinter records every dispatched result. It is safe for concurrent
// use because notifier workers dispatch concurrently.
type recordingPrinter struct {
	mu      sync.Mutex
	results []recordedResult
}

func (p *recordingPrinter) Print(_ context.Context, r *detectors.ResultWithMetadata) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.results = append(p.results, recordedResult{
		detectorName: r.DetectorName,
		detectorType: r.DetectorType.String(),
	})
	return nil
}

func (p *recordingPrinter) snapshot() []recordedResult {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]recordedResult(nil), p.results...)
}

// runCustomDetectorScan scans a temporary file containing data with the given
// custom detectors and returns the dispatched results.
func runCustomDetectorScan(
	t *testing.T,
	data string,
	allDetectors []detectors.Detector,
	registry *custom_detectors.Registry,
) []recordedResult {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "input.txt")
	require.NoError(t, os.WriteFile(path, []byte(data), 0o600))

	sourceManager := sources.NewManager(sources.WithSourceUnits(), sources.WithBufferedOutput(64))
	printer := new(recordingPrinter)

	conf := Config{
		Concurrency:            1,
		Decoders:               decoders.DefaultDecoders(),
		Detectors:              allDetectors,
		Verify:                 false,
		SourceManager:          sourceManager,
		Dispatcher:             NewPrinterDispatcher(printer),
		VerificationOverlap:    true,
		CustomDetectorRegistry: registry,
	}

	e, err := NewEngine(context.Background(), &conf)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	e.Start(ctx)

	_, err = e.ScanFileSystem(ctx, sources.FilesystemConfig{Paths: []string{path}})
	require.NoError(t, err)
	require.NoError(t, e.Finish(ctx))

	return printer.snapshot()
}

func detectorNames(results []recordedResult) []string {
	names := make([]string, 0, len(results))
	for _, result := range results {
		names = append(names, result.detectorName)
	}
	sort.Strings(names)
	return names
}

func mustCustomDetectors(t *testing.T, pbs ...*custom_detectorspb.CustomRegex) []detectors.Detector {
	t.Helper()
	registry, err := custom_detectors.NewRegistry(pbs, custom_detectors.Policy{})
	require.NoError(t, err)
	out := make([]detectors.Detector, 0, len(pbs))
	for _, detector := range registry.Detectors() {
		out = append(out, detector)
	}
	return out
}

func customPB(name string, priority int32, keyword, pattern string) *custom_detectorspb.CustomRegex {
	return &custom_detectorspb.CustomRegex{
		Name:     name,
		Priority: priority,
		Keywords: []string{keyword},
		Regex:    map[string]string{"main": pattern},
	}
}

// Requirement 5.1: two detectors hitting the same text, opposite priorities.
// The order in which the engine runs them must follow the configured
// priority, while the set of results is unchanged.
func TestEngine_CustomDetectorPriorityChangesOrderNotSet(t *testing.T) {
	shared := "teamtoken"

	run := func(t *testing.T, alphaPriority, betaPriority int32) ([]string, []string) {
		alpha := customPB("alpha", alphaPriority, shared, `teamtoken`)
		beta := customPB("beta", betaPriority, shared, `teamtoken`)
		all := mustCustomDetectors(t, alpha, beta)

		results := runCustomDetectorScan(t, "prelude "+shared+" epilogue", all, nil)
		require.ElementsMatch(t, []string{"alpha", "beta"}, detectorNames(results))

		// The deterministic execution path returns conclusions in declared
		// order, so the test can assert on it without depending on workers.
		registry, err := custom_detectors.NewRegistry(
			[]*custom_detectorspb.CustomRegex{alpha, beta}, custom_detectors.Policy{})
		require.NoError(t, err)
		outcomes := registry.Evaluate(t.Context(), registry.Detectors(), []byte(shared), false)
		require.Len(t, outcomes, 2)
		var order []string
		for _, outcome := range outcomes {
			require.NoError(t, outcome.Err)
			require.NotEmpty(t, outcome.Results, "%s should produce a conclusion", outcome.DetectorName)
			order = append(order, outcome.DetectorName)
		}
		return order, detectorNames(results)
	}

	order, resultSet := run(t, 20, 10)
	assert.Equal(t, []string{"alpha", "beta"}, order)

	oppositeOrder, oppositeSet := run(t, 10, 20)
	assert.Equal(t, []string{"beta", "alpha"}, oppositeOrder)
	assert.Equal(t, resultSet, oppositeSet, "changing priority must not change the conclusion set")
}

// Requirement 5.2: an excluded detector neither runs nor produces a result,
// and its keyword is absent from the prefilter.
func TestEngine_CustomDetectorExclusion(t *testing.T) {
	alpha := customPB("alpha", 10, "alphakey", `alphakey`)
	beta := customPB("beta", 5, "betakey", `betakey`)

	registry, err := custom_detectors.NewRegistry(
		[]*custom_detectorspb.CustomRegex{alpha, beta},
		custom_detectors.Policy{Exclude: []string{"beta"}},
	)
	require.NoError(t, err)

	betaDetector, ok := registry.Lookup("beta")
	require.True(t, ok)

	enabled := make([]detectors.Detector, 0, 1)
	for _, detector := range registry.Detectors() {
		enabled = append(enabled, detector)
	}
	require.Len(t, enabled, 1)

	results := runCustomDetectorScan(t, "prelude alphakey betakey epilogue", enabled, registry)
	assert.Equal(t, []string{"alpha"}, detectorNames(results), "the excluded detector must not produce a result")
	// An excluded detector is not executed at all, even though its keyword is
	// present in the scanned text.
	assert.Zero(t, betaDetector.ExecutionCount(), "an excluded detector must not be executed")
	assert.NotZero(t, enabled[0].(*custom_detectors.CustomRegexWebhook).ExecutionCount())

	// Its keyword must not be in the filesystem prefilter either.
	core := ahocorasick.NewAhoCorasickCore(enabled)
	keywords := core.KeywordsForSource(sourcespb.SourceType_SOURCE_TYPE_FILESYSTEM)
	assert.Contains(t, keywords, "alphakey")
	assert.NotContains(t, keywords, "betakey", "an excluded detector is a ghost entry in the prefilter")
}

// Short-circuiting is opt-in: with it on, only the highest-priority matching
// custom detector runs; with it off both run.
func TestEngine_CustomDetectorShortCircuit(t *testing.T) {
	const shared = "teamtoken"
	build := func(t *testing.T, shortCircuit bool) ([]detectors.Detector, *custom_detectors.Registry, *custom_detectors.CustomRegexWebhook) {
		high := customPB("high", 20, shared, `teamtoken`)
		low := customPB("low", 1, shared, `teamtoken`)
		registry, err := custom_detectors.NewRegistry(
			[]*custom_detectorspb.CustomRegex{high, low},
			custom_detectors.Policy{ShortCircuit: shortCircuit},
		)
		require.NoError(t, err)
		lowDetector, ok := registry.Lookup("low")
		require.True(t, ok)
		enabled := make([]detectors.Detector, 0, 2)
		for _, detector := range registry.Detectors() {
			enabled = append(enabled, detector)
		}
		return enabled, registry, lowDetector
	}

	t.Run("short circuit on", func(t *testing.T) {
		enabled, registry, low := build(t, true)
		results := runCustomDetectorScan(t, "prelude teamtoken epilogue", enabled, registry)
		assert.Equal(t, []string{"high"}, detectorNames(results))
		assert.Zero(t, low.ExecutionCount(), "the lower-priority detector must be skipped")
	})

	t.Run("short circuit off", func(t *testing.T) {
		enabled, registry, low := build(t, false)
		results := runCustomDetectorScan(t, "prelude teamtoken epilogue", enabled, registry)
		assert.ElementsMatch(t, []string{"high", "low"}, detectorNames(results))
		assert.NotZero(t, low.ExecutionCount())
	})
}

// Every detector excluded is allowed: the scan produces no custom detector
// results rather than failing, and the condition is queryable so it is not
// mistaken for a clean scan.
func TestEngine_AllCustomDetectorsExcluded(t *testing.T) {
	alpha := customPB("alpha", 10, "alphakey", `alphakey`)
	registry, err := custom_detectors.NewRegistry(
		[]*custom_detectorspb.CustomRegex{alpha},
		custom_detectors.Policy{Exclude: []string{"alpha"}},
	)
	require.NoError(t, err)
	require.True(t, registry.AllExcluded())
	require.ErrorIs(t, registry.EmptySelectionError(), custom_detectors.ErrNoEnabledDetectors)

	results := runCustomDetectorScan(t, "prelude alphakey epilogue", nil, registry)
	assert.Empty(t, results)
}

// A scoped detector does not take part in prefiltering for other source
// types, even when its keyword is present.
func TestEngine_CustomDetectorSourceScope(t *testing.T) {
	repo := customPB("repo-only", 10, "repokey", `repokey`)
	repo.SourceTypes = []string{"repository"}
	files := customPB("files", 5, "repokey", `repokey`)

	all := mustCustomDetectors(t, repo, files)
	core := ahocorasick.NewAhoCorasickCore(all)

	gitMatches := core.FindDetectorMatchesForSource([]byte("repokey"), sourcespb.SourceType_SOURCE_TYPE_GIT)
	require.Len(t, gitMatches, 2)
	assert.Equal(t, "repo-only", gitMatches[0].Detector.(*custom_detectors.CustomRegexWebhook).GetName())

	fsMatches := core.FindDetectorMatchesForSource([]byte("repokey"), sourcespb.SourceType_SOURCE_TYPE_FILESYSTEM)
	require.Len(t, fsMatches, 1)
	assert.Equal(t, "files", fsMatches[0].Detector.(*custom_detectors.CustomRegexWebhook).GetName())

	// A keyword only the scoped detector declares must not be a ghost entry
	// in the filesystem view, while a shared keyword stays because the
	// unscoped detector legitimately declares it.
	repoOnlyKeyword := customPB("repo-only-2", 0, "onlyinrepo", `onlyinrepo`)
	repoOnlyKeyword.SourceTypes = []string{"repository"}
	core = ahocorasick.NewAhoCorasickCore([]detectors.Detector{mustCustomDetector(t, repoOnlyKeyword)})
	assert.NotContains(t, core.KeywordsForSource(sourcespb.SourceType_SOURCE_TYPE_FILESYSTEM), "onlyinrepo")
	assert.Contains(t, core.KeywordsForSource(sourcespb.SourceType_SOURCE_TYPE_GIT), "onlyinrepo")
}

func mustCustomDetector(t *testing.T, pb *custom_detectorspb.CustomRegex) detectors.Detector {
	t.Helper()
	registry, err := custom_detectors.NewRegistry([]*custom_detectorspb.CustomRegex{pb}, custom_detectors.Policy{})
	require.NoError(t, err)
	require.Len(t, registry.Detectors(), 1)
	return registry.Detectors()[0]
}
