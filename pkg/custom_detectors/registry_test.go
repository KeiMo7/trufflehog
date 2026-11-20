package custom_detectors

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
)

// countingRegexDetector is used by engine tests to observe executions; it is
// defined here so the test helpers share one definition.

func testDetector(t *testing.T, name string, priority int32, mutate ...func(*custom_detectorspb.CustomRegex)) *CustomRegexWebhook {
	t.Helper()
	pb := &custom_detectorspb.CustomRegex{
		Name:     name,
		Priority: priority,
		Keywords: []string{"shared"},
		Regex:    map[string]string{"main": `\w+`},
	}
	for _, fn := range mutate {
		fn(pb)
	}
	detector, err := NewWebhookCustomRegex(pb)
	require.NoError(t, err)
	return detector
}

func namesOf(detectors []*CustomRegexWebhook) []string {
	names := make([]string, 0, len(detectors))
	for _, detector := range detectors {
		names = append(names, detector.GetName())
	}
	return names
}

func pbDetectors(detectors ...*CustomRegexWebhook) []*custom_detectorspb.CustomRegex {
	out := make([]*custom_detectorspb.CustomRegex, 0, len(detectors))
	for _, detector := range detectors {
		out = append(out, detector.CustomRegex)
	}
	return out
}

// Requirement 1/2/10: both detectors matching the same text get a chance, and
// their order follows the declared priority, not any implicit type ordering.
func TestRegistry_PriorityOrdersDetectorsButKeepsEveryConclusion(t *testing.T) {
	alpha := testDetector(t, "alpha", 10)
	beta := testDetector(t, "beta", 20)

	registry, err := NewRegistry(pbDetectors(alpha, beta), Policy{})
	require.NoError(t, err)

	require.Equal(t, []string{"beta", "alpha"}, namesOf(registry.Detectors()),
		"higher priority must come first")
	plan := registry.PlanForMatches([]*CustomRegexWebhook{alpha, beta})
	require.Equal(t, []string{"beta", "alpha"}, namesOf(plan.Ordered))
	require.Empty(t, plan.Skipped, "without short-circuiting both detectors run")

	// Flipping the priorities flips the order but not the set.
	alpha.CustomRegex.Priority = 30
	flipped, err := NewRegistry(pbDetectors(alpha, beta), Policy{})
	require.NoError(t, err)
	require.Equal(t, []string{"alpha", "beta"}, namesOf(flipped.Detectors()))
	assert.ElementsMatch(t, namesOf(registry.Detectors()), namesOf(flipped.Detectors()),
		"changing priority must not change which detectors run")
}

// Requirement 9: equal priorities fall back to a stable rule (name), and two
// runs produce the same order.
func TestRegistry_EqualPriorityIsStableAndDeterministic(t *testing.T) {
	detectors := []*custom_detectorspb.CustomRegex{
		{Name: "zeta", Keywords: []string{"z"}, Regex: map[string]string{"main": `.`}},
		{Name: "alpha", Keywords: []string{"a"}, Regex: map[string]string{"main": `.`}},
		{Name: "mike", Keywords: []string{"m"}, Regex: map[string]string{"main": `.`}},
	}
	var first []string
	for i := 0; i < 50; i++ {
		registry, err := NewRegistry(detectors, Policy{})
		require.NoError(t, err)
		got := namesOf(registry.Detectors())
		if i == 0 {
			first = got
			require.Equal(t, []string{"alpha", "mike", "zeta"}, got)
			continue
		}
		require.Equal(t, first, got, "run %d returned a different order", i)
	}
}

// Registration validation: empty keyword, duplicate keyword, duplicate name,
// and invalid regex are all rejected, and every problem names its detector.
func TestRegistry_RejectsInvalidRegistrations(t *testing.T) {
	valid := func(name string) *custom_detectorspb.CustomRegex {
		return &custom_detectorspb.CustomRegex{
			Name:     name,
			Keywords: []string{"kw"},
			Regex:    map[string]string{"main": `\w+`},
		}
	}
	badKeyword := valid("bad-keyword")
	badKeyword.Keywords = nil
	emptyKeyword := valid("empty-keyword")
	emptyKeyword.Keywords = []string{""}
	duplicateKeyword := valid("duplicate-keyword")
	duplicateKeyword.Keywords = []string{"Hog", "hog"}
	badRegex := valid("bad-regex")
	badRegex.Regex = map[string]string{"main": "("}

	_, err := NewRegistry([]*custom_detectorspb.CustomRegex{
		valid("ok"),
		valid("ok"),
		badKeyword,
		emptyKeyword,
		duplicateKeyword,
		badRegex,
	}, Policy{})
	require.Error(t, err)

	var registrationErr *RegistrationError
	require.ErrorAs(t, err, &registrationErr)
	require.Len(t, registrationErr.Problems, 5, "every problem should be reported at once:\n%s", err)

	byName := make(map[string][]string)
	for _, problem := range registrationErr.Problems {
		byName[problem.Name] = append(byName[problem.Name], problem.Reason)
	}
	for _, name := range []string{"ok", "bad-keyword", "empty-keyword", "duplicate-keyword", "bad-regex"} {
		require.NotEmpty(t, byName[name], "error must name detector %q", name)
	}
	assert.Contains(t, err.Error(), `detector "ok" (index 1)`, "duplicate names must be reported against the later entry")
	assert.Contains(t, err.Error(), "no keywords")
	assert.Contains(t, err.Error(), "empty keyword")
	assert.Contains(t, err.Error(), `duplicate keyword "hog"`)
	assert.Contains(t, err.Error(), "regex 'main':")
}

// Requirement 2/6 of the failure section: a priority rule that names a
// detector that is not registered fails startup and lists the unknown name.
func TestRegistry_RejectsPolicyReferencingUnknownDetector(t *testing.T) {
	alpha := testDetector(t, "alpha", 0)
	_, err := NewRegistry(pbDetectors(alpha), Policy{
		Precedence: []Precedence{{Before: "alpha", After: "typo"}},
		Exclude:    []string{"ghost"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"typo"`)
	assert.Contains(t, err.Error(), `"ghost"`)
	assert.Contains(t, err.Error(), "unknown detector")
	assert.Contains(t, err.Error(), "not registered")
}

// Requirement 4 in the failure section: a precedence cycle is refused and the
// conflicting pair is named.
func TestRegistry_RejectsPrecedenceCycle(t *testing.T) {
	alpha := testDetector(t, "alpha", 0)
	beta := testDetector(t, "beta", 0)
	gamma := testDetector(t, "gamma", 0)

	_, err := NewRegistry(pbDetectors(alpha, beta, gamma), Policy{
		Precedence: []Precedence{
			{Before: "alpha", After: "beta"},
			{Before: "beta", After: "gamma"},
			{Before: "gamma", After: "alpha"},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "precedence cycle")
	assert.Contains(t, err.Error(), "between")
	// The reported pair is a real edge of the cycle.
	assert.Regexp(t, `between "(alpha|beta|gamma)" and "(alpha|beta|gamma)"`, err.Error())
}

// Requirement 3 of the failure section / 5 in the required shapes: exclusion
// is hard. An excluded detector's keywords never enter the prefilter.
func TestRegistry_ExclusionRemovesKeywordsFromPrefilter(t *testing.T) {
	kept := testDetector(t, "kept", 0, func(pb *custom_detectorspb.CustomRegex) {
		pb.Keywords = []string{"keepme"}
	})
	dropped := testDetector(t, "dropped", 0, func(pb *custom_detectorspb.CustomRegex) {
		pb.Keywords = []string{"dropme"}
	})

	registry, err := NewRegistry(pbDetectors(kept, dropped), Policy{Exclude: []string{"dropped"}})
	require.NoError(t, err)

	assert.Equal(t, []string{"keepme"}, registry.Keywords())
	assert.Equal(t, []string{"keepme"}, registry.KeywordsForSource(sourcespb.SourceType_SOURCE_TYPE_GIT))
	assert.False(t, registry.Enabled("dropped"))
	assert.Equal(t, []string{"dropped"}, registry.Excluded())
}

// Requirement: disabled is the per-detector spelling of exclude.
func TestRegistry_DisabledDetectorIsExcluded(t *testing.T) {
	disabled := testDetector(t, "disabled", 100, func(pb *custom_detectorspb.CustomRegex) {
		pb.Disabled = true
		pb.Keywords = []string{"ghostkey"}
	})
	kept := testDetector(t, "kept", 0, func(pb *custom_detectorspb.CustomRegex) {
		pb.Keywords = []string{"livekey"}
	})

	registry, err := NewRegistry(pbDetectors(disabled, kept), Policy{})
	require.NoError(t, err)
	assert.Equal(t, []string{"livekey"}, registry.Keywords())
	assert.False(t, registry.Enabled("disabled"))
}

// Requirement 5 of the required shapes: scope is per source type.
func TestRegistry_SourceScopeLimitsPrefilter(t *testing.T) {
	repoOnly := testDetector(t, "repo-only", 0, func(pb *custom_detectorspb.CustomRegex) {
		pb.Keywords = []string{"repokw"}
		pb.SourceTypes = []string{"repository"}
	})
	everywhere := testDetector(t, "everywhere", 0, func(pb *custom_detectorspb.CustomRegex) {
		pb.Keywords = []string{"allkw"}
	})

	registry, err := NewRegistry(pbDetectors(everywhere, repoOnly), Policy{})
	require.NoError(t, err)

	git := registry.KeywordsForSource(sourcespb.SourceType_SOURCE_TYPE_GIT)
	assert.ElementsMatch(t, []string{"repokw", "allkw"}, git)

	fs := registry.KeywordsForSource(sourcespb.SourceType_SOURCE_TYPE_FILESYSTEM)
	assert.Equal(t, []string{"allkw"}, fs, "a repository-only detector must not prefilter filesystem chunks")

	s3 := registry.KeywordsForSource(sourcespb.SourceType_SOURCE_TYPE_S3)
	assert.Equal(t, []string{"allkw"}, s3)
}

func TestRegistry_RejectsUnknownSourceType(t *testing.T) {
	bad := &custom_detectorspb.CustomRegex{
		Name:        "bad",
		Keywords:    []string{"kw"},
		Regex:       map[string]string{"main": `\w+`},
		SourceTypes: []string{"kubernetes"},
	}
	_, err := NewRegistry([]*custom_detectorspb.CustomRegex{bad}, Policy{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `detector "bad"`)
	assert.Contains(t, err.Error(), `unknown source type "kubernetes"`)
}

// Requirement 4 of the hard constraints: the keyword set is exactly the
// enabled, in-scope detectors' keywords, with no ghost entries.
func TestRegistry_KeywordsMatchEnabledDetectors(t *testing.T) {
	one := testDetector(t, "one", 0, func(pb *custom_detectorspb.CustomRegex) {
		pb.Keywords = []string{"shared", "one"}
	})
	two := testDetector(t, "two", 5, func(pb *custom_detectorspb.CustomRegex) {
		pb.Keywords = []string{"shared", "two"}
		pb.SourceTypes = []string{"filesystem"}
	})
	three := testDetector(t, "three", 0, func(pb *custom_detectorspb.CustomRegex) {
		pb.Keywords = []string{"three"}
	})

	registry, err := NewRegistry(pbDetectors(one, two, three), Policy{Exclude: []string{"three"}})
	require.NoError(t, err)

	want := map[string]bool{"shared": true, "one": true, "two": true}
	got := registry.Keywords()
	for _, keyword := range got {
		assert.True(t, want[keyword], "unexpected keyword %q in prefilter", keyword)
	}
	for keyword := range want {
		assert.Contains(t, got, keyword)
	}
}

// Short-circuiting is opt-in and only affects the plan, not the conclusions
// of detectors that do run.
func TestRegistry_ShortCircuitKeepsOnlyTopPriority(t *testing.T) {
	high := testDetector(t, "high", 10)
	low := testDetector(t, "low", 1)
	registry, err := NewRegistry(pbDetectors(low, high), Policy{ShortCircuit: true})
	require.NoError(t, err)

	plan := registry.PlanForMatches([]*CustomRegexWebhook{low, high})
	require.Equal(t, []string{"high"}, namesOf(plan.Ordered))
	require.Equal(t, []string{"low"}, namesOf(plan.Skipped))

	// With short-circuiting off (the default) nothing is skipped.
	parallel, err := NewRegistry(pbDetectors(low, high), Policy{})
	require.NoError(t, err)
	plan = parallel.PlanForMatches([]*CustomRegexWebhook{low, high})
	require.Equal(t, []string{"high", "low"}, namesOf(plan.Ordered))
	assert.Empty(t, plan.Skipped)
}

func TestRegistry_AllExcludedIsReported(t *testing.T) {
	only := testDetector(t, "only", 0)
	registry, err := NewRegistry(pbDetectors(only), Policy{Exclude: []string{"only"}})
	require.NoError(t, err)
	assert.True(t, registry.AllExcluded())
	assert.Empty(t, registry.Detectors())
	require.ErrorIs(t, registry.EmptySelectionError(), ErrNoEnabledDetectors)
	assert.ErrorContains(t, registry.EmptySelectionError(), "only")
}

// Requirement 1/9 of the failure section: one detector failing (or panicking)
// is confined to that detector, and the error names it. The others continue.
func TestRegistry_EvaluateConfinesFailures(t *testing.T) {
	good := testDetector(t, "good", 10)
	failing := &erroringDetector{name: "failing"}

	outcomes := EvaluateDetectors(t.Context(),
		[]detectors.Detector{failing, good}, []byte("shared abc"), false)
	require.Len(t, outcomes, 2)

	assert.Equal(t, "failing", outcomes[0].DetectorName)
	require.Error(t, outcomes[0].Err)
	assert.Contains(t, outcomes[0].Err.Error(), `detector "failing"`)
	assert.Empty(t, outcomes[0].Results)

	assert.Equal(t, "good", outcomes[1].DetectorName)
	require.NoError(t, outcomes[1].Err)
	require.NotEmpty(t, outcomes[1].Results)
}

type erroringDetector struct{ name string }

func (d *erroringDetector) FromData(context.Context, bool, []byte) ([]detectors.Result, error) {
	return nil, fmt.Errorf("boom")
}
func (d *erroringDetector) Keywords() []string { return nil }
func (d *erroringDetector) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_CustomRegex
}
func (d *erroringDetector) Description() string { return d.name }

func TestRegistry_EvaluateRecoversPanicPerDetector(t *testing.T) {
	registry, err := NewRegistry([]*custom_detectorspb.CustomRegex{
		{Name: "alpha", Priority: 5, Keywords: []string{"shared"}, Regex: map[string]string{"main": `\w+`}},
	}, Policy{})
	require.NoError(t, err)

	// evaluateSafely is the wrapper Evaluate uses, exercised directly here
	// because the panic must be caught even though the registered detector is
	// a concrete type.
	panicking := &panickingDetector{CustomRegexWebhook: registry.Detectors()[0]}
	results, err := evaluateSafely(t.Context(), panicking, []byte("shared"), false)
	assert.Empty(t, results)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "panicked")

	// A healthy detector still produces its conclusion, in priority order.
	outcomes := registry.Evaluate(t.Context(), registry.Detectors(), []byte("shared abc"), false)
	require.Len(t, outcomes, 1)
	require.NoError(t, outcomes[0].Err)
	assert.NotEmpty(t, outcomes[0].Results)
}

type panickingDetector struct {
	*CustomRegexWebhook
}

func (d *panickingDetector) FromData(context.Context, bool, []byte) ([]detectors.Result, error) {
	panic("boom")
}

func TestRegistry_PolicyPriorityOverrides(t *testing.T) {
	alpha := testDetector(t, "alpha", 1)
	beta := testDetector(t, "beta", 2)

	// Without overrides beta (priority 2) is first.
	base, err := NewRegistry(pbDetectors(alpha, beta), Policy{})
	require.NoError(t, err)
	require.Equal(t, []string{"beta", "alpha"}, namesOf(base.Detectors()))

	// The policy can flip the order without editing either detector.
	registry, err := NewRegistry(pbDetectors(alpha, beta), Policy{
		Priorities: map[string]int32{"alpha": 10},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"alpha", "beta"}, namesOf(registry.Detectors()))
	assert.Equal(t, int32(1), alpha.GetPriority(), "the override must not mutate the detector")

	// An override that names an unknown detector is rejected, not ignored.
	_, err = NewRegistry(pbDetectors(alpha, beta), Policy{
		Priorities: map[string]int32{"typo": 10},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"typo"`)
	assert.Contains(t, err.Error(), "priority override names an unknown detector")
}

// Requirement 3 of the hard constraints: duplicate names are rejected with a
// clear disposition, reported against the later entry.
func TestRegistry_DuplicateNamesAreRejected(t *testing.T) {
	first := testDetector(t, "same", 0)
	second := testDetector(t, "same", 5)
	_, err := NewRegistry(pbDetectors(first, second), Policy{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate detector name")
	assert.Contains(t, err.Error(), `detector "same" (index 1)`)
	assert.Contains(t, err.Error(), DuplicateNamePolicy)
}

// Requirement 2 of the required shapes: one detector failing is confined to
// itself (see TestRegistry_EvaluateConfinesFailures), and ordering is stable
// across runs of the same configuration.
func TestRegistry_PlanIsDeterministic(t *testing.T) {
	detectors := []*custom_detectorspb.CustomRegex{
		{Name: "c", Priority: 1, Keywords: []string{"x"}, Regex: map[string]string{"main": `.`}},
		{Name: "a", Priority: 1, Keywords: []string{"x"}, Regex: map[string]string{"main": `.`}},
		{Name: "b", Priority: 2, Keywords: []string{"x"}, Regex: map[string]string{"main": `.`}},
	}
	var first []string
	for i := 0; i < 25; i++ {
		registry, err := NewRegistry(detectors, Policy{})
		require.NoError(t, err)
		got := namesOf(registry.Detectors())
		if i == 0 {
			first = got
			continue
		}
		require.Equal(t, first, got, "run %d differed: %v vs %v", i, first, got)
	}
	assert.Equal(t, []string{"b", "a", "c"}, first)
}

func TestRegistry_ConcurrentReadsAreSafe(t *testing.T) {
	detectors := []*custom_detectorspb.CustomRegex{
		{Name: "a", Keywords: []string{"a"}, Regex: map[string]string{"main": `.`}},
		{Name: "b", Keywords: []string{"b"}, Regex: map[string]string{"main": `.`}, SourceTypes: []string{"filesystem"}},
	}
	registry, err := NewRegistry(detectors, Policy{})
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = registry.Detectors()
			_ = registry.KeywordsForSource(sourcespb.SourceType_SOURCE_TYPE_GIT)
			_ = registry.PlanForMatches(registry.Detectors())
		}()
	}
	wg.Wait()
}

func TestParseSourceScope(t *testing.T) {
	t.Run("zero value means all", func(t *testing.T) {
		// A detector constructed without the constructor must not be scoped
		// away from every source.
		var zero SourceScope
		assert.True(t, zero.IsAll())
		assert.True(t, zero.Includes(sourcespb.SourceType_SOURCE_TYPE_GIT))
		assert.True(t, zero.Includes(sourcespb.SourceType_SOURCE_TYPE_S3))
	})

	tests := []struct {
		name    string
		input   []string
		wantErr bool
		check   func(*testing.T, SourceScope)
	}{
		{name: "empty means all", input: nil, check: func(t *testing.T, s SourceScope) {
			assert.True(t, s.IsAll())
		}},
		{name: "all", input: []string{"all"}, check: func(t *testing.T, s SourceScope) {
			assert.True(t, s.IsAll())
		}},
		{name: "group", input: []string{"repository"}, check: func(t *testing.T, s SourceScope) {
			assert.True(t, s.Includes(sourcespb.SourceType_SOURCE_TYPE_GIT))
			assert.False(t, s.Includes(sourcespb.SourceType_SOURCE_TYPE_FILESYSTEM))
		}},
		{name: "enum name with prefix", input: []string{"SOURCE_TYPE_S3"}, check: func(t *testing.T, s SourceScope) {
			assert.True(t, s.Includes(sourcespb.SourceType_SOURCE_TYPE_S3))
		}},
		{name: "enum name without prefix, any case", input: []string{"gcs-unauthed"}, check: func(t *testing.T, s SourceScope) {
			assert.True(t, s.Includes(sourcespb.SourceType_SOURCE_TYPE_GCS_UNAUTHED))
		}},
		{name: "unknown", input: []string{"nope"}, wantErr: true},
		{name: "empty entry", input: []string{" "}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSourceScope(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.check != nil {
				tt.check(t, got)
			}
		})
	}
}

func TestValidateKeywordsRejectsDuplicates(t *testing.T) {
	require.ErrorContains(t, ValidateKeywords([]string{"Token", "token"}), `duplicate keyword "token"`)
	require.NoError(t, ValidateKeywords([]string{"token", "secret"}))
}

func TestCustomRegexWebhookImplementsPriorityProvider(t *testing.T) {
	detector := testDetector(t, "p", 7)
	var provider detectors.PriorityProvider = detector
	assert.Equal(t, int32(7), provider.Priority())
}

func TestRegistry_OrderDetectorsRespectsHardPrecedenceOverPriority(t *testing.T) {
	high := testDetector(t, "high", 100)
	low := testDetector(t, "low", 0)
	registry, err := NewRegistry(pbDetectors(high, low), Policy{
		Precedence: []Precedence{{Before: "low", After: "high"}},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"low", "high"}, namesOf(registry.Detectors()),
		"a hard precedence rule overrides the priority values")
}

func ExampleRegistry() {
	detectors := []*custom_detectorspb.CustomRegex{
		{Name: "team-a", Keywords: []string{"token"}, Regex: map[string]string{"main": `\w+`}, Priority: 10},
		{Name: "team-b", Keywords: []string{"token"}, Regex: map[string]string{"main": `\w+`}, Priority: 5},
	}
	registry, _ := NewRegistry(detectors, Policy{})
	fmt.Println(namesOf(registry.Detectors()))
	// Output: [team-a team-b]
}
