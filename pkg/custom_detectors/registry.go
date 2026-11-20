package custom_detectors

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
)

// DuplicateNamePolicy states what a registry does when two custom detectors
// declare the same name. A custom detector's name is part of its identity:
// results are labelled with it, ordering rules refer to it, and the prefilter
// keeps one entry per name. Silently keeping both would make each of those
// ambiguous, so duplicates are rejected.
const DuplicateNamePolicy = "reject"

// RegistrationError reports every problem found while registering a set of
// custom detectors. Each entry names the detector it belongs to. Registration
// never proceeds with a partially valid set: an error means nothing was
// registered.
type RegistrationError struct {
	Problems []DetectorProblem
}

// DetectorProblem is one reason a detector was rejected.
type DetectorProblem struct {
	// Name is the detector name, or "(unnamed)" when the detector omitted it.
	Name string
	// Index is the position of the detector in the input, starting at 0.
	Index int
	// Reason describes the problem.
	Reason string
}

func (e *RegistrationError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "invalid custom detector configuration: %d problem(s)", len(e.Problems))
	for _, p := range e.Problems {
		fmt.Fprintf(&b, "\n  - detector %q (index %d): %s", p.Name, p.Index, p.Reason)
	}
	return b.String()
}

// detectorDisplayName returns the name used in diagnostics.
func detectorDisplayName(name string) string {
	if name == "" {
		return "(unnamed)"
	}
	return name
}

// Policy is the cross-detector configuration for a set of custom detectors.
// The zero value keeps every detector enabled, in priority order, with ties
// broken by name.
type Policy struct {
	// Precedence holds hard ordering constraints by detector name. Each pair
	// says the "before" detector always runs before the "after" detector.
	Precedence []Precedence
	// Priorities overrides a detector's own priority by name. It lets one
	// policy block declare the order without editing every detector.
	Priorities map[string]int32
	// Exclude names detectors that must not run.
	Exclude []string
	// ShortCircuit makes the highest-priority matching detector suppress the
	// lower-priority custom detectors on the same chunk. It is off by default,
	// so every matching detector gets a chance to produce a conclusion.
	ShortCircuit bool
}

// Precedence is one hard ordering constraint between two named detectors.
type Precedence struct {
	Before string
	After  string
}

// PolicyFromProto converts the protobuf policy to a Policy. It returns an
// error naming the offending entry when a precedence rule is incomplete.
func PolicyFromProto(pb *custom_detectorspb.CustomDetectorPolicy) (Policy, error) {
	if pb == nil {
		return Policy{}, nil
	}
	policy := Policy{
		Exclude:      append([]string(nil), pb.GetExclude()...),
		ShortCircuit: pb.GetShortCircuit(),
	}
	if priorities := pb.GetPriorities(); len(priorities) > 0 {
		policy.Priorities = make(map[string]int32, len(priorities))
		for i, entry := range priorities {
			name := strings.TrimSpace(entry.GetName())
			if name == "" {
				return Policy{}, fmt.Errorf(
					"custom detector policy: priority override %d must name a detector", i+1)
			}
			policy.Priorities[name] = entry.GetPriority()
		}
	}
	seen := make(map[Precedence]struct{}, len(pb.GetPrecedence()))
	for i, rule := range pb.GetPrecedence() {
		before := strings.TrimSpace(rule.GetBefore())
		after := strings.TrimSpace(rule.GetAfter())
		if before == "" || after == "" {
			return Policy{}, fmt.Errorf(
				"custom detector policy: precedence rule %d must name both a before and an after detector", i+1)
		}
		if before == after {
			return Policy{}, fmt.Errorf(
				"custom detector policy: precedence rule %d puts detector %q before itself", i+1, before)
		}
		pair := Precedence{Before: before, After: after}
		if _, ok := seen[pair]; ok {
			continue
		}
		seen[pair] = struct{}{}
		policy.Precedence = append(policy.Precedence, pair)
	}
	return policy, nil
}

// Registry holds a validated set of custom detectors plus the ordering and
// exclusion rules that apply to them.
//
// A Registry is the single place that decides:
//   - which detectors are enabled at all (not excluded, not disabled);
//   - which of those apply to a given source type;
//   - the order in which they run (priority, then hard precedence, then name);
//   - which keywords enter a source type's prefilter.
//
// It is immutable once built and safe for concurrent use.
type Registry struct {
	detectors []*CustomRegexWebhook
	byName    map[string]*CustomRegexWebhook
	// order is the enablement-independent ordering of all registered
	// detectors, highest priority first. Excluded detectors keep their place
	// in this slice so the order of the rest does not depend on exclusion.
	order    []string
	rank     map[string]int
	disabled map[string]struct{}
	policy   Policy
}

// NewRegistry validates pbDetectors and builds a Registry.
//
// Validation covers each detector on its own (keywords, regexes, verifier
// configuration, source_types) and the set as a whole (unique names,
// precedence rules that name a registered detector, and precedence cycles).
// Every problem is collected and returned together; the returned Registry is
// nil when any problem exists.
func NewRegistry(pbDetectors []*custom_detectorspb.CustomRegex, policy Policy) (*Registry, error) {
	problems := make([]DetectorProblem, 0)
	addProblem := func(index int, name, format string, args ...any) {
		problems = append(problems, DetectorProblem{
			Name:   detectorDisplayName(name),
			Index:  index,
			Reason: fmt.Sprintf(format, args...),
		})
	}

	// First pass: per-detector validation and name uniqueness. Detectors are
	// built only after the whole set validates, so a rejected set never
	// leaves a half-built registry behind.
	detectors := make([]*CustomRegexWebhook, len(pbDetectors))
	seenNames := make(map[string]int, len(pbDetectors))
	for i, pbDetector := range pbDetectors {
		if pbDetector == nil {
			addProblem(i, "", "detector entry is empty")
			continue
		}
		name := pbDetector.GetName()
		// A name is the detector's identity in ordering rules and in results.
		// An unnamed detector is still allowed for backward compatibility, but
		// there can be only one: two unnamed detectors would be
		// indistinguishable in the prefilter and in the results.
		if previous, ok := seenNames[name]; ok {
			addProblem(i, name, "duplicate detector name, already registered at index %d (%s)", previous, DuplicateNamePolicy)
		} else {
			seenNames[name] = i
		}

		// NewWebhookCustomRegex validates keywords, regexes, verifier
		// configuration, and source_types.
		detector, err := NewWebhookCustomRegex(pbDetector)
		if err != nil {
			addProblem(i, name, "%v", err)
			continue
		}
		detectors[i] = detector
	}

	return buildRegistry(pbDetectors, detectors, policy, problems)
}

// NewRegistryFromDetectors validates detectors that have already been built
// and applies policy to them. It is how the engine raises a Registry when the
// detectors arrive as a slice of detectors.Detector rather than as protobuf
// configuration. Detectors that are not custom detectors are ignored.
func NewRegistryFromDetectors(allDetectors []detectors.Detector, policy Policy) (*Registry, error) {
	pbDetectors := make([]*custom_detectorspb.CustomRegex, 0, len(allDetectors))
	built := make([]*CustomRegexWebhook, 0, len(allDetectors))
	problems := make([]DetectorProblem, 0)
	seenNames := make(map[string]int, len(allDetectors))
	for i, detector := range allDetectors {
		custom, ok := detector.(*CustomRegexWebhook)
		if !ok {
			continue
		}
		pbDetectors = append(pbDetectors, custom.CustomRegex)
		built = append(built, custom)
		name := custom.GetName()
		if previous, ok := seenNames[name]; ok {
			problems = append(problems, DetectorProblem{
				Name: detectorDisplayName(name), Index: i,
				Reason: fmt.Sprintf("duplicate detector name, already registered at index %d (%s)", previous, DuplicateNamePolicy),
			})
		} else {
			seenNames[name] = i
		}
	}
	return buildRegistry(pbDetectors, built, policy, problems)
}

// buildRegistry validates policy against the supplied detectors and assembles
// the Registry. detectors[i] must correspond to pbDetectors[i], or be nil when
// that detector failed per-detector validation.
func buildRegistry(
	pbDetectors []*custom_detectorspb.CustomRegex,
	detectors []*CustomRegexWebhook,
	policy Policy,
	problems []DetectorProblem,
) (*Registry, error) {
	// Exclusion may name detectors that were rejected above; those names are
	// checked against the input, not against successfully built detectors, so
	// a typo is reported once, as an unknown name.
	known := make(map[string]struct{}, len(pbDetectors))
	for _, pbDetector := range pbDetectors {
		if pbDetector != nil && pbDetector.GetName() != "" {
			known[pbDetector.GetName()] = struct{}{}
		}
	}
	excluded := make(map[string]struct{}, len(policy.Exclude))
	for _, name := range policy.Exclude {
		name = strings.TrimSpace(name)
		if name == "" {
			problems = append(problems, DetectorProblem{
				Name:   "(policy)",
				Index:  -1,
				Reason: "custom detector policy: exclude contains an empty detector name",
			})
			continue
		}
		if _, ok := known[name]; !ok {
			problems = append(problems, DetectorProblem{
				Name:   name,
				Index:  -1,
				Reason: "custom detector policy: excluded detector is not registered",
			})
			continue
		}
		excluded[name] = struct{}{}
	}

	// Disabled is the per-detector spelling of exclusion.
	for _, pbDetector := range pbDetectors {
		if pbDetector != nil && pbDetector.GetDisabled() && pbDetector.GetName() != "" {
			excluded[pbDetector.GetName()] = struct{}{}
		}
	}

	// Priority overrides must name registered detectors. The override is
	// applied to ordering only; it never mutates the caller's configuration.
	for name := range policy.Priorities {
		if _, ok := known[name]; !ok {
			problems = append(problems, DetectorProblem{
				Name:   name,
				Index:  -1,
				Reason: "custom detector policy: priority override names an unknown detector",
			})
		}
	}

	// Precedence rules must name registered detectors.
	for _, rule := range policy.Precedence {
		if _, ok := known[rule.Before]; !ok {
			problems = append(problems, DetectorProblem{
				Name:   rule.Before,
				Index:  -1,
				Reason: fmt.Sprintf("custom detector policy: precedence rule names an unknown detector (before %q)", rule.Before),
			})
		}
		if _, ok := known[rule.After]; !ok {
			problems = append(problems, DetectorProblem{
				Name:   rule.After,
				Index:  -1,
				Reason: fmt.Sprintf("custom detector policy: precedence rule names an unknown detector (after %q)", rule.After),
			})
		}
	}

	order, cycleErr := orderDetectors(pbDetectors, policy)
	if cycleErr != nil {
		problems = append(problems, DetectorProblem{
			Name:   "(policy)",
			Index:  -1,
			Reason: cycleErr.Error(),
		})
	}

	if len(problems) > 0 {
		return nil, &RegistrationError{Problems: problems}
	}

	byName := make(map[string]*CustomRegexWebhook, len(detectors))
	rank := make(map[string]int, len(order))
	for position, name := range order {
		rank[name] = position
	}
	for _, detector := range detectors {
		if detector == nil {
			continue
		}
		byName[detector.GetName()] = detector
	}

	return &Registry{
		detectors: detectors,
		byName:    byName,
		order:     order,
		rank:      rank,
		disabled:  excluded,
		policy:    policy,
	}, nil
}

// orderDetectors returns detector names in execution order: priority
// descending, then hard precedence, then name. Precedence is resolved with a
// topological sort; a cycle is an error that names one conflicting pair.
func orderDetectors(pbDetectors []*custom_detectorspb.CustomRegex, policy Policy) ([]string, error) {
	precedence := policy.Precedence
	// Base order: priority descending, name ascending. This is the complete
	// order before precedence is applied.
	names := make([]string, 0, len(pbDetectors))
	priority := make(map[string]int32, len(pbDetectors))
	for _, pbDetector := range pbDetectors {
		if pbDetector == nil {
			continue
		}
		name := pbDetector.GetName()
		names = append(names, name)
		priority[name] = pbDetector.GetPriority()
	}
	for name, override := range policy.Priorities {
		if _, ok := priority[name]; ok {
			priority[name] = override
		}
	}
	sort.SliceStable(names, func(i, j int) bool {
		if priority[names[i]] != priority[names[j]] {
			return priority[names[i]] > priority[names[j]]
		}
		return names[i] < names[j]
	})
	baseRank := make(map[string]int, len(names))
	for rank, name := range names {
		baseRank[name] = rank
	}

	// Hard precedence edges. Only edges between registered names matter;
	// unknown names are reported separately.
	edges := make(map[string][]string, len(names))
	indegree := make(map[string]int, len(names))
	for _, name := range names {
		indegree[name] = 0
	}
	seenEdge := make(map[Precedence]struct{}, len(precedence))
	for _, rule := range precedence {
		if _, ok := baseRank[rule.Before]; !ok {
			continue
		}
		if _, ok := baseRank[rule.After]; !ok {
			continue
		}
		if _, ok := seenEdge[rule]; ok {
			continue
		}
		seenEdge[rule] = struct{}{}
		edges[rule.Before] = append(edges[rule.Before], rule.After)
		indegree[rule.After]++
	}

	// Kahn's algorithm. When several detectors are ready, the one earliest in
	// the base order goes first, which makes the result a stable refinement of
	// the priority order.
	var ready []string
	for _, name := range names {
		if indegree[name] == 0 {
			ready = append(ready, name)
		}
	}
	sortByRank(ready, baseRank)

	ordered := make([]string, 0, len(names))
	for len(ready) > 0 {
		name := ready[0]
		ready = ready[1:]
		ordered = append(ordered, name)
		for _, next := range edges[name] {
			indegree[next]--
			if indegree[next] == 0 {
				ready = append(ready, next)
			}
		}
		sortByRank(ready, baseRank)
	}

	if len(ordered) != len(names) {
		return nil, cycleError(names, edges, indegree, baseRank)
	}
	return ordered, nil
}

func sortByRank(names []string, rank map[string]int) {
	sort.SliceStable(names, func(i, j int) bool { return rank[names[i]] < rank[names[j]] })
}

// cycleError finds one concrete cycle among the detectors that could not be
// ordered and reports the pair that closes it.
func cycleError(names []string, edges map[string][]string, indegree map[string]int, baseRank map[string]int) error {
	stuck := make([]string, 0)
	for _, name := range names {
		if indegree[name] > 0 {
			stuck = append(stuck, name)
		}
	}
	sortByRank(stuck, baseRank)

	// Every detector left after Kahn's algorithm lies on or downstream of a
	// cycle. A depth-first walk restricted to the stuck set therefore reaches
	// one; the first repeated detector closes the cycle.
	const (
		unvisited = iota
		onPath
		done
	)
	state := make(map[string]int, len(stuck))
	var path []string
	var cycle []string

	var walk func(string) bool
	walk = func(name string) bool {
		state[name] = onPath
		path = append(path, name)
		next := append([]string(nil), edges[name]...)
		sortByRank(next, baseRank)
		for _, candidate := range next {
			if _, ok := state[candidate]; !ok {
				continue
			}
			switch state[candidate] {
			case onPath:
				for i, onPathName := range path {
					if onPathName == candidate {
						cycle = append(append([]string(nil), path[i:]...), candidate)
						return true
					}
				}
			case unvisited:
				if walk(candidate) {
					return true
				}
			}
		}
		path = path[:len(path)-1]
		state[name] = done
		return false
	}
	for _, name := range stuck {
		if state[name] == unvisited && walk(name) {
			break
		}
	}
	if len(cycle) >= 2 {
		return fmt.Errorf(
			"custom detector policy: precedence cycle between %q and %q: %s",
			cycle[len(cycle)-2], cycle[len(cycle)-1], strings.Join(cycle, " -> "))
	}

	// Fall back to the first edge that points back into the stuck set.
	for _, before := range stuck {
		for _, after := range edges[before] {
			if _, ok := state[after]; ok {
				return fmt.Errorf("custom detector policy: precedence cycle between %q and %q", before, after)
			}
		}
	}
	return fmt.Errorf("custom detector policy: precedence rules contain a cycle")
}

// Detectors returns the enabled detectors in execution order. Detectors that
// are excluded or disabled are not returned.
func (r *Registry) Detectors() []*CustomRegexWebhook {
	enabled := make([]*CustomRegexWebhook, 0, len(r.detectors))
	for _, name := range r.order {
		if r.isDisabled(name) {
			continue
		}
		enabled = append(enabled, r.byName[name])
	}
	return enabled
}

// DetectorsForSource returns the enabled detectors that apply to sourceType,
// in execution order.
func (r *Registry) DetectorsForSource(sourceType sourcespb.SourceType) []*CustomRegexWebhook {
	enabled := make([]*CustomRegexWebhook, 0, len(r.detectors))
	for _, detector := range r.Detectors() {
		if !detector.scope.Includes(sourceType) {
			continue
		}
		enabled = append(enabled, detector)
	}
	return enabled
}

// Lookup returns the registered detector with the given name.
func (r *Registry) Lookup(name string) (*CustomRegexWebhook, bool) {
	detector, ok := r.byName[name]
	return detector, ok
}

// Enabled reports whether the named detector is registered and enabled.
func (r *Registry) Enabled(name string) bool {
	if _, ok := r.byName[name]; !ok {
		return false
	}
	return !r.isDisabled(name)
}

// Excluded returns the names that are excluded from scanning, sorted.
func (r *Registry) Excluded() []string {
	names := make([]string, 0, len(r.disabled))
	for name := range r.disabled {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// AllExcluded reports whether detectors were registered but every one of them
// is excluded from scanning.
func (r *Registry) AllExcluded() bool {
	return len(r.byName) > 0 && len(r.Detectors()) == 0
}

// ShortCircuit reports whether a matching detector suppresses lower-priority
// custom detectors on the same chunk.
func (r *Registry) ShortCircuit() bool { return r.policy.ShortCircuit }

// KeywordsForSource returns the keywords that enter the prefilter for
// sourceType: exactly the keywords of the enabled, in-scope detectors. A
// detector that is excluded, disabled, or out of scope contributes nothing.
func (r *Registry) KeywordsForSource(sourceType sourcespb.SourceType) []string {
	seen := make(map[string]struct{})
	var keywords []string
	for _, detector := range r.DetectorsForSource(sourceType) {
		for _, keyword := range detector.Keywords() {
			folded := strings.ToLower(keyword)
			if _, ok := seen[folded]; ok {
				continue
			}
			seen[folded] = struct{}{}
			keywords = append(keywords, folded)
		}
	}
	return keywords
}

// Keywords returns every keyword that can enter any prefilter, i.e. the
// keywords of all enabled detectors regardless of source scope. Detectors
// that are excluded or disabled contribute nothing.
func (r *Registry) Keywords() []string {
	seen := make(map[string]struct{})
	var keywords []string
	for _, detector := range r.Detectors() {
		for _, keyword := range detector.Keywords() {
			folded := strings.ToLower(keyword)
			if _, ok := seen[folded]; ok {
				continue
			}
			seen[folded] = struct{}{}
			keywords = append(keywords, folded)
		}
	}
	return keywords
}

// SortedByPriority orders the given detectors the way the Registry does.
// Detectors that do not belong to the registry are placed after the ones that
// do, keeping their input order. It is used by the engine to order the
// detectors a chunk's keyword match selected.
func (r *Registry) SortedByPriority(input []*CustomRegexWebhook) []*CustomRegexWebhook {
	out := append([]*CustomRegexWebhook(nil), input...)
	sort.SliceStable(out, func(i, j int) bool {
		iRank, iOK := r.rank[out[i].GetName()]
		jRank, jOK := r.rank[out[j].GetName()]
		switch {
		case iOK && jOK:
			return iRank < jRank
		case iOK:
			return true
		case jOK:
			return false
		default:
			return false
		}
	})
	return out
}

// Plan is the execution plan for the custom detectors whose keywords matched
// one chunk.
type Plan struct {
	// Ordered holds the detectors to run, highest priority first.
	Ordered []*CustomRegexWebhook
	// Skipped holds the detectors that matched but will not run because a
	// higher-priority detector short-circuited them.
	Skipped []*CustomRegexWebhook
}

// PlanForMatches builds the execution plan for the custom detectors that
// matched a chunk.
//
// Without short-circuiting every match is kept, ordered by the registry. With
// short-circuiting only the highest-priority match is run and the rest are
// reported as skipped. Ties are broken by the registry's stable order, so the
// same input always produces the same plan.
func (r *Registry) PlanForMatches(matches []*CustomRegexWebhook) Plan {
	ordered := r.SortedByPriority(matches)
	if !r.policy.ShortCircuit || len(ordered) <= 1 {
		return Plan{Ordered: ordered}
	}
	return Plan{Ordered: ordered[:1], Skipped: ordered[1:]}
}

// Outcome is one detector's conclusion for a chunk.
type Outcome struct {
	// Detector is the detector that produced the outcome.
	Detector detectors.Detector
	// DetectorName is the detector's name, or its description for a detector
	// that has none.
	DetectorName string
	// Results are the conclusions, in the detector's own order.
	Results []detectors.Result
	// Err is set when the detector failed. A failure is confined to this
	// outcome; the other detectors still run.
	Err error
}

// Evaluate runs the given detectors on one chunk, in the order the registry
// declares, and returns one Outcome per detector.
//
// It is the deterministic execution primitive behind the engine's prefilter:
// outcomes come back in declared-priority order, so callers that need
// conclusions in a defined order (tests, batch tooling, embedders) do not have
// to depend on goroutine scheduling. Short-circuiting, when enabled, is
// applied as well. A detector that fails or panics yields an Outcome with Err
// set and does not stop the others.
func (r *Registry) Evaluate(ctx context.Context, matching []*CustomRegexWebhook, data []byte, verify bool) []Outcome {
	plan := r.PlanForMatches(matching)
	ordered := make([]detectors.Detector, 0, len(plan.Ordered))
	for _, detector := range plan.Ordered {
		ordered = append(ordered, detector)
	}
	return EvaluateDetectors(ctx, ordered, data, verify)
}

// EvaluateDetectors runs already-ordered detectors on one chunk and returns
// one Outcome per detector. Unlike Evaluate it accepts any detector, which
// lets callers mix custom and built-in detectors in a caller-chosen order.
// One detector's error or panic never stops the rest.
func EvaluateDetectors(
	ctx context.Context,
	ordered []detectors.Detector,
	data []byte,
	verify bool,
) []Outcome {
	outcomes := make([]Outcome, 0, len(ordered))
	for _, detector := range ordered {
		name := detector.Description()
		if custom, ok := detector.(*CustomRegexWebhook); ok {
			name = custom.GetName()
		}
		if common.IsDone(ctx) {
			outcomes = append(outcomes, Outcome{Detector: detector, DetectorName: name, Err: ctx.Err()})
			continue
		}
		results, err := evaluateSafely(ctx, detector, data, verify)
		outcomes = append(outcomes, Outcome{Detector: detector, DetectorName: name, Results: results, Err: err})
	}
	return outcomes
}

// evaluateSafely calls FromData and turns a panic into an error attributable
// to this detector.
func evaluateSafely(
	ctx context.Context,
	detector detectors.Detector,
	data []byte,
	verify bool,
) (results []detectors.Result, err error) {
	name := detector.Description()
	if custom, ok := detector.(*CustomRegexWebhook); ok {
		name = custom.GetName()
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			results = nil
			err = fmt.Errorf("detector %q panicked: %v", name, recovered)
		}
	}()
	results, err = detector.FromData(ctx, verify, data)
	if err != nil {
		results = nil
		err = fmt.Errorf("detector %q: %w", name, err)
	}
	return results, err
}

// Rank returns the registry position of the detector, lower first, and
// whether the detector belongs to this registry.
func (r *Registry) Rank(detector *CustomRegexWebhook) (int, bool) {
	if _, ok := r.byName[detector.GetName()]; !ok {
		return 0, false
	}
	return r.rank[detector.GetName()], true
}

func (r *Registry) isDisabled(name string) bool {
	_, ok := r.disabled[name]
	return ok
}

// ensure the detector implements the optional priority interface.
var _ detectors.PriorityProvider = (*CustomRegexWebhook)(nil)

// Priority returns the explicitly declared priority of the detector.
func (c *CustomRegexWebhook) Priority() int32 { return c.GetPriority() }

// ErrNoEnabledDetectors is returned by NewRegistry when detectors were
// supplied but the policy excluded every one of them. An empty result is
// allowed, but callers must be able to tell "nothing was scanned" apart from
// "nothing was found", so this is surfaced explicitly.
var ErrNoEnabledDetectors = errors.New("every custom detector is excluded; scans will produce no custom detector results")

// EmptySelectionError explains an empty custom detector selection.
func (r *Registry) EmptySelectionError() error {
	if !r.AllExcluded() {
		return nil
	}
	return fmt.Errorf("%w (excluded: %s)", ErrNoEnabledDetectors, strings.Join(r.Excluded(), ", "))
}
