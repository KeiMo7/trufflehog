package ahocorasick

import (
	"cmp"
	"slices"
	"sync"

	ahocorasick "github.com/BobuSumisu/aho-corasick"

	"github.com/trufflesecurity/trufflehog/v3/pkg/custom_detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
)

// lowerBuf is a reusable buffer holding the lowercased copy of one chunk.
//
// Every chunk needs such a copy, and each one is thrown away moments later, so
// rather than allocate a new buffer every time we borrow one from a pool and
// hand it back afterwards. In a steady scan the pool already holds a buffer big
// enough, so the copy costs no allocation at all.
//
// The pool stores pointers rather than plain slices. Putting a slice into a
// sync.Pool would allocate on every Put, which is the very thing being avoided.
type lowerBuf struct{ b []byte }

var lowerBufPool = sync.Pool{New: func() any { return new(lowerBuf) }}

// maxPooledLowerBuf is the largest buffer worth keeping for reuse.
//
// One unusually large chunk would otherwise leave a matching buffer sitting in
// the pool for the rest of the run, once per worker goroutine. Past this size
// it is cheaper to let the buffer go and allocate again next time.
const maxPooledLowerBuf = 1 << 20 // 1 MiB

// getLowerBuf borrows a buffer able to hold size bytes.
func getLowerBuf(size int) *lowerBuf {
	buf := lowerBufPool.Get().(*lowerBuf)
	if cap(buf.b) < size {
		buf.b = make([]byte, 0, size)
	}
	return buf
}

// putLowerBuf returns a buffer for reuse, unless it is too big to be worth
// holding on to.
func putLowerBuf(buf *lowerBuf) {
	if cap(buf.b) > maxPooledLowerBuf {
		return
	}
	buf.b = buf.b[:0]
	lowerBufPool.Put(buf)
}

// appendASCIILower copies src onto dst, turning A-Z into a-z and leaving every
// other byte exactly as it was.
//
// Only A-Z is changed, for two reasons.
//
// It keeps the copy the same length as the original. Lowercasing a character
// can change how many bytes it takes: "İ" needs two bytes, "i" needs one.
// FindDetectorMatches searches the lowercased copy but then cuts bytes out of
// the original chunk, so if the copy were a different length every position
// would point somewhere slightly wrong, and the text handed to a detector would
// not be the text that matched.
//
// Nothing is lost by leaving other bytes alone. Every built-in detector keyword
// is plain ASCII, so a non-ASCII byte can never be part of a match either way.
//
// Keywords are folded through this same function when they are registered, so
// both sides of the search always agree. The one gap is a custom detector whose
// keyword contains a cased non-ASCII letter: that letter is left as written on
// both sides, so the keyword matches only text spelling it the same way.
func appendASCIILower(dst, src []byte) []byte {
	for _, c := range src {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		dst = append(dst, c)
	}
	return dst
}

// DetectorKey is used to identify a detector in the keywordsToDetectors map.
// Multiple detectors can have the same detector type but different versions.
// This allows us to identify a detector by its type and version. An
// additional (optional) field is provided to disambiguate multiple custom
// detectors. This type is exported even though none of its fields are so
// that the AhoCorasickCore can populate passed-in maps keyed on this type
// without exposing any of its internals to consumers.
type DetectorKey struct {
	detectorType       detector_typepb.DetectorType
	version            int
	customDetectorName string
	// priority is the explicitly declared priority of the detector, or 0 when
	// it declares none. It orders detectors of the same type; it is never
	// derived from the type enum.
	priority int32
}

func (k DetectorKey) Loggable() map[string]any {
	res := map[string]any{"type": k.detectorType.String()}
	if k.version > 0 {
		res["version"] = k.version
	}
	if k.customDetectorName != "" {
		res["name"] = k.customDetectorName
	}
	return res
}

// Type returns the detector type of the key.
func (k DetectorKey) Type() detector_typepb.DetectorType { return k.detectorType }

// Priority returns the explicitly declared priority of the key.
func (k DetectorKey) Priority() int32 { return k.priority }

// compare orders keys by detector type, then priority (highest first), then
// version and custom detector name so that the result order does not depend on
// map iteration. The type order is the protobuf enum value, which is
// assignment history, not priority; priority only orders detectors that share
// a type, which is where the old type order said nothing.
func (k DetectorKey) compare(other DetectorKey) int {
	return cmp.Or(
		cmp.Compare(k.detectorType, other.detectorType),
		cmp.Compare(other.priority, k.priority),
		cmp.Compare(k.version, other.version),
		cmp.Compare(k.customDetectorName, other.customDetectorName),
	)
}

// spanCalculator is an interface that defines a method for calculating a match span
// in the chunk data. This allows for different strategies to be used without changing the core logic.
type spanCalculator interface {
	calculateSpan(params spanCalculationParams) matchSpan
}

// spanCalculationParams provides the necessary context for calculating match spans,
// including the keyword index in the chunk, the chunk data itself, and the detector being used.
type spanCalculationParams struct {
	keywordIdx int64 // Index of the keyword in the chunk data
	chunkData  []byte
	detector   detectors.Detector
}

// EntireChunkSpanCalculator is a strategy that calculates the match span to use the entire chunk data.
// This is used when we want to match against the full length of the provided chunk.
type EntireChunkSpanCalculator struct{}

// calculateSpan returns the match span as the length of the chunk data,
// effectively using the entire chunk for matching.
func (e *EntireChunkSpanCalculator) calculateSpan(params spanCalculationParams) matchSpan {
	return matchSpan{startOffset: 0, endOffset: int64(len(params.chunkData))}
}

// adjustableSpanCalculator is a strategy that calculates match spans. It uses a default offset magnitude
// or values provided by specific detectors to adjust the start and end indices of the span, allowing
// for more granular control over the match.
type adjustableSpanCalculator struct{ offsetMagnitude int64 }

// newAdjustableSpanCalculator creates a new instance of adjustableSpanCalculator with the
// specified offset magnitude.
func newAdjustableSpanCalculator(offsetRadius int64) *adjustableSpanCalculator {
	return &adjustableSpanCalculator{offsetMagnitude: offsetRadius}
}

// calculateSpan computes the match span based on the keyword index and the offset magnitude.
// If the detector provides an override value, it uses that instead of the default offset magnitude to
// calculate the maximum size of the span.
// The start index of the span is also adjusted if the detector provides a start offset.
func (m *adjustableSpanCalculator) calculateSpan(params spanCalculationParams) matchSpan {
	keywordIdx := params.keywordIdx

	maxSize := keywordIdx + m.offsetMagnitude
	startOffset := keywordIdx - m.offsetMagnitude

	// Check if the detector implements each interface and update values accordingly.
	// This CAN'T be done in a switch statement because a detector can implement multiple interfaces.
	if provider, ok := params.detector.(detectors.MultiPartCredentialProvider); ok {
		maxSize = provider.MaxCredentialSpan() + keywordIdx
		startOffset = keywordIdx - provider.MaxCredentialSpan()
	}
	if provider, ok := params.detector.(detectors.MaxSecretSizeProvider); ok {
		maxSize = provider.MaxSecretSize() + keywordIdx
	}
	if provider, ok := params.detector.(detectors.StartOffsetProvider); ok {
		startOffset = keywordIdx - provider.StartOffset()
	}

	startIdx := max(startOffset, 0)
	endIdx := min(maxSize, int64(len(params.chunkData)))

	// Ensure the start index is not greater than the end index to prevent invalid spans.
	// In rare cases where the calculated start index exceeds the end index (possibly due to
	// detector-provided offsets), we reset the start index to 0 to maintain a valid span range
	// and avoid runtime panics. This is a temporary fix until the root cause is identified.
	if startIdx >= endIdx {
		startIdx = 0
	}

	return matchSpan{startOffset: startIdx, endOffset: endIdx}
}

// CoreOption is a functional option type for configuring an AhoCorasickCore instance.
type CoreOption func(*Core)

// WithSpanCalculator sets the span calculator for AhoCorasickCore.
func WithSpanCalculator(spanCalculator spanCalculator) CoreOption {
	return func(ac *Core) { ac.spanCalculator = spanCalculator }
}

// Core encapsulates the operations and data structures used for keyword matching via the
// Aho-Corasick algorithm. It is responsible for constructing and managing the trie for efficient
// substring searches, as well as mapping keywords to their associated detectors for rapid lookups.
type Core struct {
	// prefilter is a ahocorasick struct used for doing efficient string
	// matching given a set of words. (keywords from the rules in the config)
	prefilter ahocorasick.Trie
	// Maps for efficient lookups during detection.
	// (This implementation maps in two layers: from keywords to detector
	// type and then again from detector type to detector. We could
	// go straight from keywords to detectors but doing it this way makes
	// some consuming code a little cleaner.)
	keywordsToDetectors map[string][]DetectorKey
	detectorsByKey      map[DetectorKey]detectors.Detector
	spanCalculator      spanCalculator // Strategy for calculating match spans

	// scoped reports whether at least one detector is limited to some source
	// types. When it is false every detector applies everywhere and the
	// per-source view is the global one, so no extra structures are built.
	scoped bool
	// sourceMu guards sourcePrefilters, which is filled lazily so scans that
	// never see a scoped detector never pay for the per-source views.
	sourceMu         sync.Mutex
	sourcePrefilters map[sourcespb.SourceType]*sourcePrefilter
}

// sourcePrefilter is the keyword view for one source type: only detectors
// enabled for that source type appear in it.
type sourcePrefilter struct {
	trie                ahocorasick.Trie
	keywordsToDetectors map[string][]DetectorKey
}

// NewAhoCorasickCore allocates and initializes a new instance of AhoCorasickCore. It uses the
// provided detector slice to create a map from keywords to detectors and build the Aho-Corasick
// prefilter trie.
func NewAhoCorasickCore(allDetectors []detectors.Detector, opts ...CoreOption) *Core {
	keywordsToDetectors := make(map[string][]DetectorKey)
	detectorsByKey := make(map[DetectorKey]detectors.Detector, len(allDetectors))
	var keywords []string
	scoped := false
	for _, d := range allDetectors {
		key := CreateDetectorKey(d)
		detectorsByKey[key] = d
		if custom, ok := d.(*custom_detectors.CustomRegexWebhook); ok && !custom.Scope().IsAll() {
			scoped = true
		}
		for _, kw := range d.Keywords() {
			// Fold the keyword exactly the way FindDetectorMatches folds the
			// chunk it searches, so the two sides can never disagree.
			kwFolded := string(appendASCIILower(nil, []byte(kw)))
			keywords = append(keywords, kwFolded)
			keywordsToDetectors[kwFolded] = append(keywordsToDetectors[kwFolded], key)
		}
	}

	const defaultOffsetRadius int64 = 512
	core := &Core{
		keywordsToDetectors: keywordsToDetectors,
		detectorsByKey:      detectorsByKey,
		prefilter:           *ahocorasick.NewTrieBuilder().AddStrings(keywords).Build(),
		spanCalculator:      newAdjustableSpanCalculator(defaultOffsetRadius), // Default span calculator
		scoped:              scoped,
	}

	for _, opt := range opts {
		opt(core)
	}

	return core
}

// prefilterForSource returns the keyword view for sourceType. When no
// detector is scoped, every detector applies everywhere and the global view
// is returned unchanged.
func (ac *Core) prefilterForSource(sourceType sourcespb.SourceType) *sourcePrefilter {
	if !ac.scoped {
		return &sourcePrefilter{
			trie:                ac.prefilter,
			keywordsToDetectors: ac.keywordsToDetectors,
		}
	}

	ac.sourceMu.Lock()
	defer ac.sourceMu.Unlock()
	if ac.sourcePrefilters == nil {
		ac.sourcePrefilters = make(map[sourcespb.SourceType]*sourcePrefilter)
	}
	if existing, ok := ac.sourcePrefilters[sourceType]; ok {
		return existing
	}

	keywordsToDetectors := make(map[string][]DetectorKey)
	// Building from detectorsByKey (a map) gives no meaningful order, but
	// FindDetectorMatches sorts its output, so the result is still stable.
	for key, detector := range ac.detectorsByKey {
		if custom, ok := detector.(*custom_detectors.CustomRegexWebhook); ok &&
			!custom.AppliesToSource(sourceType) {
			continue
		}
		for _, kw := range detector.Keywords() {
			kwFolded := string(appendASCIILower(nil, []byte(kw)))
			keywordsToDetectors[kwFolded] = append(keywordsToDetectors[kwFolded], key)
		}
	}
	keywords := make([]string, 0, len(keywordsToDetectors))
	for kw := range keywordsToDetectors {
		keywords = append(keywords, kw)
	}
	built := &sourcePrefilter{
		trie:                *ahocorasick.NewTrieBuilder().AddStrings(keywords).Build(),
		keywordsToDetectors: keywordsToDetectors,
	}
	ac.sourcePrefilters[sourceType] = built
	return built
}

// DetectorMatch represents a detected pattern's metadata in a data chunk.
// It encapsulates the key identifying a specific detector, the detector instance itself,
// the start and end offsets of the matched keyword in the chunk, and the matched portions of the chunk data.
type DetectorMatch struct {
	Key DetectorKey
	detectors.Detector
	matchSpans []matchSpan

	// matches is a slice of byte slices, each representing a matched portion of the chunk data.
	matches [][]byte
}

// MatchSpan represents a single occurrence of a matched keyword in the chunk.
// It contains the start and end byte offsets of the matched keyword within the chunk.
type matchSpan struct {
	startOffset int64
	endOffset   int64
}

// addMatchSpan adds a match span to the DetectorMatch instance.
func (d *DetectorMatch) addMatchSpan(spans ...matchSpan) {
	d.matchSpans = append(d.matchSpans, spans...)
}

// mergeMatches merges overlapping or adjacent matchSpans into a single matchSpan.
// It updates the matchSpans field with the merged spans.
func (d *DetectorMatch) mergeMatches() {
	if len(d.matchSpans) <= 1 {
		return
	}

	merged := make([]matchSpan, 0, len(d.matchSpans))
	current := d.matchSpans[0]

	for i := 1; i < len(d.matchSpans); i++ {
		if d.matchSpans[i].startOffset <= current.endOffset {
			if d.matchSpans[i].endOffset > current.endOffset {
				current.endOffset = d.matchSpans[i].endOffset
			}
			continue
		}
		merged = append(merged, current)
		current = d.matchSpans[i]
	}

	merged = append(merged, current)
	d.matchSpans = merged
}

// extractMatches extracts the matched portions from the chunk data and stores them in the matches field.
func (d *DetectorMatch) extractMatches(chunkData []byte) {
	d.matches = make([][]byte, len(d.matchSpans))
	for i, m := range d.matchSpans {
		d.matches[i] = chunkData[m.startOffset:m.endOffset]
	}
}

// Matches returns a slice of byte slices, each representing a matched portion of the chunk data.
func (d *DetectorMatch) Matches() [][]byte { return d.matches }

// FindDetectorMatches finds the matching detectors for a given chunk of data using the Aho-Corasick algorithm.
// It returns a slice of DetectorMatch instances, each containing the detector key, detector,
// a slice of matchSpans, and the corresponding matched portions of the chunk data.
//
// Each matchSpan represents a position in the chunk data where a keyword was found,
// along with the corresponding span (start and end positions).
// The span is determined based on the configured spanCalculator strategy.
// Adjacent or overlapping matches are merged to avoid duplicating or overlapping the matched
// portions of the chunk data.
//
// The matches field contains the actual byte slices of the matched portions from the chunk data.
func (ac *Core) FindDetectorMatches(chunkData []byte) []*DetectorMatch {
	return ac.findDetectorMatches(chunkData, nil)
}

// FindDetectorMatchesForSource finds the matching detectors for a chunk and
// only returns detectors enabled for sourceType. Custom detectors with a
// source_types scope that does not include sourceType are omitted, including
// detector types whose keywords would otherwise match. The result order is the
// same as FindDetectorMatches.
func (ac *Core) FindDetectorMatchesForSource(
	chunkData []byte,
	sourceType sourcespb.SourceType,
) []*DetectorMatch {
	view := ac.prefilterForSource(sourceType)
	return ac.findDetectorMatches(chunkData, view)
}

// findDetectorMatches runs the prefilter in view, or the global prefilter when
// view is nil.
func (ac *Core) findDetectorMatches(chunkData []byte, view *sourcePrefilter) []*DetectorMatch {
	// Search a lowercased copy so matching ignores case, but keep reporting
	// positions against the original chunk, which is what the spans below cut
	// from. The copy is borrowed and returned so it costs no allocation.
	lowered := getLowerBuf(len(chunkData))
	defer putLowerBuf(lowered)
	lowered.b = appendASCIILower(lowered.b[:0], chunkData)

	prefilter := &ac.prefilter
	keywordsToDetectors := ac.keywordsToDetectors
	if view != nil {
		prefilter = &view.trie
		keywordsToDetectors = view.keywordsToDetectors
	}

	matches := prefilter.Match(lowered.b)

	matchCount := len(matches)
	if matchCount == 0 {
		return nil
	}

	detectorMatches := make(map[DetectorKey]*DetectorMatch)

	for _, m := range matches {
		for _, k := range keywordsToDetectors[m.MatchString()] {
			if _, exists := detectorMatches[k]; !exists {
				detector := ac.detectorsByKey[k]
				detectorMatches[k] = &DetectorMatch{
					Key:        k,
					Detector:   detector,
					matchSpans: make([]matchSpan, 0),
				}
			}

			detectorMatch := detectorMatches[k]
			startIdx := m.Pos()
			span := ac.spanCalculator.calculateSpan(
				spanCalculationParams{
					keywordIdx: startIdx,
					chunkData:  chunkData,
					detector:   detectorMatch.Detector,
				},
			)
			detectorMatch.addMatchSpan(span)
		}
	}

	uniqueDetectors := make([]*DetectorMatch, 0, len(detectorMatches))
	for _, detectorMatch := range detectorMatches {
		// Merge overlapping or adjacent match spans.
		detectorMatch.mergeMatches()
		detectorMatch.extractMatches(chunkData)

		uniqueDetectors = append(uniqueDetectors, detectorMatch)
	}

	// Sort so the order of the returned matches does not depend on map iteration.
	slices.SortFunc(uniqueDetectors, func(a, b *DetectorMatch) int { return a.Key.compare(b.Key) })

	return uniqueDetectors
}

// CreateDetectorKey creates a unique key for each detector from its type, version, priority, and, for
// custom regex detectors, its name.
func CreateDetectorKey(d detectors.Detector) DetectorKey {
	detectorType := d.Type()
	var version int
	if v, ok := d.(detectors.Versioner); ok {
		version = v.Version()
	}
	var priority int32
	if p, ok := d.(detectors.PriorityProvider); ok {
		priority = p.Priority()
	}
	var customDetectorName string
	if r, ok := d.(*custom_detectors.CustomRegexWebhook); ok {
		customDetectorName = r.GetName()
	}
	return DetectorKey{
		detectorType:       detectorType,
		version:            version,
		customDetectorName: customDetectorName,
		priority:           priority,
	}
}

func (ac *Core) KeywordsToDetectors() map[string][]DetectorKey {
	return ac.keywordsToDetectors
}

// KeywordsForSource returns the keywords that can trigger a detector for the
// given source type. It is the keyword set of the per-source prefilter, so it
// never contains a keyword that belongs only to a detector scoped away from
// that source.
func (ac *Core) KeywordsForSource(sourceType sourcespb.SourceType) map[string]struct{} {
	view := ac.prefilterForSource(sourceType)
	keywords := make(map[string]struct{}, len(view.keywordsToDetectors))
	for keyword := range view.keywordsToDetectors {
		keywords[keyword] = struct{}{}
	}
	return keywords
}
