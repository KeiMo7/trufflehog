package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/custom_detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
)

func TestNewYAML_CustomDetectorPolicy(t *testing.T) {
	input := []byte(`
detectors:
  - name: team-a
    keywords: [hog]
    regex:
      token: '([A-Za-z0-9]{20})'
    priority: 10
  - name: team-b
    keywords: [hog]
    regex:
      token: '([A-Za-z0-9]{20})'
    priority: 5
  - name: always-noisy
    keywords: [hog]
    regex:
      token: '([A-Za-z0-9]{20})'
  - name: repo-only
    keywords: [repo]
    regex:
      token: '([A-Za-z0-9]{20})'
    sourceTypes: [repository]
customDetectorPolicy:
  exclude: [always-noisy]
  precedence:
    - before: team-b
      after: team-a
  priorities:
    - name: team-b
      priority: 50
  shortCircuit: true
`)

	conf, err := NewYAML(input)
	require.NoError(t, err)
	require.NotNil(t, conf.CustomDetectorRegistry)

	names := make([]string, 0, len(conf.Detectors))
	for _, detector := range conf.Detectors {
		names = append(names, detector.(*custom_detectors.CustomRegexWebhook).GetName())
	}
	// team-a and team-b are both enabled; the hard precedence rule puts
	// team-b first despite its lower priority. always-noisy is excluded, and
	// repo-only has no priority and sorts by name after the positive ones.
	assert.Equal(t, []string{"team-b", "team-a", "repo-only"}, names)
	assert.True(t, conf.CustomDetectorRegistry.ShortCircuit())
	assert.Equal(t, []string{"always-noisy"}, conf.CustomDetectorRegistry.Excluded())

	keywords := conf.CustomDetectorRegistry.KeywordsForSource(sourcespb.SourceType_SOURCE_TYPE_FILESYSTEM)
	assert.ElementsMatch(t, []string{"hog"}, keywords, "repo-only is scoped away; always-noisy is excluded")
}

// Config without a custom detector policy keeps the previous behavior: every
// detector is registered with priority 0 and ordered by name.
func TestNewYAML_NoPolicyKeepsAllDetectors(t *testing.T) {
	input := []byte(`
detectors:
  - name: zeta
    keywords: [z]
    regex:
      token: '(z)'
  - name: alpha
    keywords: [a]
    regex:
      token: '(a)'
`)

	conf, err := NewYAML(input)
	require.NoError(t, err)
	require.Len(t, conf.Detectors, 2)
	assert.Equal(t, "alpha", conf.Detectors[0].(*custom_detectors.CustomRegexWebhook).GetName())
	assert.Equal(t, "zeta", conf.Detectors[1].(*custom_detectors.CustomRegexWebhook).GetName())
}

func TestNewYAML_RejectsInvalidCustomDetectorPolicy(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name: "duplicate names",
			input: `
detectors:
  - name: dup
    keywords: [a]
    regex:
      token: '(a)'
  - name: dup
    keywords: [b]
    regex:
      token: '(b)'
`,
			wantErr: `duplicate detector name`,
		},
		{
			name: "unknown exclusion",
			input: `
detectors:
  - name: real
    keywords: [a]
    regex:
      token: '(a)'
customDetectorPolicy:
  exclude: [ghost]
`,
			wantErr: "excluded detector is not registered",
		},
		{
			name: "precedence cycle",
			input: `
detectors:
  - name: a
    keywords: [a]
    regex:
      token: '(a)'
  - name: b
    keywords: [b]
    regex:
      token: '(b)'
customDetectorPolicy:
  precedence:
    - before: a
      after: b
    - before: b
      after: a
`,
			wantErr: "precedence cycle",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewYAML([]byte(tt.input))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}
