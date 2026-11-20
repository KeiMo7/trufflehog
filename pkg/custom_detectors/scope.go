package custom_detectors

import (
	"fmt"
	"sort"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
)

// sourceGroups maps the human-friendly source groups accepted in a custom
// detector's source_types field to the concrete source types they cover.
// A detector may also name a source type directly, with or without the
// SOURCE_TYPE_ prefix.
var sourceGroups = map[string][]sourcespb.SourceType{
	"repository": {
		sourcespb.SourceType_SOURCE_TYPE_GIT,
		sourcespb.SourceType_SOURCE_TYPE_PUBLIC_GIT,
		sourcespb.SourceType_SOURCE_TYPE_GITHUB,
		sourcespb.SourceType_SOURCE_TYPE_GITHUB_REALTIME,
		sourcespb.SourceType_SOURCE_TYPE_GITHUB_EXPERIMENTAL,
		sourcespb.SourceType_SOURCE_TYPE_GITHUB_UNAUTHENTICATED_ORG,
		sourcespb.SourceType_SOURCE_TYPE_GITLAB,
		sourcespb.SourceType_SOURCE_TYPE_BITBUCKET,
		sourcespb.SourceType_SOURCE_TYPE_GERRIT,
		sourcespb.SourceType_SOURCE_TYPE_AZURE_REPOS,
	},
	"filesystem": {
		sourcespb.SourceType_SOURCE_TYPE_FILESYSTEM,
	},
	"object_storage": {
		sourcespb.SourceType_SOURCE_TYPE_S3,
		sourcespb.SourceType_SOURCE_TYPE_S3_UNAUTHED,
		sourcespb.SourceType_SOURCE_TYPE_GCS,
		sourcespb.SourceType_SOURCE_TYPE_GCS_UNAUTHED,
		sourcespb.SourceType_SOURCE_TYPE_AZURE_STORAGE,
	},
}

// sourceGroupAliases lets users spell the groups the way they think of them.
var sourceGroupAliases = map[string]string{
	"repo":           "repository",
	"repos":          "repository",
	"repositories":   "repository",
	"vcs":            "repository",
	"fs":             "filesystem",
	"file":           "filesystem",
	"files":          "filesystem",
	"object-storage": "object_storage",
	"objectstorage":  "object_storage",
	"bucket":         "object_storage",
	"buckets":        "object_storage",
}

// SourceScope is the set of source types a custom detector is enabled for.
// The zero value covers every source type.
type SourceScope struct {
	all   bool
	types map[sourcespb.SourceType]struct{}
}

// AllSources returns a scope that includes every source type.
func AllSources() SourceScope { return SourceScope{all: true} }

// ParseSourceScope parses the source_types field of a custom detector.
// An empty list means every source type. Entries are case-insensitive and may
// be a group name ("repository", "filesystem", "object_storage"), a source
// type enum name ("S3" or "SOURCE_TYPE_S3"), or "all".
func ParseSourceScope(input []string) (SourceScope, error) {
	if len(input) == 0 {
		return AllSources(), nil
	}

	scope := SourceScope{types: make(map[sourcespb.SourceType]struct{}, len(input))}
	for _, entry := range input {
		name := strings.ToLower(strings.TrimSpace(entry))
		if name == "" {
			return SourceScope{}, fmt.Errorf("empty source type")
		}
		switch name {
		case "all", "*":
			scope.all = true
			continue
		}
		if canonical, ok := sourceGroupAliases[name]; ok {
			name = canonical
		}
		if group, ok := sourceGroups[name]; ok {
			for _, typ := range group {
				scope.types[typ] = struct{}{}
			}
			continue
		}

		enumName := strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
		if !strings.HasPrefix(enumName, "SOURCE_TYPE_") {
			enumName = "SOURCE_TYPE_" + enumName
		}
		value, ok := sourcespb.SourceType_value[enumName]
		if !ok {
			return SourceScope{}, fmt.Errorf("unknown source type %q", entry)
		}
		scope.types[sourcespb.SourceType(value)] = struct{}{}
	}

	if scope.all {
		return AllSources(), nil
	}
	return scope, nil
}

// Includes reports whether the scope covers the given source type. The zero
// SourceScope covers every source type, so a detector built without going
// through the constructor is never accidentally scoped away.
func (s SourceScope) Includes(sourceType sourcespb.SourceType) bool {
	if s.all || s.types == nil {
		return true
	}
	_, ok := s.types[sourceType]
	return ok
}

// IsAll reports whether the scope covers every source type.
func (s SourceScope) IsAll() bool { return s.all || s.types == nil }

// Types returns the covered source types. An all-source scope returns every
// source type known to the sourcespb package.
func (s SourceScope) Types() []sourcespb.SourceType {
	if s.IsAll() {
		types := make([]sourcespb.SourceType, 0, len(sourcespb.SourceType_name))
		for value := range sourcespb.SourceType_name {
			types = append(types, sourcespb.SourceType(value))
		}
		sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
		return types
	}
	types := make([]sourcespb.SourceType, 0, len(s.types))
	for typ := range s.types {
		types = append(types, typ)
	}
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
	return types
}

// Names returns the covered source types in sorted order. An all-source scope
// returns "all". It is used for diagnostics and tests.
func (s SourceScope) Names() []string {
	if s.IsAll() {
		return []string{"all"}
	}
	names := make([]string, 0, len(s.types))
	for typ := range s.types {
		names = append(names, typ.String())
	}
	sort.Strings(names)
	return names
}
