package gcs

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// fakeObject is one object served by fakeGCSServer.
type fakeObject struct {
	// content is the object body. Two objects with the same content are the
	// same content for the source's deduplication.
	content string
	// size overrides the reported size, so a test can make an object look empty
	// or too large without changing what the handler would return.
	size int64
	// readStatus, when non-zero, makes a Get of this object fail with that HTTP
	// status instead of returning the body.
	readStatus int
}

// fakeBucket is one bucket served by fakeGCSServer.
type fakeBucket struct {
	objects map[string]fakeObject
	// listStatus, when non-zero, makes every object listing of the bucket fail
	// with that HTTP status.
	listStatus int
}

// fakeGCSServer serves the parts of the GCS JSON API the source uses against
// several buckets, so tests can exercise enumeration and per-unit scanning
// without real GCP access.
type fakeGCSServer struct {
	mu      sync.Mutex
	buckets map[string]fakeBucket
	// listBuckets, when non-nil, is the exact bucket list the project endpoint
	// returns. When nil, every non-excluded bucket is returned.
	listBuckets []string
	listErr     int
	requests    []string
}

func newFakeGCSServer(t *testing.T, buckets map[string]fakeBucket) (*fakeGCSServer, *httptest.Server) {
	t.Helper()
	f := &fakeGCSServer{buckets: buckets}
	srv := httptest.NewServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(srv.Close)
	t.Setenv("STORAGE_EMULATOR_HOST", srv.Listener.Addr().String())
	return f, srv
}

// listCalls returns how many object-listing requests the server has served.
func (f *fakeGCSServer) listCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, req := range f.requests {
		if strings.Contains(req, "/o?") {
			n++
		}
	}
	return n
}

func (f *fakeGCSServer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
	f.mu.Unlock()
	const listPrefix = "/storage/v1/b/"
	switch {
	case r.URL.Path == "/storage/v1/b":
		f.serveBucketList(w, r)
	case strings.HasPrefix(r.URL.Path, listPrefix) && strings.HasSuffix(r.URL.Path, "/o"):
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, listPrefix), "/o")
		f.serveObjectList(w, r, name)
	case strings.HasPrefix(r.URL.Path, listPrefix) && strings.Contains(r.URL.Path, "/o/"):
		name := strings.TrimPrefix(r.URL.Path, listPrefix)
		bucket, key, _ := strings.Cut(name, "/o/")
		f.serveObject(w, r, bucket, key)
	case strings.HasPrefix(r.URL.Path, "/"):
		// Media download: /<bucket>/<key>.
		bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
		f.serveMedia(w, r, bucket, key)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeGCSServer) serveBucketList(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	listErr := f.listErr
	names := append([]string(nil), f.listBuckets...)
	if names == nil {
		for name := range f.buckets {
			names = append(names, name)
		}
	}
	f.mu.Unlock()

	if listErr != 0 {
		writeGoogleError(w, listErr, "listing buckets failed")
		return
	}
	sort.Strings(names)
	items := make([]map[string]any, 0, len(names))
	for _, name := range names {
		items = append(items, map[string]any{"name": name})
	}
	writeJSON(w, map[string]any{"items": items})
}

func (f *fakeGCSServer) serveObjectList(w http.ResponseWriter, r *http.Request, bucket string) {
	f.mu.Lock()
	bkt, ok := f.buckets[bucket]
	listErr := bkt.listStatus
	f.mu.Unlock()

	if !ok {
		writeGoogleError(w, http.StatusNotFound, "no such bucket")
		return
	}
	if listErr != 0 {
		writeGoogleError(w, listErr, "listing objects failed")
		return
	}

	prefix := r.URL.Query().Get("prefix")
	pageToken := r.URL.Query().Get("pageToken")

	keys := make([]string, 0, len(bkt.objects))
	for key := range bkt.objects {
		if strings.HasPrefix(key, prefix) && key > pageToken {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)

	// Two per page so paging and streaming are both exercised.
	const pageSize = 2
	truncated := len(keys) > pageSize
	if truncated {
		keys = keys[:pageSize]
	}

	items := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		obj := bkt.objects[key]
		items = append(items, objectAttrs(bucket, key, obj))
	}
	resp := map[string]any{"items": items}
	if truncated {
		resp["nextPageToken"] = keys[len(keys)-1]
	}
	writeJSON(w, resp)
}

func (f *fakeGCSServer) serveObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	f.mu.Lock()
	bkt, ok := f.buckets[bucket]
	obj, okObj := bkt.objects[key]
	f.mu.Unlock()

	if !ok || !okObj {
		writeGoogleError(w, http.StatusNotFound, "no such object")
		return
	}
	writeJSON(w, objectAttrs(bucket, key, obj))
}

func (f *fakeGCSServer) serveMedia(w http.ResponseWriter, r *http.Request, bucket, key string) {
	f.mu.Lock()
	bkt, ok := f.buckets[bucket]
	obj, okObj := bkt.objects[key]
	f.mu.Unlock()

	if !ok || !okObj {
		writeGoogleError(w, http.StatusNotFound, "no such object")
		return
	}
	if obj.readStatus != 0 {
		writeGoogleError(w, obj.readStatus, "read failed")
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(obj.content)))
	_, _ = w.Write([]byte(obj.content))
}

func objectAttrs(bucket, key string, obj fakeObject) map[string]any {
	content := obj.content
	size := obj.size
	if size == 0 && content != "" {
		size = int64(len(content))
	}
	sum := md5Sum(content)
	return map[string]any{
		"name":        key,
		"bucket":      bucket,
		"size":        strconv.FormatInt(size, 10),
		"md5Hash":     base64.StdEncoding.EncodeToString(sum[:]),
		"contentType": "text/plain",
	}
}

func md5Sum(content string) [md5.Size]byte {
	return md5.Sum([]byte(content))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// writeGoogleError writes an error body in the shape googleapi.Error decodes, so
// the client sees the intended status code.
func writeGoogleError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
}

// newUnitTestSource initializes a source against the fake server. It uses
// unauthenticated credentials, which the fake accepts for every bucket.
func newUnitTestSource(t *testing.T, conn *sourcespb.GCS) *Source {
	t.Helper()
	if conn.Credential == nil {
		conn.Credential = &sourcespb.GCS_Unauthenticated{}
	}
	anyConn, err := anypb.New(conn)
	require.NoError(t, err)

	s := &Source{}
	require.NoError(t, s.Init(context.Background(), "gcs unit test", 1, 1, false, anyConn, 2))
	return s
}

// listedUnits enumerates the source and returns the units it reported, sorted
// by ID, failing the test if enumeration reports an error.
func listedUnits(t *testing.T, s *Source) []string {
	t.Helper()
	reporter := unitCollector{}
	require.NoError(t, s.Enumerate(context.Background(), &reporter))
	require.Empty(t, reporter.errs)
	return reporter.ids()
}

// unitCollector is a UnitReporter that records the units it is given.
type unitCollector struct {
	units []GCSObjectUnit
	errs  []error
}

func (c *unitCollector) UnitOk(_ context.Context, unit sources.SourceUnit) error {
	gcsUnit, ok := unit.(GCSObjectUnit)
	if !ok {
		return fmt.Errorf("unexpected unit type %T", unit)
	}
	c.units = append(c.units, gcsUnit)
	return nil
}

func (c *unitCollector) UnitErr(_ context.Context, err error) error {
	c.errs = append(c.errs, err)
	return nil
}

// ids returns the units' IDs, sorted so comparisons ignore enumeration order.
func (c *unitCollector) ids() []string {
	ids := make([]string, 0, len(c.units))
	for _, unit := range c.units {
		id, _ := unit.SourceUnitID()
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// objectListCalls returns how many object-listing requests the server has
// served, across all buckets.
func (f *fakeGCSServer) objectListCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, req := range f.requests {
		if strings.Contains(req, "/o?") || strings.HasSuffix(req, "/o") {
			n++
		}
	}
	return n
}

// setReadStatus changes whether a Get of the given object fails, so a test can
// make a failing object readable between runs.
func (f *fakeGCSServer) setReadStatus(bucket, key string, status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	bkt := f.buckets[bucket]
	obj := bkt.objects[key]
	obj.readStatus = status
	bkt.objects[key] = obj
	f.buckets[bucket] = bkt
}
