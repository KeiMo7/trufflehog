package gcs

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/api/googleapi"
)

func TestClassifyUnitError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want UnitErrorKind
	}{
		{name: "forbidden", err: &googleapi.Error{Code: 403}, want: UnitErrorPermission},
		{name: "unauthorized", err: &googleapi.Error{Code: 401}, want: UnitErrorPermission},
		{name: "not found", err: &googleapi.Error{Code: 404}, want: UnitErrorConfig},
		{name: "bad request", err: &googleapi.Error{Code: 400}, want: UnitErrorConfig},
		{name: "server error", err: &googleapi.Error{Code: 500}, want: UnitErrorNetwork},
		{name: "throttled", err: &googleapi.Error{Code: 429}, want: UnitErrorNetwork},
		{name: "url error", err: &url.Error{Op: "get", URL: "x", Err: errors.New("boom")}, want: UnitErrorNetwork},
		{name: "net error", err: &net.OpError{Op: "dial", Err: errors.New("refused")}, want: UnitErrorNetwork},
		{name: "unknown", err: errors.New("something"), want: UnitErrorNetwork},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyUnitError(tt.err, "op", "bucket", "prefix/")
			assert.Equal(t, tt.want, got.Kind)
			// The class is stable through the reported error chain.
			kind, ok := unitErrorKind(got)
			assert.True(t, ok)
			assert.Equal(t, tt.want, kind)
		})
	}
}

// A classified error's message names the unit and the failure class but never
// the raw cause, which can carry a request URL with an API key or a response
// body.
func TestUnitErrorDoesNotLeakCause(t *testing.T) {
	const secret = "super-secret-api-key"
	raw := fmt.Errorf("request to https://storage.googleapis.com?key=%s failed", secret)

	err := classifyUnitError(&googleapi.Error{Code: 403, Message: secret}, "list objects", "bucket", "p/")
	assert.NotContains(t, err.Error(), secret)
	assert.Contains(t, err.Error(), "permission")
	assert.Contains(t, err.Error(), "bucket")

	// A wrapped raw error likewise does not appear in the message.
	err = classifyUnitError(raw, "read object", "bucket", "")
	assert.NotContains(t, err.Error(), secret)
}
