package gcs

import (
	"errors"
	"fmt"
	"net"
	"net/url"

	"cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"

	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
)

// UnitErrorKind names the class of failure a unit hit, so a caller can tell a
// permission problem from a transient network one from a bad configuration
// without parsing an error string.
type UnitErrorKind string

const (
	// UnitErrorPermission means the credentials are not allowed to read the
	// bucket or its objects.
	UnitErrorPermission UnitErrorKind = "permission"
	// UnitErrorNetwork means the request failed in transit or the service was
	// temporarily unavailable, so retrying the unit may work.
	UnitErrorNetwork UnitErrorKind = "network"
	// UnitErrorConfig means the bucket or prefix does not exist or the request
	// is otherwise invalid for the configured target.
	UnitErrorConfig UnitErrorKind = "config"
)

// UnitError is the error a unit scan reports for a failure inside one unit.
//
// It deliberately does not unwrap to the underlying error: the raw error from
// the storage client can carry request URLs (which may embed an API key) and
// other internals that must not reach logs or the job report. Kind is the
// detail callers should switch on.
type UnitError struct {
	Kind   UnitErrorKind
	Op     string
	Bucket string
	Prefix string
	// code is the HTTP status code when the failure came from the API, kept for
	// debugging the classification without exposing the response body.
	code int
	err  error
}

// Error returns a message safe to log and to put in a report: the operation,
// the unit it happened in, and the class of failure. It never includes the
// underlying error text.
func (e *UnitError) Error() string {
	unit := fmt.Sprintf("bucket %q", sanitizer.UTF8(e.Bucket))
	if e.Prefix != "" {
		unit = fmt.Sprintf("bucket %q prefix %q", sanitizer.UTF8(e.Bucket), sanitizer.UTF8(e.Prefix))
	}
	if e.code != 0 {
		return fmt.Sprintf("gcs: %s %s: %s (http %d)", e.Op, unit, e.Kind, e.code)
	}
	return fmt.Sprintf("gcs: %s %s: %s", e.Op, unit, e.Kind)
}

// Unwrap reports the underlying cause for errors.Is checks, but the message
// above never prints it. Returning it keeps context cancellation and sentinel
// comparisons working for code that inspects the chain.
func (e *UnitError) Unwrap() error { return e.err }

// classifyUnitError turns a storage client error into a UnitError. Errors that
// look transient are classed as network so a unit that failed because of them
// is retried rather than treated as permanently done.
func classifyUnitError(err error, op, bucket, prefix string) *UnitError {
	if err == nil {
		return nil
	}

	unitErr := &UnitError{Kind: UnitErrorNetwork, Op: op, Bucket: bucket, Prefix: prefix, err: err}

	// A storage sentinel that already names the cause is the clearest signal.
	if errors.Is(err, storage.ErrBucketNotExist) || errors.Is(err, storage.ErrObjectNotExist) {
		unitErr.Kind = UnitErrorConfig
		return unitErr
	}

	var apiErr *googleapi.Error
	if errors.As(err, &apiErr) {
		unitErr.code = apiErr.Code
		switch {
		case apiErr.Code == 401 || apiErr.Code == 403:
			unitErr.Kind = UnitErrorPermission
		case apiErr.Code == 404:
			unitErr.Kind = UnitErrorConfig
		case apiErr.Code == 408 || apiErr.Code == 429 || (apiErr.Code >= 500 && apiErr.Code < 600):
			unitErr.Kind = UnitErrorNetwork
		default:
			// Any other 4xx is a request we built wrong for this target, e.g. a
			// malformed bucket name.
			unitErr.Kind = UnitErrorConfig
		}
		return unitErr
	}

	var netErr net.Error
	var urlErr *url.Error
	switch {
	case errors.As(err, &netErr), errors.As(err, &urlErr), errors.Is(err, net.ErrClosed):
		unitErr.Kind = UnitErrorNetwork
	default:
		// Unknown failures are treated as network so the unit is retried rather
		// than silently considered complete.
		unitErr.Kind = UnitErrorNetwork
	}
	return unitErr
}

// unitErrorKind returns the class of err if it is (or wraps) a UnitError, and
// false otherwise.
func unitErrorKind(err error) (UnitErrorKind, bool) {
	var unitErr *UnitError
	if errors.As(err, &unitErr) {
		return unitErr.Kind, true
	}
	return "", false
}
