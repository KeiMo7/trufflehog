package verificationcache

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

var (
	explicitStatusCodePattern = regexp.MustCompile(`(?i)(?:http(?:\s+response)?(?:\s+status)?|status(?:\s+code)?|response(?:\s+status)?)[^0-9]{0,12}([1-5][0-9]{2})\b`)
	anyStatusCodePattern      = regexp.MustCompile(`\b([1-5][0-9]{2})\b`)
)

// StatusCodeError allows detectors to report structured HTTP status information instead of relying on error text.
type StatusCodeError interface {
	StatusCode() int
}

func statusCodeFromError(err error) int {
	if err == nil {
		return 0
	}
	var coded StatusCodeError
	if errors.As(err, &coded) {
		return coded.StatusCode()
	}
	msg := err.Error()
	if match := explicitStatusCodePattern.FindStringSubmatch(msg); len(match) == 2 {
		code, _ := strconv.Atoi(match[1])
		return code
	}
	if match := anyStatusCodePattern.FindStringSubmatch(msg); len(match) == 2 {
		code, _ := strconv.Atoi(match[1])
		return code
	}
	return 0
}

func resultStatusCode(result *detectors.Result, err error) int {
	if result != nil && result.VerificationStatusCode > 0 {
		return result.VerificationStatusCode
	}
	return statusCodeFromError(err)
}

func classifyVerification(result *detectors.Result) (status detectors.VerificationStatus, code int, rateLimited bool) {
	err := result.VerificationError()
	code = resultStatusCode(result, err)

	if result.Verified {
		if code == 0 {
			// A successful verifier did receive a successful response; HTTP-based detectors rarely expose the 2xx
			// status directly, so record the conventional success code for the audit trail.
			code = 200
		}
		return detectors.VerificationStatusValid, code, false
	}
	if err == nil {
		return detectors.VerificationStatusInvalid, 0, false
	}

	switch {
	case code == 429:
		return detectors.VerificationStatusUnverified, code, true
	case code == 408, code == 425, code >= 500 && code <= 599:
		return detectors.VerificationStatusUnverified, code, false
	case code == 0:
		return detectors.VerificationStatusUnverified, code, false
	case code == 400, code == 401, code == 402, code == 403, code == 409, code == 410, code == 422:
		return detectors.VerificationStatusInvalid, code, false
	default:
		return detectors.VerificationStatusUnverified, code, false
	}
}

func pendingRateLimitError(attempts int) error {
	return fmt.Errorf("verification remained rate limited after %d attempt(s); pending manual confirmation", attempts)
}
