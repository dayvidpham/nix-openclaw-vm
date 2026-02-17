package proxy

import (
	"bytes"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// placeholderPattern matches agent-vault placeholder tokens (UUID v4 format).
var placeholderPattern = regexp.MustCompile(`agent-vault-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`)

// MaxBodyBytes is the maximum bytes read from a request or response body.
// Gateway initialization should set this from Config.MaxBodySize. The default
// (10 MiB) applies when the proxy package is used without explicit configuration.
var MaxBodyBytes int64 = 10 * 1024 * 1024

// Extract finds all unique placeholder tokens in the request's headers, query
// parameters, and body. The returned slice contains no duplicates.
func Extract(req *http.Request) ([]string, error) {
	seen := make(map[string]struct{})

	// Scan header values.
	for _, vals := range req.Header {
		for _, v := range vals {
			for _, m := range placeholderPattern.FindAllString(v, -1) {
				seen[m] = struct{}{}
			}
		}
	}

	// Scan URL query parameters.
	for _, vals := range req.URL.Query() {
		for _, v := range vals {
			for _, m := range placeholderPattern.FindAllString(v, -1) {
				seen[m] = struct{}{}
			}
		}
	}

	// Scan body (if present). We read up to MaxBodyBytes, scan it, then reset it
	// so downstream consumers can still read it.
	if req.Body != nil && req.Body != http.NoBody {
		body, err := io.ReadAll(io.LimitReader(req.Body, MaxBodyBytes))
		if err != nil {
			return nil, err
		}
		req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(body))

		for _, m := range placeholderPattern.FindAllString(string(body), -1) {
			seen[m] = struct{}{}
		}
	}

	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	return out, nil
}

// ReplaceInRequest substitutes placeholder tokens with real credential values
// throughout the request's headers, query parameters, and body.
// The replacements map is keyed by placeholder → real value.
func ReplaceInRequest(req *http.Request, replacements map[string]string) error {
	if len(replacements) == 0 {
		return nil
	}

	// Build a strings.NewReplacer for single-pass replacement (prevents
	// double-substitution when a replacement value happens to contain
	// another placeholder).
	pairs := make([]string, 0, len(replacements)*2)
	for placeholder, real := range replacements {
		pairs = append(pairs, placeholder, real)
	}
	r := strings.NewReplacer(pairs...)

	// Replace in headers.
	for key, vals := range req.Header {
		for i, v := range vals {
			req.Header[key][i] = r.Replace(v)
		}
	}

	// Replace in URL query parameters.
	q := req.URL.Query()
	changed := false
	for key, vals := range q {
		for i, v := range vals {
			replaced := r.Replace(v)
			if replaced != v {
				q[key][i] = replaced
				changed = true
			}
		}
	}
	if changed {
		req.URL.RawQuery = q.Encode()
	}

	// Replace in body.
	if req.Body != nil && req.Body != http.NoBody {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return err
		}
		req.Body.Close()

		replaced := []byte(r.Replace(string(body)))
		req.Body = io.NopCloser(bytes.NewReader(replaced))
		req.ContentLength = int64(len(replaced))
		req.Header.Set("Content-Length", strconv.Itoa(len(replaced)))
	}

	return nil
}
