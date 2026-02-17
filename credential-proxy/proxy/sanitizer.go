package proxy

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// ScrubCredentials replaces real credential values in the response body with
// their corresponding placeholder tokens. This prevents credential leakage
// in responses forwarded back to the agent.
//
// The credentials map is keyed as realValue → placeholder (the reverse of the
// injection mapping).
//
// The response body is fully read, scrubbed, and replaced with a new reader.
// Content-Length is updated to reflect the scrubbed body size.
//
// The returned int is the total number of actual replacements made across all
// credential values (not the number of map entries).
func ScrubCredentials(resp *http.Response, credentials map[string]string) (int, error) {
	if len(credentials) == 0 {
		return 0, nil
	}

	// Read up to MaxBodyBytes from the response body.
	if resp.Body == nil {
		return 0, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	if err != nil {
		return 0, err
	}
	resp.Body.Close()

	// Count actual occurrences and replace. strings.NewReplacer does not expose
	// a replacement count, so we use strings.Count + strings.ReplaceAll instead.
	scrubbed := string(body)
	count := 0
	for realVal, placeholder := range credentials {
		n := strings.Count(scrubbed, realVal)
		count += n
		if n > 0 {
			scrubbed = strings.ReplaceAll(scrubbed, realVal, placeholder)
		}
	}

	scrubbedBytes := []byte(scrubbed)

	// Reset body and update Content-Length.
	resp.Body = io.NopCloser(bytes.NewReader(scrubbedBytes))
	resp.ContentLength = int64(len(scrubbedBytes))
	resp.Header.Set("Content-Length", strconv.Itoa(len(scrubbedBytes)))

	return count, nil
}
