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
func ScrubCredentials(resp *http.Response, credentials map[string]string) error {
	if len(credentials) == 0 {
		return nil
	}

	// Build a strings.NewReplacer for efficient multi-pattern replacement.
	pairs := make([]string, 0, len(credentials)*2)
	for realVal, placeholder := range credentials {
		pairs = append(pairs, realVal, placeholder)
	}
	r := strings.NewReplacer(pairs...)

	// Read the entire response body.
	if resp.Body == nil {
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	// Replace real credential values with placeholders.
	scrubbed := r.Replace(string(body))
	scrubbedBytes := []byte(scrubbed)

	// Reset body and update Content-Length.
	resp.Body = io.NopCloser(bytes.NewReader(scrubbedBytes))
	resp.ContentLength = int64(len(scrubbedBytes))
	resp.Header.Set("Content-Length", strconv.Itoa(len(scrubbedBytes)))

	return nil
}
