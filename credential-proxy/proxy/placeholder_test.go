package proxy

import (
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const testPlaceholder = "agent-vault-deadbeef-1234-5678-9abc-def012345678"
const testPlaceholder2 = "agent-vault-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

func newRequestWithBody(method, target, body string) *http.Request {
	req, _ := http.NewRequest(method, target, strings.NewReader(body))
	return req
}

func readBody(t *testing.T, body io.ReadCloser) string {
	t.Helper()
	if body == nil {
		return ""
	}
	b, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

func TestExtract_Header(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Api-Key", testPlaceholder)

	got, err := Extract(req)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(got) != 1 || got[0] != testPlaceholder {
		t.Errorf("got %v, want [%s]", got, testPlaceholder)
	}
}

func TestExtract_Body(t *testing.T) {
	body := `{"api_key":"` + testPlaceholder + `"}`
	req := newRequestWithBody("POST", "http://example.com", body)

	got, err := Extract(req)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(got) != 1 || got[0] != testPlaceholder {
		t.Errorf("got %v, want [%s]", got, testPlaceholder)
	}

	// Body should still be readable after Extract.
	remaining := readBody(t, req.Body)
	if remaining != body {
		t.Errorf("body not preserved: got %q", remaining)
	}
}

func TestExtract_QueryParams(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com?token="+testPlaceholder, nil)

	got, err := Extract(req)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(got) != 1 || got[0] != testPlaceholder {
		t.Errorf("got %v, want [%s]", got, testPlaceholder)
	}
}

func TestExtract_Deduplication(t *testing.T) {
	// Same placeholder in both header and body.
	body := `{"key":"` + testPlaceholder + `"}`
	req := newRequestWithBody("POST", "http://example.com", body)
	req.Header.Set("Authorization", "Bearer "+testPlaceholder)

	got, err := Extract(req)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("expected 1 deduplicated result, got %d: %v", len(got), got)
	}
}

func TestExtract_MultipleDifferent(t *testing.T) {
	body := `{"a":"` + testPlaceholder + `","b":"` + testPlaceholder2 + `"}`
	req := newRequestWithBody("POST", "http://example.com", body)

	got, err := Extract(req)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 results, got %d: %v", len(got), got)
	}
	sort.Strings(got)
	want := []string{testPlaceholder2, testPlaceholder}
	sort.Strings(want)
	if got[0] != want[0] || got[1] != want[1] {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestExtract_NoMatches(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Custom", "no-placeholder-here")

	got, err := Extract(req)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty slice, got %v", got)
	}
}

func TestReplaceInRequest_Headers(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Api-Key", testPlaceholder)

	err := ReplaceInRequest(req, map[string]string{
		testPlaceholder: "sk-real-secret-key",
	})
	if err != nil {
		t.Fatalf("ReplaceInRequest: %v", err)
	}
	if got := req.Header.Get("X-Api-Key"); got != "sk-real-secret-key" {
		t.Errorf("header = %q, want %q", got, "sk-real-secret-key")
	}
}

func TestReplaceInRequest_Body(t *testing.T) {
	body := `{"api_key":"` + testPlaceholder + `"}`
	req := newRequestWithBody("POST", "http://example.com", body)

	err := ReplaceInRequest(req, map[string]string{
		testPlaceholder: "sk-real-key",
	})
	if err != nil {
		t.Fatalf("ReplaceInRequest: %v", err)
	}

	got := readBody(t, req.Body)
	want := `{"api_key":"sk-real-key"}`
	if got != want {
		t.Errorf("body = %q, want %q", got, want)
	}

	// Content-Length must be updated.
	wantLen := strconv.Itoa(len(want))
	if req.ContentLength != int64(len(want)) {
		t.Errorf("ContentLength = %d, want %d", req.ContentLength, len(want))
	}
	if cl := req.Header.Get("Content-Length"); cl != wantLen {
		t.Errorf("Content-Length header = %q, want %q", cl, wantLen)
	}
}

func TestReplaceInRequest_QueryParams(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com/api?token="+testPlaceholder+"&other=keep", nil)

	err := ReplaceInRequest(req, map[string]string{
		testPlaceholder: "real-token-value",
	})
	if err != nil {
		t.Fatalf("ReplaceInRequest: %v", err)
	}

	q, _ := url.ParseQuery(req.URL.RawQuery)
	if got := q.Get("token"); got != "real-token-value" {
		t.Errorf("query token = %q, want %q", got, "real-token-value")
	}
	if got := q.Get("other"); got != "keep" {
		t.Errorf("query other = %q, want %q", got, "keep")
	}
}

func TestReplaceInRequest_EmptyMap(t *testing.T) {
	body := `{"key":"value"}`
	req := newRequestWithBody("POST", "http://example.com", body)

	err := ReplaceInRequest(req, map[string]string{})
	if err != nil {
		t.Fatalf("ReplaceInRequest: %v", err)
	}

	// Body should be unchanged (and still readable).
	got := readBody(t, req.Body)
	if got != body {
		t.Errorf("body = %q, want %q", got, body)
	}
}
