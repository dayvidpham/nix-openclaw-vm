package proxy

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func newResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode:    statusCode,
		Header:        http.Header{"Content-Length": []string{strconv.Itoa(len(body))}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

func readResponseBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	if resp.Body == nil {
		return ""
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return string(b)
}

func TestScrubCredentials_JSON(t *testing.T) {
	realKey := "sk-ant-api03-real-secret-key-abc123"
	body := `{"response":"your key is ` + realKey + `"}`
	resp := newResponse(200, body)

	err := ScrubCredentials(resp, map[string]string{
		realKey: testPlaceholder,
	})
	if err != nil {
		t.Fatalf("ScrubCredentials: %v", err)
	}

	got := readResponseBody(t, resp)
	want := `{"response":"your key is ` + testPlaceholder + `"}`
	if got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestScrubCredentials_Plaintext(t *testing.T) {
	realKey := "ghp_1234567890abcdef"
	body := "Your token is: " + realKey + "\n"
	resp := newResponse(200, body)

	err := ScrubCredentials(resp, map[string]string{
		realKey: testPlaceholder,
	})
	if err != nil {
		t.Fatalf("ScrubCredentials: %v", err)
	}

	got := readResponseBody(t, resp)
	want := "Your token is: " + testPlaceholder + "\n"
	if got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestScrubCredentials_EmptyMap(t *testing.T) {
	body := `{"data":"untouched"}`
	resp := newResponse(200, body)

	err := ScrubCredentials(resp, map[string]string{})
	if err != nil {
		t.Fatalf("ScrubCredentials: %v", err)
	}

	// Body should be unchanged — ScrubCredentials returns early for empty map.
	got := readResponseBody(t, resp)
	if got != body {
		t.Errorf("body = %q, want %q", got, body)
	}
}

func TestScrubCredentials_NilBody(t *testing.T) {
	resp := &http.Response{
		StatusCode: 204,
		Header:     http.Header{},
		Body:       nil,
	}

	err := ScrubCredentials(resp, map[string]string{
		"some-secret": testPlaceholder,
	})
	if err != nil {
		t.Fatalf("ScrubCredentials with nil body: %v", err)
	}
}

func TestScrubCredentials_MultipleCredentials(t *testing.T) {
	realKey1 := "sk-secret-key-one"
	realKey2 := "ghp-secret-key-two"
	body := `key1=` + realKey1 + `&key2=` + realKey2
	resp := newResponse(200, body)

	err := ScrubCredentials(resp, map[string]string{
		realKey1: testPlaceholder,
		realKey2: testPlaceholder2,
	})
	if err != nil {
		t.Fatalf("ScrubCredentials: %v", err)
	}

	got := readResponseBody(t, resp)
	if !strings.Contains(got, testPlaceholder) {
		t.Errorf("expected body to contain %s, got %q", testPlaceholder, got)
	}
	if !strings.Contains(got, testPlaceholder2) {
		t.Errorf("expected body to contain %s, got %q", testPlaceholder2, got)
	}
	if strings.Contains(got, realKey1) {
		t.Errorf("body still contains real key1: %q", got)
	}
	if strings.Contains(got, realKey2) {
		t.Errorf("body still contains real key2: %q", got)
	}
}

func TestScrubCredentials_ContentLengthUpdated(t *testing.T) {
	// Real key is shorter than placeholder, so Content-Length should increase.
	realKey := "short"
	body := `value=` + realKey
	resp := newResponse(200, body)

	err := ScrubCredentials(resp, map[string]string{
		realKey: testPlaceholder,
	})
	if err != nil {
		t.Fatalf("ScrubCredentials: %v", err)
	}

	got := readResponseBody(t, resp)
	wantBody := `value=` + testPlaceholder
	if got != wantBody {
		t.Errorf("body = %q, want %q", got, wantBody)
	}

	// Verify Content-Length header matches actual body length.
	wantLen := len(wantBody)
	if resp.ContentLength != int64(wantLen) {
		t.Errorf("ContentLength = %d, want %d", resp.ContentLength, wantLen)
	}
	if cl := resp.Header.Get("Content-Length"); cl != strconv.Itoa(wantLen) {
		t.Errorf("Content-Length header = %q, want %q", cl, strconv.Itoa(wantLen))
	}
}
