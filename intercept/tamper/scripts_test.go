package tamper

import (
	"net/http"
	"strings"
	"testing"
)

// TestScriptsAPI_EndToEnd is a smoke test that tamper wires scriptstore.RegisterRoutes
// correctly at its own basePath and pushes a "script-updated" control event on PUT/DELETE
// (the one piece of behavior scriptstore itself knows nothing about). Exhaustive REST
// behavior (404/400/atomic writes/listing) is covered by scriptstore's own tests.
func TestScriptsAPI_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	ti, wsURL := newTestServerWithConfig(t, TamperConfig{ScriptsDir: dir})
	base := "http" + strings.TrimPrefix(wsURL, "ws") + "/api/i/tamper/scripts"
	control := dialControl(t, ti, wsURL)

	resp := httpDo(t, http.MethodPut, base+"/foo", strings.NewReader("console.log(1)"))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT /scripts/foo: expected 204, got %d", resp.StatusCode)
	}
	var updated scriptUpdatedMsg
	readJSON(t, control, &updated)
	if updated.Type != msgScriptUpdated || updated.Name != "foo" {
		t.Fatalf("expected script-updated for %q, got %+v", "foo", updated)
	}

	resp = httpDo(t, http.MethodGet, base+"/foo", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /scripts/foo: expected 200, got %d", resp.StatusCode)
	}
	if body := string(readBody(t, resp)); body != "console.log(1)" {
		t.Fatalf("unexpected content: %s", body)
	}

	resp = httpDo(t, http.MethodDelete, base+"/foo", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /scripts/foo: expected 204, got %d", resp.StatusCode)
	}
	readJSON(t, control, &updated)
	if updated.Type != msgScriptUpdated || updated.Name != "foo" {
		t.Fatalf("expected script-updated for %q, got %+v", "foo", updated)
	}
}

func TestScriptsAPI_DisabledWithoutScriptsDir(t *testing.T) {
	_, wsURL := newTestServerWithConfig(t, TamperConfig{})
	base := "http" + strings.TrimPrefix(wsURL, "ws") + "/api/i/tamper/scripts"

	resp := httpDo(t, http.MethodGet, base, nil)
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("expected 501 when scripts-dir isn't configured, got %d", resp.StatusCode)
	}
}
