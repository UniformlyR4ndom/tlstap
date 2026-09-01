package tamper

import (
	"net/http"
	"strings"
	"testing"
)

// TestFramerScriptsAPI_EndToEnd mirrors TestScriptsAPI_EndToEnd, against the separate
// framer-scripts store nested at /framer/scripts, asserting the distinct
// "framer-script-updated" event rather than "script-updated".
func TestFramerScriptsAPI_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	ti, wsURL := newTestServerWithConfig(t, TamperConfig{FramerScriptsDir: dir})
	base := "http" + strings.TrimPrefix(wsURL, "ws") + "/api/i/tamper/framer/scripts"
	control := dialControl(t, ti, wsURL)

	resp := httpDo(t, http.MethodPut, base+"/foo", strings.NewReader("function frame(state, chunk) {}"))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT /framer/scripts/foo: expected 204, got %d", resp.StatusCode)
	}
	var updated framerScriptUpdatedMsg
	readJSON(t, control, &updated)
	if updated.Type != msgFramerScriptUpdated || updated.Name != "foo" {
		t.Fatalf("expected framer-script-updated for %q, got %+v", "foo", updated)
	}

	resp = httpDo(t, http.MethodGet, base+"/foo", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /framer/scripts/foo: expected 200, got %d", resp.StatusCode)
	}
	if body := string(readBody(t, resp)); body != "function frame(state, chunk) {}" {
		t.Fatalf("unexpected content: %s", body)
	}

	resp = httpDo(t, http.MethodDelete, base+"/foo", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /framer/scripts/foo: expected 204, got %d", resp.StatusCode)
	}
	readJSON(t, control, &updated)
	if updated.Type != msgFramerScriptUpdated || updated.Name != "foo" {
		t.Fatalf("expected framer-script-updated for %q, got %+v", "foo", updated)
	}
}

func TestFramerScriptsAPI_DisabledWithoutFramerScriptsDir(t *testing.T) {
	_, wsURL := newTestServerWithConfig(t, TamperConfig{})
	base := "http" + strings.TrimPrefix(wsURL, "ws") + "/api/i/tamper/framer/scripts"

	resp := httpDo(t, http.MethodGet, base, nil)
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("expected 501 when framer-scripts-dir isn't configured, got %d", resp.StatusCode)
	}
}

// TestFramerScriptsAPI_SeparateFromScripts confirms the two stores are independent: the
// same name in both is not a collision, and configuring one doesn't implicitly enable
// the other.
func TestFramerScriptsAPI_SeparateFromScripts(t *testing.T) {
	scriptsDir := t.TempDir()
	framerDir := t.TempDir()
	_, wsURL := newTestServerWithConfig(t, TamperConfig{ScriptsDir: scriptsDir, FramerScriptsDir: framerDir})
	scriptsBase := "http" + strings.TrimPrefix(wsURL, "ws") + "/api/i/tamper/scripts"
	framerBase := "http" + strings.TrimPrefix(wsURL, "ws") + "/api/i/tamper/framer/scripts"

	resp := httpDo(t, http.MethodPut, scriptsBase+"/shared", strings.NewReader("tamper.register('onReceive', () => {})"))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT /scripts/shared: expected 204, got %d", resp.StatusCode)
	}
	resp = httpDo(t, http.MethodPut, framerBase+"/shared", strings.NewReader("function frame(state, chunk) {}"))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT /framer/scripts/shared: expected 204, got %d", resp.StatusCode)
	}

	resp = httpDo(t, http.MethodGet, scriptsBase+"/shared", nil)
	if body := string(readBody(t, resp)); body != "tamper.register('onReceive', () => {})" {
		t.Fatalf("scripts/shared was overwritten by the framer store: %s", body)
	}
	resp = httpDo(t, http.MethodGet, framerBase+"/shared", nil)
	if body := string(readBody(t, resp)); body != "function frame(state, chunk) {}" {
		t.Fatalf("framer/scripts/shared was overwritten by the scripts store: %s", body)
	}
}
