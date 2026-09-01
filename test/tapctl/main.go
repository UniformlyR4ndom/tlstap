// tapctl is a one-shot test/debug client for tlstap interceptors that expose an API
// (currently tamper's control/watch WebSocket API and dbdump's REST/WebSocket API).
// Each subcommand opens a fresh connection, performs one action, prints JSON to
// stdout, and exits — no persistent connection is needed for any of them (see
// CLAUDE.md's "tamper Interceptor" section for why that's true even for tamper's
// hold/resolve workflow).
//
// Usage: tapctl <group> <command> [flags]; groups: tamper, dbdump, core.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/websocket"
)

const defaultAPI = "http://127.0.0.1:9090"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "tamper":
		tamperMain(os.Args[2:])
	case "dbdump":
		dbdumpMain(os.Args[2:])
	case "core":
		coreMain(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown group: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `tapctl - one-shot test client for tlstap interceptor APIs

Usage:
  tapctl tamper <command> [flags]
  tapctl dbdump <command> [flags]
  tapctl core <command> [flags]

Run "tapctl tamper help", "tapctl dbdump help", or "tapctl core help" for that group's
commands.

--api defaults to `+defaultAPI+` and is treated as the API server root (canonical
/api/i/<name>/... paths are used, i.e. single-proxy usage) in every command.
`)
}

// --- flag helpers ---

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// flagWasSet reports whether name was explicitly passed on the command line, as
// opposed to just holding its zero-value default. Used for every required numeric
// flag (--conn, --session, --stream, --id, --direction, ...): several of these (e.g. a
// ConnID) are legitimately 0, so a bare "!= 0" check would wrongly reject valid input
// — exactly the bug that shipped in tamper's --conn handling before being fixed.
func flagWasSet(fs *flag.FlagSet, name string) bool {
	var set bool
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

// --- output helpers ---

func printJSON(v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fail("marshal output: %v", err)
	}
	fmt.Println(string(b))
}

// printRawJSON re-indents already-well-formed JSON bytes (an API response passed
// straight through) rather than decoding and re-marshaling, which would lose the
// server's original key order for no benefit.
func printRawJSON(data []byte) {
	var buf bytes.Buffer
	if err := json.Indent(&buf, data, "", "  "); err != nil {
		fail("invalid JSON response: %v", err)
	}
	fmt.Println(buf.String())
}

// --- WebSocket helpers ---

func wsBase(apiBase string) (string, error) {
	switch {
	case strings.HasPrefix(apiBase, "http://"):
		return "ws://" + strings.TrimPrefix(apiBase, "http://"), nil
	case strings.HasPrefix(apiBase, "https://"):
		return "wss://" + strings.TrimPrefix(apiBase, "https://"), nil
	case strings.HasPrefix(apiBase, "ws://"), strings.HasPrefix(apiBase, "wss://"):
		return apiBase, nil
	default:
		return "", fmt.Errorf("--api must start with http://, https://, ws://, or wss://, got %q", apiBase)
	}
}

// dialWS upgrades a connection to path (which may include a query string), e.g.
// dialWS(api, "/api/i/tamper/control") or dialWS(api, "/api/i/dbdump/stid-stream").
func dialWS(apiBase, path string) (*websocket.Conn, error) {
	base, err := wsBase(apiBase)
	if err != nil {
		return nil, err
	}
	target := strings.TrimSuffix(base, "/") + path
	conn, _, err := websocket.DefaultDialer.Dial(target, nil)
	return conn, err
}

// --- HTTP helpers (dbdump's REST endpoints) ---

// apiError is the {"error": "..."} shape every dbdump REST endpoint returns on failure.
type apiError struct {
	Error string `json:"error"`
}

func checkHTTPError(resp *http.Response, data []byte) error {
	if resp.StatusCode < 400 {
		return nil
	}
	var e apiError
	if json.Unmarshal(data, &e) == nil && e.Error != "" {
		return fmt.Errorf("%s (status %d)", e.Error, resp.StatusCode)
	}
	return fmt.Errorf("request failed with status %d", resp.StatusCode)
}

func httpGet(apiBase, path string) ([]byte, error) {
	resp, err := http.Get(strings.TrimSuffix(apiBase, "/") + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return data, checkHTTPError(resp, data)
}

func httpPostJSON(apiBase, path string, reqBody any) ([]byte, error) {
	b, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}
	resp, err := http.Post(strings.TrimSuffix(apiBase, "/")+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return data, checkHTTPError(resp, data)
}

// httpPostRaw is like httpPostJSON but returns the raw *http.Response for callers that
// need to inspect headers (the /chunk endpoint's multipart response).
func httpPostRaw(apiBase, path string, reqBody any) (*http.Response, error) {
	b, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}
	resp, err := http.Post(strings.TrimSuffix(apiBase, "/")+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return nil, checkHTTPError(resp, data)
	}
	return resp, nil
}

// httpSendRaw sends a request with a raw (non-JSON) body via the given method and
// returns the raw response body — used by REST endpoints whose request content isn't
// JSON, e.g. tamper's script store and core's fs store.
func httpSendRaw(method, apiBase, path string, body []byte, contentType string) ([]byte, error) {
	req, err := http.NewRequest(method, strings.TrimSuffix(apiBase, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return data, checkHTTPError(resp, data)
}

// httpPutRaw sends a PUT with a raw (non-JSON) body — see httpSendRaw.
func httpPutRaw(apiBase, path string, body []byte, contentType string) ([]byte, error) {
	return httpSendRaw(http.MethodPut, apiBase, path, body, contentType)
}

// httpPostRawBody sends a POST with a raw (non-JSON) body — see httpSendRaw. Distinct
// from httpPostJSON/httpPostRaw above, which both send a JSON-encoded request body
// (dbdump's REST convention); this one is for core's fs-append, which — like
// scripts/fs PUT — transfers content as a raw body, not JSON.
func httpPostRawBody(apiBase, path string, body []byte, contentType string) ([]byte, error) {
	return httpSendRaw(http.MethodPost, apiBase, path, body, contentType)
}

// httpDelete sends a DELETE request and returns the raw response body.
func httpDelete(apiBase, path string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodDelete, strings.TrimSuffix(apiBase, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return data, checkHTTPError(resp, data)
}
