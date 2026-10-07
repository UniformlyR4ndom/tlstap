package main

import (
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
)

func coreMain(args []string) {
	if len(args) < 1 {
		coreUsage()
		os.Exit(2)
	}

	switch args[0] {
	case "fs-list":
		cmdCoreFsList(args[1:])
	case "fs-get":
		cmdCoreFsGet(args[1:])
	case "fs-put":
		cmdCoreFsPut(args[1:])
	case "fs-append":
		cmdCoreFsAppend(args[1:])
	case "kv-list":
		cmdCoreKvList(args[1:])
	case "kv-read":
		cmdCoreKvRead(args[1:])
	case "kv-write":
		cmdCoreKvWrite(args[1:])
	case "kv-delete":
		cmdCoreKvDelete(args[1:])
	case "-h", "--help", "help":
		coreUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown core command: %s\n\n", args[0])
		coreUsage()
		os.Exit(2)
	}
}

func coreUsage() {
	fmt.Fprint(os.Stderr, `tapctl core - drive tlstap's core services (not tied to any one interceptor)

Usage:
  tapctl core fs-list [--path PATH] [--api URL]
  tapctl core fs-get --path PATH [--api URL]
  tapctl core fs-put --path PATH (--file PATH2 | --file -) [--api URL]
  tapctl core fs-append --path PATH (--file PATH2 | --file -) [--api URL]
  tapctl core kv-list [--prefix PREFIX] [--api URL]
  tapctl core kv-read --key KEY [--api URL]
  tapctl core kv-write --key KEY (--file PATH | --file -) [--api URL]
  tapctl core kv-delete --key KEY [--api URL]

fs-list/fs-get/fs-put act on core.fs's store; see core/CLAUDE.md's "Filesystem access"
section. --path is slash-separated for subdirectories (e.g. "sub/dir/file.bin"); fs-list's
--path defaults to "" (the configured root itself). fs-get prints raw file bytes to
stdout, same pipeable convention as tamper's script-get, except content here is
arbitrary binary, not always printable text. There is no fs-delete: the server exposes
no DELETE endpoint. fs-append (--file PATH|-, same as fs-put) appends instead of
overwriting, creating the file (and missing parent directories) if it doesn't exist yet;
safe under concurrent appends to the same file from elsewhere (see core/fs's Append).

kv-list/kv-read/kv-write/kv-delete act on core.kv's store (see core/CLAUDE.md's
"core/kv" section) — a general-purpose key-value store independent of core.fs above,
e.g. for a script-stashed value (a crypto key exchanged on one connection, shared
across streams/scripts via tamper.kv.*/framer.kv.*/dissector.kv.*). Unlike every other
tapctl command, key/prefix travel in the query string, not a JSON body or path segment —
mirrors the REST API itself (core/kv/api.go), which reserves the request/response body
purely for value bytes. kv-list's --prefix defaults to "" (every key); kv-read prints
the raw value to stdout, same pipeable convention as fs-get, or fails with "key not
found" (404) if absent. kv-write reads from --file (a path, or - for stdin), same
convention as fs-put/fs-append — a plain upsert, no separate "create" vs. "update".
kv-delete is idempotent regardless of prior existence, same as the REST endpoint itself.
`)
}

// --- fs access (REST; see core/fs/fs.go) ---

// encodeFsPath percent-encodes each slash-separated segment of path individually (not
// the path as a whole), so literal slashes survive as separators through to the
// server's {path...} wildcard route instead of being escaped into %2F — mirroring
// web/coreFsApi.js's encodeFsPath. Empty segments (leading/trailing/doubled slashes) are
// dropped; the server's own path.Clean-based resolution would collapse them anyway.
func encodeFsPath(path string) string {
	var b strings.Builder
	first := true
	for _, seg := range strings.Split(path, "/") {
		if seg == "" {
			continue
		}
		if !first {
			b.WriteByte('/')
		}
		b.WriteString(url.PathEscape(seg))
		first = false
	}
	return b.String()
}

func cmdCoreFsList(args []string) {
	fs := flag.NewFlagSet("core fs-list", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	path := fs.String("path", "", "subdirectory relative to the configured root (default: the root itself)")
	fs.Parse(args)

	endpoint := "/api/core/fs/list"
	if enc := encodeFsPath(*path); enc != "" {
		endpoint += "/" + enc
	}

	data, err := httpGet(*api, endpoint)
	if err != nil {
		fail("%v", err)
	}
	printRawJSON(data)
}

func cmdCoreFsGet(args []string) {
	fs := flag.NewFlagSet("core fs-get", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	path := fs.String("path", "", "file path relative to the configured root (required)")
	fs.Parse(args)

	if *path == "" {
		fail("--path is required")
	}

	data, err := httpGet(*api, "/api/core/fs/file/"+encodeFsPath(*path))
	if err != nil {
		fail("%v", err)
	}
	// Raw file bytes — arbitrary binary, not necessarily printable — written verbatim
	// to stdout, same pipeable convention as tamper's script-get.
	os.Stdout.Write(data)
}

func cmdCoreFsPut(args []string) {
	fs := flag.NewFlagSet("core fs-put", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	path := fs.String("path", "", "file path relative to the configured root (required)")
	file := fs.String("file", "", "path to file content, or - for stdin (required)")
	fs.Parse(args)

	if *path == "" {
		fail("--path is required")
	}
	if *file == "" {
		fail("--file is required (path, or - for stdin)")
	}

	var content []byte
	var err error
	if *file == "-" {
		content, err = io.ReadAll(os.Stdin)
	} else {
		content, err = os.ReadFile(*file)
	}
	if err != nil {
		fail("read --file: %v", err)
	}

	if _, err := httpPutRaw(*api, "/api/core/fs/file/"+encodeFsPath(*path), content, "application/octet-stream"); err != nil {
		fail("%v", err)
	}
	printJSON(struct {
		Status string `json:"status"`
	}{"ok"})
}

func cmdCoreFsAppend(args []string) {
	fs := flag.NewFlagSet("core fs-append", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	path := fs.String("path", "", "file path relative to the configured root (required)")
	file := fs.String("file", "", "path to content to append, or - for stdin (required)")
	fs.Parse(args)

	if *path == "" {
		fail("--path is required")
	}
	if *file == "" {
		fail("--file is required (path, or - for stdin)")
	}

	var content []byte
	var err error
	if *file == "-" {
		content, err = io.ReadAll(os.Stdin)
	} else {
		content, err = os.ReadFile(*file)
	}
	if err != nil {
		fail("read --file: %v", err)
	}

	if _, err := httpPostRawBody(*api, "/api/core/fs/file/"+encodeFsPath(*path), content, "application/octet-stream"); err != nil {
		fail("%v", err)
	}
	printJSON(struct {
		Status string `json:"status"`
	}{"ok"})
}

// --- kv access (REST; see core/kv/api.go) ---

func cmdCoreKvList(args []string) {
	fs := flag.NewFlagSet("core kv-list", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	prefix := fs.String("prefix", "", "only keys with this byte-prefix (default: every key)")
	fs.Parse(args)

	endpoint := "/api/core/kv/list"
	if *prefix != "" {
		endpoint += "?prefix=" + url.QueryEscape(*prefix)
	}

	data, err := httpPostRawBody(*api, endpoint, nil, "")
	if err != nil {
		fail("%v", err)
	}
	printRawJSON(data)
}

func cmdCoreKvRead(args []string) {
	fs := flag.NewFlagSet("core kv-read", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	key := fs.String("key", "", "key (required)")
	fs.Parse(args)

	if *key == "" {
		fail("--key is required")
	}

	data, err := httpPostRawBody(*api, "/api/core/kv/read?key="+url.QueryEscape(*key), nil, "")
	if err != nil {
		fail("%v", err)
	}
	// Raw value bytes — arbitrary binary, not necessarily printable — written verbatim
	// to stdout, same pipeable convention as core fs-get/tamper script-get.
	os.Stdout.Write(data)
}

func cmdCoreKvWrite(args []string) {
	fs := flag.NewFlagSet("core kv-write", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	key := fs.String("key", "", "key (required)")
	file := fs.String("file", "", "path to value content, or - for stdin (required)")
	fs.Parse(args)

	if *key == "" {
		fail("--key is required")
	}
	if *file == "" {
		fail("--file is required (path, or - for stdin)")
	}

	var content []byte
	var err error
	if *file == "-" {
		content, err = io.ReadAll(os.Stdin)
	} else {
		content, err = os.ReadFile(*file)
	}
	if err != nil {
		fail("read --file: %v", err)
	}

	if _, err := httpPostRawBody(*api, "/api/core/kv/write?key="+url.QueryEscape(*key), content, "application/octet-stream"); err != nil {
		fail("%v", err)
	}
	printJSON(struct {
		Status string `json:"status"`
	}{"ok"})
}

func cmdCoreKvDelete(args []string) {
	fs := flag.NewFlagSet("core kv-delete", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	key := fs.String("key", "", "key (required)")
	fs.Parse(args)

	if *key == "" {
		fail("--key is required")
	}

	if _, err := httpPostRawBody(*api, "/api/core/kv/delete?key="+url.QueryEscape(*key), nil, ""); err != nil {
		fail("%v", err)
	}
	printJSON(struct {
		Status string `json:"status"`
	}{"ok"})
}
