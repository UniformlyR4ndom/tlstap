// WebSocket protocol implementation (RFC 6455) for wireclient-cli — hand-rolled rather than
// using gorilla/websocket (already a project dependency elsewhere), since this tool's whole
// purpose is precise control over wire details a high-level library deliberately hides:
// RSV bits, unsolicited pongs, deliberately incomplete frames. Every send goes through the
// same encode path, normal and unusual alike — no split between "library path" and "raw
// bytes for the special cases".
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xa
)

type WebSocket struct{}

type wsSession struct {
	conn     net.Conn // reads/writes go through here (may be *tls.Conn)
	rawConn  net.Conn // underlying TCP conn, for an abrupt (non-TLS-clean) close
	reader   *bufio.Reader
	isServer bool // masking direction: client frames masked, server frames never are
}

func (s *wsSession) Close() error { return s.conn.Close() }

func (s *wsSession) clientMasking() bool { return !s.isServer }

func (WebSocket) HandshakeClient(conn net.Conn, rawConn net.Conn, opts Options, log func(string)) (Session, error) {
	// Retained on the session, not discarded after the handshake — the status line/
	// headers and the WebSocket frames that follow share one TCP stream, and a second,
	// fresh bufio.Reader would lose whatever this one already buffered ahead.
	reader := bufio.NewReader(conn)
	return handshakeClient(conn, rawConn, reader, opts, log)
}

func handshakeClient(conn, rawConn net.Conn, reader *bufio.Reader, opts Options, log func(string)) (Session, error) {
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)

	path := opts.Path
	if path == "" {
		path = "/"
	}
	req := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		path, conn.RemoteAddr(), key,
	)
	if _, err := io.WriteString(conn, req); err != nil {
		return nil, err
	}
	log("sent Upgrade request")

	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("reading status line: %w", err)
	}
	if !strings.Contains(statusLine, "101") {
		return nil, fmt.Errorf("upgrade rejected: %s", strings.TrimSpace(statusLine))
	}
	accept, err := readHeaderValue(reader, "Sec-WebSocket-Accept")
	if err != nil {
		return nil, err
	}
	if want := acceptValue(key); accept != want {
		log(fmt.Sprintf("warning: Sec-WebSocket-Accept mismatch (got %q, want %q) — continuing anyway", accept, want))
	}
	log("upgrade accepted (101)")

	return &wsSession{conn: conn, rawConn: rawConn, reader: reader, isServer: false}, nil
}

// readHeaderValue reads header lines up to (and consuming) the terminating blank line,
// returning the value of the first line matching name (case-insensitively). Used by the
// client handshake only — the server side gets real header parsing from net/http instead.
func readHeaderValue(reader *bufio.Reader, name string) (string, error) {
	value := ""
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("reading headers: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return value, nil
		}
		if fieldName, fieldValue, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(fieldName), name) {
			value = strings.TrimSpace(fieldValue)
		}
	}
}

// ListenAndHandshakeServer runs a real net/http.Server so the Upgrade request gets real
// HTTP/1.1 parsing (not our own hand-rolled reading — another independent check, on top of
// requireUpgrade's own RFC 6455 validation) before Hijack()ing the connection to take over
// for WebSocket framing. Stops listening as soon as it has (or fails to get) one session —
// this tool speaks to exactly one peer per invocation, same as the client role.
func (WebSocket) ListenAndHandshakeServer(addr string, tlsConfig *tls.Config, opts Options, requireUpgrade bool, log func(string)) (Session, error) {
	sessionCh := make(chan Session, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		key, err := validateUpgradeRequest(r, requireUpgrade)
		if err != nil {
			writeUpgradeError(w, err)
			errCh <- err
			return
		}
		log(fmt.Sprintf("received request: %s %s %s", r.Method, r.URL.Path, r.Proto))

		hj, ok := w.(http.Hijacker)
		if !ok {
			err := fmt.Errorf("response writer doesn't support hijacking")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			errCh <- err
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			errCh <- err
			return
		}

		resp := fmt.Sprintf(
			"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
			acceptValue(key),
		)
		if _, err := bufrw.WriteString(resp); err != nil || bufrw.Flush() != nil {
			conn.Close()
			errCh <- fmt.Errorf("writing 101 response: %w", err)
			return
		}
		log("sent 101 response")

		// bufrw.Reader, not a fresh bufio.Reader — net/http may have already buffered
		// bytes past the request headers (e.g. an immediately-following WS frame) while
		// parsing the request; a new reader would lose them.
		sessionCh <- &wsSession{conn: conn, rawConn: conn, reader: bufrw.Reader, isServer: true}
	})

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}
	fmt.Fprintf(os.Stderr, "listening on %s, waiting for one connection...\n", addr)

	server := &http.Server{Handler: mux}
	go server.Serve(listener)

	select {
	case session := <-sessionCh:
		listener.Close()
		return session, nil
	case err := <-errCh:
		listener.Close()
		return nil, err
	}
}

// validateUpgradeRequest checks RFC 6455 §4.2.1's request requirements, returning the
// Sec-WebSocket-Key on success — matching how a real WebSocket endpoint behaves, by far the
// most common real-world setup. When requireUpgrade is false, only the key itself (needed
// to compute Sec-WebSocket-Accept at all) is checked — a deliberate escape hatch for feeding
// tlstap a request that isn't really a proper upgrade attempt, not the default.
func validateUpgradeRequest(r *http.Request, requireUpgrade bool) (key string, err error) {
	key = r.Header.Get("Sec-WebSocket-Key")
	if !requireUpgrade {
		if key == "" {
			return "", fmt.Errorf("no Sec-WebSocket-Key header in request")
		}
		return key, nil
	}

	if r.Method != http.MethodGet {
		return "", fmt.Errorf("expected GET, got %s", r.Method)
	}
	if !r.ProtoAtLeast(1, 1) {
		return "", fmt.Errorf("expected HTTP/1.1 or later, got %s", r.Proto)
	}
	if !headerTokenContains(r.Header.Get("Upgrade"), "websocket") {
		return "", fmt.Errorf("Upgrade header %q does not contain \"websocket\"", r.Header.Get("Upgrade"))
	}
	if !headerTokenContains(r.Header.Get("Connection"), "Upgrade") {
		return "", fmt.Errorf("Connection header %q does not contain \"Upgrade\"", r.Header.Get("Connection"))
	}
	if v := r.Header.Get("Sec-WebSocket-Version"); v != "13" {
		return "", &versionMismatchError{got: v}
	}
	if key == "" {
		return "", fmt.Errorf("no Sec-WebSocket-Key header in request")
	}
	if decoded, decErr := base64.StdEncoding.DecodeString(key); decErr != nil || len(decoded) != 16 {
		return "", fmt.Errorf("Sec-WebSocket-Key %q is not valid base64 for 16 bytes", key)
	}
	return key, nil
}

func headerTokenContains(header, token string) bool {
	for _, part := range strings.Split(header, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

// versionMismatchError gets its own RFC 6455 §4.2.2-mandated response: 426 Upgrade
// Required with a Sec-WebSocket-Version: 13 header, not a generic 400.
type versionMismatchError struct{ got string }

func (e *versionMismatchError) Error() string {
	return fmt.Sprintf("Sec-WebSocket-Version %q not supported, want 13", e.got)
}

func writeUpgradeError(w http.ResponseWriter, err error) {
	var versionErr *versionMismatchError
	if errors.As(err, &versionErr) {
		w.Header().Set("Sec-WebSocket-Version", "13")
		http.Error(w, err.Error(), http.StatusUpgradeRequired)
		return
	}
	http.Error(w, err.Error(), http.StatusBadRequest)
}

func acceptValue(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

// buildFrameBytes encodes one RFC 6455 §5.2 wire frame.
func buildFrameBytes(fin, rsv1, rsv2, rsv3 bool, opcode byte, payload []byte, masked bool) ([]byte, error) {
	var b0 byte = opcode & 0x0f
	if fin {
		b0 |= 0x80
	}
	if rsv1 {
		b0 |= 0x40
	}
	if rsv2 {
		b0 |= 0x20
	}
	if rsv3 {
		b0 |= 0x10
	}

	buf := []byte{b0}
	n := len(payload)
	switch {
	case n < 126:
		lb := byte(n)
		if masked {
			lb |= 0x80
		}
		buf = append(buf, lb)
	case n < 65536:
		lb := byte(126)
		if masked {
			lb |= 0x80
		}
		buf = append(buf, lb, byte(n>>8), byte(n))
	default:
		lb := byte(127)
		if masked {
			lb |= 0x80
		}
		buf = append(buf, lb, 0, 0, 0, 0, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}

	if masked {
		var key [4]byte
		if _, err := rand.Read(key[:]); err != nil {
			return nil, err
		}
		buf = append(buf, key[:]...)
		maskedPayload := make([]byte, n)
		for i, b := range payload {
			maskedPayload[i] = b ^ key[i%4]
		}
		buf = append(buf, maskedPayload...)
	} else {
		buf = append(buf, payload...)
	}
	return buf, nil
}

func (s *wsSession) writeFrame(fin, rsv1, rsv2, rsv3 bool, opcode byte, payload []byte, masked bool) error {
	buf, err := buildFrameBytes(fin, rsv1, rsv2, rsv3, opcode, payload, masked)
	if err != nil {
		return err
	}
	_, err = s.conn.Write(buf)
	return err
}

func (WebSocket) Send(session Session, spec string, log func(Frame)) error {
	s := session.(*wsSession)
	kind, rest, _ := strings.Cut(spec, ":")

	switch kind {
	case "text":
		return s.sendSimple(opText, []byte(rest), log)
	case "binary":
		payload, err := parseBinaryArg(rest)
		if err != nil {
			return err
		}
		return s.sendSimple(opBinary, payload, log)
	case "fragment":
		return s.sendFragment(rest, log)
	case "frame":
		return s.sendFrameSpec(rest, log)
	case "ping":
		return s.sendSimple(opPing, []byte(rest), log)
	case "pong":
		return s.sendSimple(opPong, []byte(rest), log)
	case "close":
		code, reason, _ := strings.Cut(rest, ":")
		codeNum, err := strconv.Atoi(code)
		if err != nil {
			return fmt.Errorf("close: bad code %q: %w", code, err)
		}
		payload := append([]byte{byte(codeNum >> 8), byte(codeNum)}, reason...)
		return s.sendSimple(opClose, payload, log)
	case "rsv":
		return s.sendRsv(rest, log)
	case "raw":
		data, err := hex.DecodeString(rest)
		if err != nil {
			return fmt.Errorf("raw: bad hex: %w", err)
		}
		if _, err := s.conn.Write(data); err != nil {
			return err
		}
		log(Frame{Direction: "sent", Summary: fmt.Sprintf("raw %d bytes", len(data))})
		return nil
	case "sleep":
		ms, err := strconv.Atoi(rest)
		if err != nil {
			return fmt.Errorf("sleep: bad duration %q: %w", rest, err)
		}
		time.Sleep(time.Duration(ms) * time.Millisecond)
		return nil
	case "truncate":
		return s.truncate(rest, log)
	default:
		return fmt.Errorf("unknown send spec kind %q", kind)
	}
}

func (s *wsSession) sendSimple(opcode byte, payload []byte, log func(Frame)) error {
	masked := s.clientMasking()
	if err := s.writeFrame(true, false, false, false, opcode, payload, masked); err != nil {
		return err
	}
	log(Frame{Direction: "sent", Summary: describeFrame(true, opcode, false, false, false, masked, payload)})
	return nil
}

// fragment:text:<p1>,<p2>,...   — pieces are literal UTF-8 substrings
// fragment:binary:<p1>,<p2>,... — pieces are hex-encoded (raw binary content can't always
// survive as a literal command-line argument the way text can)
func (s *wsSession) sendFragment(rest string, log func(Frame)) error {
	kind, parts, _ := strings.Cut(rest, ":")
	opcode, err := messageOpcode(kind)
	if err != nil {
		return fmt.Errorf("fragment: %w", err)
	}
	masked := s.clientMasking()
	pieces := strings.Split(parts, ",")
	for i, piece := range pieces {
		payload := []byte(piece)
		if kind == "binary" {
			payload, err = hex.DecodeString(piece)
			if err != nil {
				return fmt.Errorf("fragment: piece %d: bad hex: %w", i, err)
			}
		}
		op := opcode
		if i > 0 {
			op = opContinuation
		}
		fin := i == len(pieces)-1
		if err := s.writeFrame(fin, false, false, false, op, payload, masked); err != nil {
			return err
		}
		log(Frame{Direction: "sent", Summary: describeFrame(fin, op, false, false, false, masked, payload)})
	}
	return nil
}

// frame:<fin 0|1>:<opcode text|binary|continuation|ping|pong|close>:<payload> — a single
// raw wire frame with explicit fin/opcode control, the one primitive none of text/binary/
// fragment/ping/pong expose on their own: composing a fin:false start frame, an
// interrupting control frame, and a fin:true continuation across separate --send
// invocations lets a test sequence put a control frame in the middle of a fragmented
// message (RFC 6455 §5.4) — something none of the higher-level specs can produce.
func (s *wsSession) sendFrameSpec(rest string, log func(Frame)) error {
	finStr, rest2, _ := strings.Cut(rest, ":")
	opcodeStr, payloadStr, _ := strings.Cut(rest2, ":")
	var fin bool
	switch finStr {
	case "0":
		fin = false
	case "1":
		fin = true
	default:
		return fmt.Errorf("frame: bad fin %q, want 0|1", finStr)
	}
	opcode, err := anyOpcode(opcodeStr)
	if err != nil {
		return fmt.Errorf("frame: %w", err)
	}
	masked := s.clientMasking()
	if err := s.writeFrame(fin, false, false, false, opcode, []byte(payloadStr), masked); err != nil {
		return err
	}
	log(Frame{Direction: "sent", Summary: describeFrame(fin, opcode, false, false, false, masked, []byte(payloadStr))})
	return nil
}

// anyOpcode is frame:'s own opcode vocabulary — unlike messageOpcode (text|binary only,
// used where fragmenting a *message* is the context), frame: is a raw primitive that must
// be able to name every opcode, continuation and the control opcodes included.
func anyOpcode(kind string) (byte, error) {
	switch kind {
	case "continuation":
		return opContinuation, nil
	case "text":
		return opText, nil
	case "binary":
		return opBinary, nil
	case "close":
		return opClose, nil
	case "ping":
		return opPing, nil
	case "pong":
		return opPong, nil
	default:
		return 0, fmt.Errorf("unknown opcode %q", kind)
	}
}

func (s *wsSession) sendRsv(rest string, log func(Frame)) error {
	bitStr, rest2, _ := strings.Cut(rest, ":")
	kind, payloadStr, _ := strings.Cut(rest2, ":")
	opcode, err := messageOpcode(kind)
	if err != nil {
		return fmt.Errorf("rsv: %w", err)
	}
	rsv1, rsv2, rsv3 := bitStr == "1", bitStr == "2", bitStr == "3"
	if !rsv1 && !rsv2 && !rsv3 {
		return fmt.Errorf("rsv: bad bit %q, want 1|2|3", bitStr)
	}
	masked := s.clientMasking()
	if err := s.writeFrame(true, rsv1, rsv2, rsv3, opcode, []byte(payloadStr), masked); err != nil {
		return err
	}
	log(Frame{Direction: "sent", Summary: describeFrame(true, opcode, rsv1, rsv2, rsv3, masked, []byte(payloadStr))})
	return nil
}

// truncate:<opcode>:size=<N> writes only the header and half the declared payload of an
// otherwise-normal frame (fin:true — any opcode frame: accepts, notably including
// continuation: for cutting short the final fragment of an accumulating message), then
// severs the raw connection directly (bypassing conn, which may be a *tls.Conn that would
// send a close_notify) — no WS close handshake, no TLS clean shutdown, a real mid-payload
// cut for testing framer truncation handling.
func (s *wsSession) truncate(rest string, log func(Frame)) error {
	kind, sizeArg, _ := strings.Cut(rest, ":")
	opcode, err := anyOpcode(kind)
	if err != nil {
		return fmt.Errorf("truncate: %w", err)
	}
	payload, err := parseBinaryArg(sizeArg)
	if err != nil {
		return err
	}

	masked := s.clientMasking()
	full, err := buildFrameBytes(true, false, false, false, opcode, payload, masked)
	if err != nil {
		return err
	}
	cut := len(full) / 2
	if _, err := s.conn.Write(full[:cut]); err != nil {
		return err
	}
	log(Frame{Direction: "sent", Summary: fmt.Sprintf("truncated %s frame: wrote %d/%d bytes, then severing connection", kind, cut, len(full))})

	if s.rawConn != nil {
		s.rawConn.Close()
	} else {
		s.conn.Close()
	}
	return ErrTruncated
}

func messageOpcode(kind string) (byte, error) {
	switch kind {
	case "text":
		return opText, nil
	case "binary":
		return opBinary, nil
	default:
		return 0, fmt.Errorf("unknown message kind %q, want text|binary", kind)
	}
}

// parseBinaryArg parses a binary payload spec argument: "hex=<...>" for exact content, or
// "size=<N>" for N deterministic bytes (A-Z repeating — recognizable/diffable in a hex
// view, unlike random noise) for hitting exact length-encoding boundaries (125/126,
// 65535/65536) or just generating a large payload.
func parseBinaryArg(arg string) ([]byte, error) {
	kind, val, ok := strings.Cut(arg, "=")
	if !ok {
		return nil, fmt.Errorf("binary: expected hex=<hex>|size=<N>, got %q", arg)
	}
	switch kind {
	case "hex":
		return hex.DecodeString(val)
	case "size":
		n, err := strconv.Atoi(val)
		if err != nil {
			return nil, fmt.Errorf("binary: bad size %q: %w", val, err)
		}
		payload := make([]byte, n)
		for i := range payload {
			payload[i] = byte('A' + i%26)
		}
		return payload, nil
	default:
		return nil, fmt.Errorf("binary: unknown arg kind %q", kind)
	}
}

func (WebSocket) ReadLoop(session Session, log func(Frame)) error {
	s := session.(*wsSession)
	for {
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(s.reader, hdr); err != nil {
			return err
		}
		fin := hdr[0]&0x80 != 0
		rsv1 := hdr[0]&0x40 != 0
		rsv2 := hdr[0]&0x20 != 0
		rsv3 := hdr[0]&0x10 != 0
		opcode := hdr[0] & 0x0f
		masked := hdr[1]&0x80 != 0
		lenField := hdr[1] & 0x7f

		var payloadLen uint64
		switch lenField {
		case 126:
			ext := make([]byte, 2)
			if _, err := io.ReadFull(s.reader, ext); err != nil {
				return err
			}
			payloadLen = uint64(ext[0])<<8 | uint64(ext[1])
		case 127:
			ext := make([]byte, 8)
			if _, err := io.ReadFull(s.reader, ext); err != nil {
				return err
			}
			for _, b := range ext {
				payloadLen = payloadLen<<8 | uint64(b)
			}
		default:
			payloadLen = uint64(lenField)
		}

		var key [4]byte
		if masked {
			if _, err := io.ReadFull(s.reader, key[:]); err != nil {
				return err
			}
		}

		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(s.reader, payload); err != nil {
			return err
		}
		if masked {
			for i := range payload {
				payload[i] ^= key[i%4]
			}
		}

		log(Frame{Direction: "recv", Summary: describeFrame(fin, opcode, rsv1, rsv2, rsv3, masked, payload)})

		if opcode == opClose {
			return nil // peer-initiated clean close
		}
	}
}

func describeFrame(fin bool, opcode byte, rsv1, rsv2, rsv3, masked bool, payload []byte) string {
	preview := payload
	note := ""
	if len(preview) > 40 {
		preview = preview[:40]
		note = "..."
	}
	return fmt.Sprintf("fin=%v opcode=%s rsv=%v/%v/%v masked=%v len=%d payload=%q%s",
		fin, opcodeName(opcode), rsv1, rsv2, rsv3, masked, len(payload), preview, note)
}

func opcodeName(opcode byte) string {
	switch opcode {
	case opContinuation:
		return "Continuation"
	case opText:
		return "Text"
	case opBinary:
		return "Binary"
	case opClose:
		return "Close"
	case opPing:
		return "Ping"
	case opPong:
		return "Pong"
	default:
		return fmt.Sprintf("Reserved(0x%x)", opcode)
	}
}
