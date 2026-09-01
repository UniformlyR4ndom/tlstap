package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"net"
	"strings"
	"time"
)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	roleFlag := flag.String("role", "", "client | server")
	protocolFlag := flag.String("protocol", "websocket", `protocol to speak (only "websocket" implemented)`)
	addr := flag.String("addr", "", "dial target (client) or listen address (server)")
	useTLS := flag.Bool("tls", false, "use TLS")
	certFile := flag.String("cert", "", "server TLS certificate (PEM, server role only)")
	keyFile := flag.String("key", "", "server TLS key (PEM, server role only)")
	insecureSkipVerify := flag.Bool("insecure-skip-verify", false, "client: skip TLS certificate verification")
	path := flag.String("path", "/", "client: WebSocket Upgrade request path")
	requireUpgrade := flag.Bool("require-upgrade", true, "server: enforce RFC 6455 Upgrade-request validation before switching protocols (matches real-world servers; disable only to deliberately feed a malformed handshake)")
	timeout := flag.Duration("timeout", 10*time.Second, "how long to wait for the peer after the send sequence finishes, before forcibly closing")
	var sends stringList
	flag.Var(&sends, "send", "one scripted send action (repeatable, executed in order) — see the doc comment atop protocol.go for the spec vocabulary")
	flag.Parse()

	if *addr == "" {
		log.Fatal("--addr is required")
	}

	var proto Protocol
	switch *protocolFlag {
	case "websocket":
		proto = WebSocket{}
	default:
		log.Fatalf(`unknown --protocol %q (only "websocket" is implemented)`, *protocolFlag)
	}

	var role Role
	switch *roleFlag {
	case "client":
		role = RoleClient
	case "server":
		role = RoleServer
	default:
		log.Fatal(`--role must be "client" or "server"`)
	}

	logStep := func(msg string) { log.Print(msg) }
	opts := Options{Path: *path}

	var session Session
	if role == RoleClient {
		conn, rawConn, err := dial(*addr, *useTLS, *insecureSkipVerify)
		if err != nil {
			log.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		session, err = proto.HandshakeClient(conn, rawConn, opts, logStep)
		if err != nil {
			log.Fatalf("handshake: %v", err)
		}
	} else {
		var tlsConfig *tls.Config
		if *useTLS {
			if *certFile == "" || *keyFile == "" {
				log.Fatal("--cert and --key are required for --role server --tls")
			}
			cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
			if err != nil {
				log.Fatalf("loading server cert: %v", err)
			}
			tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		}
		var err error
		session, err = proto.ListenAndHandshakeServer(*addr, tlsConfig, opts, *requireUpgrade, logStep)
		if err != nil {
			log.Fatalf("handshake: %v", err)
		}
	}
	defer session.Close()

	logFrame := func(f Frame) { log.Printf("%-4s %s", f.Direction, f.Summary) }

	readDone := make(chan error, 1)
	go func() { readDone <- proto.ReadLoop(session, logFrame) }()

	for _, spec := range sends {
		if err := proto.Send(session, spec, logFrame); err != nil {
			if errors.Is(err, ErrTruncated) {
				log.Printf("send %q: %v", spec, err)
				break
			}
			log.Fatalf("send %q failed: %v", spec, err)
		}
	}

	select {
	case err := <-readDone:
		log.Printf("connection closed: %v", err)
	case <-time.After(*timeout):
		log.Printf("timeout reached, closing connection")
		session.Close()
		<-readDone
	}
}

// dial connects to a server (client role only — the server role's connection handling is
// owned entirely by Protocol.ListenAndHandshakeServer, since a WebSocket upgrade can't be
// validated correctly without a real net/http.Server; see protocol.go's doc comment on
// Protocol for why). Returns the conn to read/write through (TLS-wrapped if requested) and,
// separately, the underlying raw TCP conn — identical to the first when not using TLS,
// otherwise needed by actions like WebSocket's "truncate" that must bypass TLS's own
// clean-shutdown behavior.
func dial(addr string, useTLS bool, insecureSkipVerify bool) (net.Conn, net.Conn, error) {
	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	if !useTLS {
		return rawConn, rawConn, nil
	}
	tlsConn := tls.Client(rawConn, &tls.Config{InsecureSkipVerify: insecureSkipVerify})
	if err := tlsConn.Handshake(); err != nil {
		return nil, nil, err
	}
	return tlsConn, rawConn, nil
}
