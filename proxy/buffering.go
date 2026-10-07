package proxy

// BufferingInterceptor is an optional interface an Interceptor may additionally implement to
// hold data across calls instead of resolving synchronously within one Intercept call. Detected
// via a one-time type assertion per connection (see ConnHandler's newHandler wiring in proxy.go),
// mirroring how ApiProvider is detected in cli.go.
//
// A direction's interceptor chain may contain at most one BufferingInterceptor (validated in
// Proxy.Start), and buffering interceptors are not supported in detecttls mode yet.
//
// Contract:
//   - No constraint on combining a non-empty Intercept return with something still pending — an
//     implementation may forward part of what it received now and keep holding the rest (e.g.
//     forward a completed message, buffer a trailing partial one).
//   - Must never release data that arrived later before data that arrived earlier, for a given
//     (ConnID, direction) — i.e. must preserve its own local FIFO. Intercept must not return data
//     unheld while earlier data is still held.
//   - HasPending returning false means everything previously held has already been sent on the
//     release channel (state change and send happen under one lock).
//   - Sends on the release channel may block; ConnHandler always has a consumer for it while the
//     connection is alive, and never holds a lock the interceptor could be waiting for.
//   - Must close the channel returned by ReleaseChannel once ConnectionTerminated has fired for
//     that ConnID (all its data released or discarded), and never send on it afterward.
//
// ConnHandler guarantees:
//   - Data sent on the release channel before an Intercept call returned is forwarded before that
//     call's own output.
//   - HasPending and ReleaseChannel are only called between ConnectionEstablished and
//     ConnectionTerminated.
type BufferingInterceptor interface {
	Interceptor

	// HasPending reports whether this interceptor currently holds anything not yet forwarded
	// for info's (ConnID, direction) — direction is implicit in info, same convention Intercept
	// already uses (compare info.SrcEndpoint against a recorded client endpoint).
	HasPending(info *ConnInfo) bool

	// ReleaseChannel returns the channel this interceptor delivers released data on for info's
	// (ConnID, direction). Expected to already exist (created in ConnectionEstablished, torn down
	// in ConnectionTerminated) — this just hands back the reference; called once per direction
	// when that direction's forwarding starts.
	ReleaseChannel(info *ConnInfo) <-chan ReleasedData
}

// ReleasedData is what a BufferingInterceptor sends on its release channel: bytes to re-enter the
// interceptor chain immediately after this interceptor's own position, in the order received on
// the channel. Err (e.g. ErrAbort) terminates the connection instead of forwarding Data.
type ReleasedData struct {
	Data []byte
	Err  error
}
