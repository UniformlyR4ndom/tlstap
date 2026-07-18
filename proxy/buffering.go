package proxy

// BufferingInterceptor is an optional interface an Interceptor may additionally implement to
// hold data across calls instead of resolving synchronously within one Intercept call. Detected
// via a one-time type assertion per connection (see ConnHandler's newHandler wiring in proxy.go),
// mirroring how ApiProvider is detected in cli.go.
//
// Contract:
//   - No constraint on combining a non-empty Intercept return with something still pending — an
//     implementation may forward part of what it received now and keep holding the rest (e.g.
//     forward a completed message, buffer a trailing partial one). ConnHandler always checks
//     HasPending after every call to a chain containing a buffering interceptor, regardless of
//     what Intercept returned.
//   - Must never release data that arrived later before data that arrived earlier, for a given
//     (ConnID, direction) — i.e. must preserve its own local FIFO. Global ordering across a chain
//     with multiple buffering interceptors falls out of composing this local guarantee at each
//     stage; ConnHandler enforces nothing itself beyond calling interceptors in chain order.
//   - Must close the channel returned by ReleaseChannel once ConnectionTerminated has fired for
//     that ConnID (all its data released or discarded), and never send on it afterward.
type BufferingInterceptor interface {
	Interceptor

	// HasPending reports whether this interceptor currently holds anything not yet forwarded
	// for info's (ConnID, direction) — direction is implicit in info, same convention Intercept
	// already uses (compare info.SrcEndpoint against a recorded client endpoint).
	HasPending(info *ConnInfo) bool

	// ReleaseChannel returns the channel this interceptor delivers released data on for info's
	// (ConnID, direction). Expected to already exist (created in ConnectionEstablished, torn down
	// in ConnectionTerminated) — this just hands back the reference; called once, lazily, the
	// first time ConnHandler transitions that direction into async mode.
	ReleaseChannel(info *ConnInfo) <-chan ReleasedData
}

// ReleasedData is what a BufferingInterceptor sends on its release channel: bytes to re-enter the
// interceptor chain immediately after this interceptor's own position, in the order received on
// the channel. Err (e.g. ErrAbort) terminates the connection instead of forwarding Data.
type ReleasedData struct {
	Data []byte
	Err  error
}
