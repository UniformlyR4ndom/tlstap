package cli

import "tlstap/proxy"

// CoreService is a utility service that, unlike an Interceptor, isn't tied to any one
// proxy or interceptor chain — it's wired directly into StartWithCli, the same way /ui/
// is registered on apiMux. See core/CLAUDE.md for its implementers (core/kv, core/fs)
// and doc/design/core-kv-store.md for the design this backs.
//
// Unlike Interceptor, there's no Init(addr) — a CoreService isn't per-proxy, so there's
// no per-proxy address to receive; whatever setup it needs (e.g. opening its own
// database) happens in its own constructor instead, before RegisterRoutes is called.
type CoreService interface {
	// Finalize releases the service's resources (e.g. closing a database). Called once
	// at shutdown, alongside every interceptor's own Finalize, bounded by the same
	// finalizeTimeout.
	Finalize()

	proxy.ApiProvider
}
