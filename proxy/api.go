package proxy

import "net/http"

// ApiProvider is an optional interface interceptors can implement to expose HTTP endpoints.
// RegisterRoutes is called once at startup with an http.ServeMux and the interceptor's
// dedicated base path (/<proxy-name>/api/i/<interceptor-name>).
type ApiProvider interface {
	RegisterRoutes(mux *http.ServeMux, basePath string)
}
