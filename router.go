package chopshop

import (
	"net/http"

	"github.com/gorilla/mux"
)

// FIXME: use strict slashes

// Route wraps Gorilla Route
type Route struct {
	f  *Framework
	r  *mux.Route
	mw Middleware
}

func wrapRoute(r *mux.Route, f *Framework, mw Middleware) *Route {
	return &Route{f: f, r: r, mw: mw}
}

// Assets attaches a handler which resolves the request against the AssetHandler
// chain given by the arguments.
func (r *Route) Assets(chain ...AssetHandler) {
	r.AssetResolver(NewAssetResolver(chain...))
}

// AssetResolver attaches a handler which invokes the given AssetResolver.
func (r *Route) AssetResolver(a *AssetResolver) {
	r.Handler(AssetResolverResponse(a))
}

// Response serves a response at the specified endpoint.
func (r *Route) Response(response Response) {
	r.Handler(SingleResponseContextHandlerFunc(response))
}

// Handler mounts a ContextHandlerFunc at the specified endpoint.
func (r *Route) Handler(fn ContextHandlerFunc) {
	r.unsafeHandler(http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			if r.mw != nil {
				fn = r.mw(fn)
			}
			r.f.ServeContext(r.f.ContextFor(req), fn)
		}))
}

func (r *Route) unsafeHandler(handler http.Handler) {
	r.r.Handler(handler)
}

// Methods restrict the HTTP Verbs which match the route.
func (r *Route) Methods(methods ...string) *Route {
	r.r.Methods(methods...)
	return r
}

// Middleware applies a middleware handler to the specified route.
func (r *Route) Middleware(mws ...Middleware) *Route {
	r.mw = composeMiddleware(mws...)
	return r
}

// Router wraps Gorilla Router for adding CRUD helpers
type Router struct {
	f  *Framework
	r  *mux.Router
	mw Middleware
}

func newRouter(f *Framework) *Router {
	return wrapRouter(mux.NewRouter(), f, nil)
}

func wrapRouter(r *mux.Router, f *Framework, mw Middleware) *Router {
	return &Router{r: r, f: f, mw: mw}
}

// PathPrefix returns a route relative to the specified prefix.
func (r *Router) PathPrefix(tpl string) *Route {
	return wrapRoute(r.r.PathPrefix(tpl), r.f, r.mw)
}

// Path returns a route for the specified prefix.
func (r *Router) Path(path string) *Route {
	return wrapRoute(r.r.Path(path), r.f, r.mw)
}

// Middleware adds middleware to the router to be applied on all endpoints.
func (r *Router) Middleware(mws ...Middleware) *Router {
	r.mw = composeMiddleware(mws...)
	return r
}

// Subrouter returns a router relative to the specified prefix.
func (r *Router) Subrouter(tpl string) *Router {
	return wrapRouter(r.PathPrefix(tpl).r.Subrouter(), r.f, r.mw)
}

// ServeHTTP adapts Router to be used an http.Handler
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.r.ServeHTTP(w, req)
}
