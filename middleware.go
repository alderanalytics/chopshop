package chopshop

import (
	"net/http"
)

// Middleware is a function which consumes a ContextHandlerFunc producing a
// new ContextHandlerFunc
type Middleware func(ContextHandlerFunc) ContextHandlerFunc

func composeMiddlewarePair(mw1, mw2 Middleware) Middleware {
	return func(h ContextHandlerFunc) ContextHandlerFunc {
		return mw1(mw2(h))
	}
}

func composeMiddleware(mws ...Middleware) Middleware {
	var mwc Middleware
	for _, mw := range mws {
		if mwc == nil {
			mwc = mw
			continue
		}

		mwc = composeMiddlewarePair(mw, mwc)
	}

	return mwc
}

// XSRFMiddleware returns EmptyJSONResponse(401) unless the X-XSRF-Token header
// is present and its content matches the context XSRF token.
func XSRFMiddleware(fn chopshop.ContextHandlerFunc) chopshop.ContextHandlerFunc {
	return func(ctx *chopshop.RequestContext) chopshop.Response {
		xsrfHeader := ctx.Request.Header.Get("X-XSRF-Token")
		if xsrfHeader == "" || ctx.XSRFToken() != xsrfHeader {
			return chopshop.EmptyJSONResponse(http.StatusUnauthorized)
		}

		return fn(ctx)
	}
}

// RightCheckMiddleware constructs a middleware that returns
// EmptyJSONResponse(401) if the session not authenticated or if it does not
// posseses the specified right.
func RightCheckMiddleware(right string) chopshop.Middleware {
	return func(fn chopshop.ContextHandlerFunc) chopshop.ContextHandlerFunc {
		return func(ctx *chopshop.RequestContext) chopshop.Response {
			if !ctx.IsAuthenticated() || !ctx.HasRight(right) {
				return chopshop.EmptyJSONResponse(http.StatusUnauthorized)
			}

			return fn(ctx)
		}
	}
}
