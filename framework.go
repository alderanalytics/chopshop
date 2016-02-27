package chopshop

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/alderanalytics/snitch"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
	"github.com/twinj/uuid"
)

// Errors produced by the framework
var (
	ErrModelIDNotPresent          = errors.New("route missing model id")
	ErrUnexpectedJWTSigningMethod = errors.New("unexpected JWT signing method")
	ErrInvalidJWT                 = errors.New("invalid JWT")
)

type key int

const (
	keyRequestContext key = iota
)

// Framework is a middleware enforcing security and providing higher level
// handlers.
type Framework struct {
	HTTPSOnlyCookies bool
	SessionSecret    []byte
	IssuerName       string
	SessionDuration  time.Duration
	ErrorReporter    snitch.ErrorReporter
	CookieDomain     string
	jwtCookieName    string
	xsrfCookieName   string
	userCookieName   string
	defaultErrorText string
	*Router
}

// PanicMonitor reports unhandled panics and optionally repanics
func (f *Framework) PanicMonitor(repanic bool) {
	if err := recover(); err != nil {
		if f.ErrorReporter == nil {
			return
		}

		ectx := snitch.ErrorContext{
			Error: fmt.Sprintf("panic: %s", err),
		}

		f.Notify(&ectx)

		if repanic {
			panic(err)
		}
	}
}

// Notify invokes the attached error reporting service, if any,
// provided that the ErrorContext pointer is not nil
func (f *Framework) Notify(ectx *snitch.ErrorContext) {
	if f.ErrorReporter != nil && ectx != nil {
		f.ErrorReporter.Notify(ectx)
	}
}

// Host returns a route which matches only a specific host.
func (f *Framework) Host(host string) *Router {
	return wrapRouter(f.Router.r.Host(host).Subrouter(), f, nil)
}

// NewFramework constructs a new framework.
func NewFramework(issuer string, cookieDomain string) (*Framework, error) {
	f := &Framework{
		IssuerName:       issuer,
		CookieDomain:     cookieDomain,
		jwtCookieName:    fmt.Sprintf("_%s_token", issuer),
		xsrfCookieName:   fmt.Sprintf("_%s_xsrf", issuer),
		userCookieName:   fmt.Sprintf("_%s_user", issuer),
		defaultErrorText: "An error has occurred. Please try the app again later.",
	}

	f.Router = newRouter(f)
	return f, nil
}

// ReadToken reads the JWT token from a cookie and validates its signature.
func (f *Framework) ReadToken(r *http.Request) (*jwt.Token, error) {
	tokenCookie, err := r.Cookie(f.jwtCookieName)
	if err == http.ErrNoCookie {
		return nil, nil
	}

	parser := jwt.Parser{UseJSONNumber: true}
	token, err := parser.Parse(tokenCookie.Value,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, ErrUnexpectedJWTSigningMethod
			}

			return f.SessionSecret, nil
		})

	if err != nil {
		return nil, err
	}

	return token, nil
}

// BeforeResponse is a hook that fires after the context handler has finished
// but before the response is sent.
func (f *Framework) BeforeResponse(ctx *RequestContext) {
	if ctx.destroyingSession {
		f.DestroySession(ctx.ResponseWriter)
		return
	}

	ctx.token.Claims["sub"] = ctx.principal
	if ctx.principal != nil {
		ctx.SetBase64JSONCookie(f.userCookieName, map[string]interface{}{
			"rights": ctx.principal.Rights,
		})
	} else {
		f.DeleteCookie(ctx.ResponseWriter, f.userCookieName)
	}

	f.SendToken(ctx.ResponseWriter, ctx.token)
	ctx.SetCookie(f.xsrfCookieName, ctx.XSRFToken(), false)
}

// SendToken signs and sends the associated jwt to the client.
func (f *Framework) SendToken(w http.ResponseWriter, token *jwt.Token) error {
	tokenStr, err := token.SignedString(f.SessionSecret)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     f.jwtCookieName,
		Domain:   f.CookieDomain,
		Value:    tokenStr,
		HttpOnly: true,
		Secure:   f.HTTPSOnlyCookies,
		Path:     "/",
		Expires:  time.Now().Add(f.SessionDuration),
	})

	return nil
}

// DestroySession deletes the xsrf and jwt tokens corresponding to the
// framework IssuerName.
func (f *Framework) DestroySession(w http.ResponseWriter) {
	f.DeleteCookie(w, f.xsrfCookieName)
	f.DeleteCookie(w, f.jwtCookieName)
	f.DeleteCookie(w, f.userCookieName)
}

// DeleteCookie deletes a cookie.
func (f *Framework) DeleteCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:    name,
		Domain:  f.CookieDomain,
		Path:    "/",
		Expires: time.Unix(1, 0),
	})
}

//FIXME: simplify below by upgrading to v3 of jwt-go (when released)
func (f *Framework) readPrincipal(token *jwt.Token) (p *Principal, err error) {
	if token == nil {
		return
	}

	sub, ok := token.Claims["sub"].(map[string]interface{})
	if !ok {
		return
	}

	username, okUser := sub["username"].(string)
	irights, okRights := sub["rights"].([]interface{})
	userIDN, okUserID := sub["user_id"].(json.Number)

	var userID uint64
	if okUserID {
		userID, err = jsonNumberToUint64(userIDN)
		okUserID = err == nil
	}

	if !okUser || !okRights || !okUserID {
		return nil, ErrInvalidJWT
	}

	rights, err := ifSliceToStrSlice(irights)
	if err != nil {
		return nil, ErrInvalidJWT
	}

	return NewPrincipal(username, userID, rights), nil
}

// CreateRequestContext constructs and returns a validated request context from
// an HTTP request.
func (f *Framework) CreateRequestContext(w http.ResponseWriter, r *http.Request) (*RequestContext, error) {
	token, err := f.ReadToken(r)
	if err != nil {
		//if we can't read the token lets transparently build a new one.
		token = nil
	}

	if token == nil {
		token = f.buildToken()
	}

	principal, err := f.readPrincipal(token)
	if err != nil {
		return nil, err
	}

	return &RequestContext{
		ResponseWriter: w,
		Request:        r,
		token:          token,
		principal:      principal,
		framework:      f,
		requestTime:    time.Now(),
	}, nil
}

// ContextFor returns the RequestContext corresponding to the http.Request
func (f *Framework) ContextFor(r *http.Request) *RequestContext {
	if val, ok := context.GetOk(r, keyRequestContext); ok {
		return val.(*RequestContext)
	}

	return nil
}

func (f *Framework) buildToken() *jwt.Token {
	token := jwt.New(jwt.SigningMethodHS512)
	token.Claims["iss"] = f.IssuerName
	token.Claims["sub"] = nil
	token.Claims["jti"] = uuid.NewV4().String()
	token.Claims["iat"] = time.Since(time.Unix(0, 0)).Seconds()
	token.Claims["vars"] = make(map[string]interface{})
	return token
}

// ServeHTTP adapts Framework for use as an http.Handler
func (f *Framework) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer f.PanicMonitor(false)

	ctx, err := f.CreateRequestContext(w, r)
	if err != nil {
		f.DestroySession(w)
		ErrorResponse(f.defaultErrorText, http.StatusBadRequest).ServeHTTP(w, r)
		return
	}

	context.Set(r, keyRequestContext, ctx)
	defer context.Clear(r)

	f.Router.ServeHTTP(w, r)
}

// ServeContext serves the request by applying the ContextHandlerFunc to the
// current context.
func (f *Framework) ServeContext(ctx *RequestContext, fn ContextHandlerFunc) {
	response := fn(ctx)
	f.BeforeResponse(ctx)
	response.ServeHTTP(ctx.ResponseWriter, ctx.Request)
}

func hasItem(item string, list []string) bool {
	for _, v := range list {
		if v == item {
			return true
		}
	}

	return false
}

func jsonNumberToUint64(n json.Number) (val uint64, err error) {
	val, err = strconv.ParseUint(n.String(), 10, 64)
	return
}
