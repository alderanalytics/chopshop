package framework

import (
	"encoding"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/serenize/snaker"
)

// ContextHandlerFunc is a handler for determining the approprate API response.
type ContextHandlerFunc func(*RequestContext) Response

// RequestContext is a utility struct containing useful information about
// the request.
type RequestContext struct {
	w                 http.ResponseWriter
	r                 *http.Request
	token             *jwt.Token
	principal         *Principal
	framework         *Framework
	requestTime       time.Time
	destroyingSession bool
	routeVars         map[string]string
	queryValues       url.Values
}

// Principal defines a user identity.
type Principal struct {
	Username string   `json:"username"`
	UserID   uint64   `json:"user_id"`
	Rights   []string `json:"rights"`
}

func NewPrincipal(username string, user_id uint64, rights []string) *Principal {
	if rights == nil {
		rights = make([]string, 0)
	}

	return &Principal{
		Username: username,
		UserID:   user_id,
		Rights:   rights,
	}
}

var (
	unmarshalerTypes = []reflect.Type{
		reflect.TypeOf(new(json.Unmarshaler)).Elem(),
		reflect.TypeOf(new(encoding.TextUnmarshaler)).Elem(),
	}
)

// AddRight endows the current session with the specified right. The current
// session must be authenticated.
func (ctx *RequestContext) AddRight(right string) error {
	if !ctx.IsAuthenticated() {
		return errors.New("Session not authenticated.")
	}

	ctx.principal.Rights = append(ctx.principal.Rights, right)
	return nil
}

// RemoveRight removes the specified right from the current session.
// If the session is unauthenticated, the session has no rights and this call
// has no effect.
func (ctx *RequestContext) RemoveRight(right string) {
	if !ctx.IsAuthenticated() {
		return
	}

	rights := ctx.principal.Rights

	i := sort.Search(len(rights), func(i int) bool {
		return rights[i] == right
	})

	if i >= len(rights) {
		return
	}

	ctx.principal.Rights = append(rights[:i], rights[i+1:]...)
}

// HasRight returns true if the current request context has been granted the
// specified right.
func (ctx *RequestContext) HasRight(right string) bool {
	if ctx.principal == nil {
		return false
	}

	return hasItem(right, ctx.principal.Rights)
}

// RouteVar returns a value matching a variable portion of the route, or the
// empty string.
func (ctx *RequestContext) RouteVar(k string) string {
	if ctx.routeVars == nil {
		ctx.routeVars = mux.Vars(ctx.r)
	}

	if v, ok := ctx.routeVars[k]; ok {
		return v
	}

	return ""
}

// RouteModelID returns the id from the route, or an error if this fails.
func (ctx *RequestContext) RouteModelID() (uint64, error) {
	idstr := ctx.RouteVar("id")
	if idstr == "" {
		return 0, ErrModelIDNotPresent
	}

	id, err := strconv.ParseUint(idstr, 10, 64)
	if err != nil {
		return 0, err
	}

	return id, nil
}

// IsAuthenticated returns true if the session is authenticated.
func (ctx *RequestContext) IsAuthenticated() bool {
	return ctx.principal != nil
}

func (ctx *RequestContext) Username() string {
	if !ctx.IsAuthenticated() {
		return ""
	}

	return ctx.principal.Username
}

func (ctx *RequestContext) UserID() uint64 {
	if !ctx.IsAuthenticated() {
		return 0
	}

	return ctx.principal.UserID
}

// QueryVar returns the value of a query variable or the empty string if it is
// not present.
func (ctx *RequestContext) QueryVar(v string) string {
	if ctx.queryValues == nil {
		ctx.queryValues = ctx.r.URL.Query()
	}

	return ctx.queryValues.Get(v)
}

// SetPrincipal sets the security principal.
func (ctx *RequestContext) SetPrincipal(username string, user_id uint64, rights []string) {
	ctx.principal = NewPrincipal(username, user_id, rights)
}

// DestroyPrincipal removes the security principal from the session.
func (ctx *RequestContext) DestroyPrincipal() {
	ctx.principal = nil
}

// GetSession retrives an item from the session store.
func (ctx *RequestContext) GetSession(key string) (interface{}, bool) {
	vars := ctx.token.Claims["vars"].(map[string]interface{})
	val, ok := vars[key]
	return val, ok
}

// HasSession tests for an item in the session store.
func (ctx *RequestContext) HasSession(key string) bool {
	vars := ctx.token.Claims["vars"].(map[string]interface{})
	_, ok := vars[key]
	return ok
}

// PutSession sets an item in the session store.
func (ctx *RequestContext) PutSession(key string, value interface{}) {
	vars := ctx.token.Claims["vars"].(map[string]interface{})
	vars[key] = value
}

// DeleteSession deletes an item from the session store.
func (ctx *RequestContext) DeleteSession(key string) {
	vars := ctx.token.Claims["vars"].(map[string]interface{})
	delete(vars, key)
}

// XSRFToken gets the session XSRF token.
func (ctx *RequestContext) XSRFToken() string {
	return ctx.SessionID()
}

// SessionID gets the session identifier.
func (ctx *RequestContext) SessionID() string {
	if sessionID, ok := ctx.token.Claims["jti"]; ok {
		return sessionID.(string)
	}

	return ""
}

// ReadJSONUnsafe deserializes a JSON encoded request body.
func (ctx *RequestContext) ReadJSONUnsafe(v interface{}) error {
	return json.NewDecoder(ctx.r.Body).Decode(v)
}

// This is wrong but works well enough for our app.
func isRecursibleType(rv reflect.Value) bool {
	ty := rv.Type()
	if ty.Kind() == reflect.Struct {
		for _, umType := range unmarshalerTypes {
			if ty.Implements(umType) || reflect.PtrTo(ty).Implements(umType) {
				return false
			}
		}
		return true
	}
	return false
}

// safeMerge merges the fields of src into dst provided that the current context
// has the right to write the given field.
func (ctx *RequestContext) safeMerge(src, dst reflect.Value) (err error) {
	ty := dst.Type()
	for i := 0; i < dst.NumField(); i++ {
		w := ty.Field(i).Tag.Get("writeRight")
		if w == "" || ctx.HasRight(w) {
			srcField := src.Field(i)
			dstField := dst.Field(i)
			if isRecursibleType(srcField) {
				err = ctx.safeMerge(srcField, dstField)
				if err != nil {
					return
				}
			} else {
				dstField.Set(srcField)
			}
		}
	}

	return nil
}

func (ctx *RequestContext) safeSerializeStruct(src reflect.Value, out map[string]interface{}) (interface{}, error) {
	if out == nil {
		out = make(map[string]interface{})
	}

	ty := src.Type()
	for i := 0; i < src.NumField(); i++ {
		field := ty.Field(i)

		r := field.Tag.Get("readWrite")
		if r == "" || ctx.HasRight(r) {
			// ensure we're supposed to serialize this field
			name, opts := parseJSONTag(field.Tag.Get("json"))
			if name == "-" || hasJSONOption("omitempty", opts) && isEmpty(src.Field(i)) {
				continue
			}

			// if its anonymous merge in the child fields
			if name == "" && field.Name == "" {
				_, err := ctx.safeSerializeStruct(src, out)
				if err != nil {
					return nil, err
				}

				continue
			}

			if name == "" {
				name = snaker.CamelToSnake(field.Name)
			}

			val, err := ctx.safeSerialize(src.Field(i))
			if err != nil {
				return nil, err
			}

			out[name] = val
		}
	}
	return out, nil
}

func (ctx *RequestContext) safeSerializeSlice(src reflect.Value) (interface{}, error) {
	slice := make([]interface{}, 0)
	for i := 0; i < src.Len(); i++ {
		val, err := ctx.safeSerialize(src.Index(i))
		if err != nil {
			return nil, err
		}
		slice = append(slice, val)
	}
	return slice, nil
}

// safeSerialize recursively converts a struct into a map[string]interface{}
// omitting fields for which the current context lacks the "read" right.
func (ctx *RequestContext) safeSerialize(src reflect.Value) (ifc interface{}, err error) {
	switch src.Type().Kind() {
	case reflect.Slice:
		ifc, err = ctx.safeSerializeSlice(src)
	case reflect.Struct:
		if m, ok := src.Interface().(encoding.TextMarshaler); ok {
			ifc, err = m, nil
		} else {
			ifc, err = ctx.safeSerializeStruct(src, nil)
		}
	case reflect.Ptr:
		ifc, err = ctx.safeSerialize(src.Elem())
	default:
		ifc, err = src.Interface(), nil
	}

	return
}

// ReadJSON sets fields of v if the principal possesses the required rights.
func (ctx *RequestContext) ReadJSON(v interface{}) error {
	rv := reflect.ValueOf(v)
	ru := reflect.New(rv.Elem().Type()).Elem()

	err := ctx.ReadJSONUnsafe(ru.Addr().Interface())
	if err != nil {
		return err
	}

	return ctx.safeMerge(ru, rv.Elem())
}

// JSONResponse returns a JSONResponse which only contains fields for which
// the current context possesses the "read" right, or an error response if
// that fails.
func (ctx *RequestContext) JSONResponse(v interface{}) Response {
	response, _ := ctx.MakeJSONResponse(v)
	return response
}

// MakeJSONResponse returns a JSONResponse which only contains fields for which
// the current context possesses the "read" right, or an error if it fails.
func (ctx *RequestContext) MakeJSONResponse(v interface{}) (Response, error) {
	out, err := ctx.safeSerialize(reflect.ValueOf(v))
	if err != nil {
		return ctx.ErrorResponse(err, http.StatusInternalServerError), err
	}
	return JSONResponse(out), nil
}

// CustomErrorMessage returns an error message to be shown to the user for a
// given error. This function acts as a hook allowing the framework to control
// what response the user may see.
func (ctx *RequestContext) CustomErrorMessage(err error, friendly string) string {
	if err == nil || !ctx.HasRight("seeErrors") {
		return friendly
	}
	return err.Error()
}

func (ctx *RequestContext) errorMakeErrorContext(err error, status int, ectx *ErrorContext) {
	ectx.Error = fmt.Sprintf("Server Error: %s", err)
	ectx.Details = make(ErrorDetails)
	ectx.Details["status"] = status
	ectx.Details["session_id"] = ctx.SessionID()
	ectx.Details["user_id"] = ctx.UserID()
	ectx.Details["username"] = ctx.Username()
	ectx.Details["is_authenticated"] = ctx.IsAuthenticated()
	ectx.Details["url"] = ctx.r.URL.String()
	ectx.Details["host"] = ctx.r.Host
}

// BlankErrorResponse logs an error and returns a blank response
func (ctx *RequestContext) BlankErrorResponse(err error, status int) Response {
	if status >= 500 {
		ctx.NotifyError(err, status)
	}

	return BlankResponse(status)
}

// ErrorResponse returns an error response containing the message from
// ErrorMessage.
func (ctx *RequestContext) ErrorResponse(err error, status int) Response {
	return ctx.CustomErrorResponse(err, ctx.framework.defaultErrorText, status)
}

// CustomErrorResponse returns an error resposne to the user with a custom
// message.
func (ctx *RequestContext) CustomErrorResponse(err error, friendly string, status int) Response {
	if status >= 500 {
		ctx.NotifyError(err, status)
	}

	return ErrorResponse(ctx.CustomErrorMessage(err, friendly), status)
}

// NotifyError
func (ctx *RequestContext) NotifyError(err error, status int) {
	var ectx ErrorContext
	ctx.errorMakeErrorContext(err, status, &ectx)
	ctx.framework.Notify(&ectx)
}

// TemplateResponse constructs a response which renders a template.
func (ctx *RequestContext) TemplateResponse(template *template.Template, templateName string, data interface{}) ResponseFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := template.ExecuteTemplate(w, templateName, data); err != nil {
			ctx.NotifyError(err, http.StatusInternalServerError)
			http.Error(w, ctx.CustomErrorMessage(err, ctx.framework.defaultErrorText), http.StatusInternalServerError)
		}
	}
}

// SetBase64JSONCookie sets a cookie with a base64 encoded json.
func (ctx *RequestContext) SetBase64JSONCookie(name string, value interface{}) error {
	bytes, err := json.Marshal(value)
	if err != nil {
		return err
	}

	data := base64.URLEncoding.EncodeToString(bytes)
	ctx.SetCookie(name, data, false)
	return nil
}

// SetCookie creates a cookie.
func (ctx *RequestContext) SetCookie(name, value string, httpOnly bool) {
	http.SetCookie(ctx.w, &http.Cookie{
		Name:     name,
		Domain:   ctx.framework.CookieDomain,
		Value:    value,
		HttpOnly: httpOnly,
		Secure:   ctx.framework.HTTPSOnlyCookies,
		Path:     "/",
		Expires:  ctx.requestTime.Add(ctx.framework.SessionDuration),
	})
}

// DeleteCookie deletes a cookie on the request object.
func (ctx *RequestContext) DeleteCookie(name string) {
	ctx.framework.DeleteCookie(ctx.w, name)
}

// DestroySession instructs the client to delete all framework cookies
// containing session data.
func (ctx *RequestContext) DestroySession() {
	ctx.destroyingSession = true
}
