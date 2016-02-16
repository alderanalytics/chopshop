package framework

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Response is a http.HandlerFunc used to respond to a request.
type Response interface {
	ServeHTTP(http.ResponseWriter, *http.Request)
	Cancel()
}

type ResponseFunc func(w http.ResponseWriter, r *http.Request)

func (f ResponseFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f(w, r)
}

func (f ResponseFunc) Cancel() {}

// SingleResponseContextHandlerFunc constructs a ContextHandlerFunc which
// returns the specified response.
func SingleResponseContextHandlerFunc(r Response) ContextHandlerFunc {
	return func(ctx *RequestContext) Response {
		return r
	}
}

// BlankResponse constructs a blank response with the specified status code.
func BlankResponse(status int) ResponseFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}
}

func EmptyJSONResponse(status int) ResponseFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprintf(w, "{}")
	}
}

// JSONResponse constructs a response containing the json serialization of
// the given value.
func JSONResponse(v interface{}) ResponseFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	}
}

// ErrorMessage holds http status codes and a message.
type ErrorMessage struct {
	Status  int    `json:"-"`
	Message string `json:"message"`
}

// ErrorResponse constructs a response containing a json encoded error.
func ErrorResponse(message string, status int) ResponseFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(ErrorMessage{Status: status, Message: message})
	}
}

// RedirectResponse constructs a response which performs an http redirect
func RedirectResponse(path string, status int) ResponseFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, path, status)
	}
}

// StreamResponse constructs a response which wraps a Reader.
type Streamer struct {
	contentType string
	rc          io.ReadCloser
}

func (s *Streamer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer s.rc.Close()
	w.Header().Set("Content-Type", s.contentType)
	io.Copy(w, s.rc)
}

func (s *Streamer) Cancel() {
	s.rc.Close()
}

// StreamResponse constructs a response which wraps a Reader.
func StreamResponse(contentType string, rc io.ReadCloser) Response {
	return &Streamer{contentType: contentType, rc: rc}
}
