// SPDX-License-Identifier: Apache-2.0

// Package httpx holds the small helpers every handler package shares: JSON
// encoding, the error envelope, request decoding limits and pagination.
package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strconv"
	"strings"
)

// Error is the JSON error body shared by every endpoint. RequestID is the
// response's X-Request-Id: quoted in a bug report, it finds the log lines.
type Error struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

type requestIDKey struct{}

// WithRequestID returns ctx carrying the id the server gave the request.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestID returns the id the server gave the request, or "" outside it.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// Page wraps a list response.
type Page[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// WriteJSON writes v with the right headers.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes the error envelope for r.
func WriteError(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	WriteJSON(w, status, Error{Code: code, Message: msg, RequestID: RequestID(r.Context())})
}

// BadRequest is a convenience for validation failures.
func BadRequest(w http.ResponseWriter, r *http.Request, msg string) {
	WriteError(w, r, http.StatusBadRequest, "bad_request", msg)
}

// Internal logs err with the request's id and route, and answers 500 with
// no detail: the id in the body is what finds the log line. The route is the
// matched pattern, so the caller's own path never reaches the log, and the
// error is kept to one line.
func Internal(w http.ResponseWriter, r *http.Request, log *slog.Logger, err error) {
	if log == nil {
		log = slog.Default()
	}
	log.Error("request failed", "request_id", RequestID(r.Context()), "route", Route(r),
		"err", strings.NewReplacer("\n", " ", "\r", " ").Replace(err.Error()))
	WriteError(w, r, http.StatusInternalServerError, "internal", "internal error")
}

// Route names the handler that served r without echoing the request's own
// path: the matched pattern, which carries the method when the route was
// registered with one, otherwise prefixed with the method.
func Route(r *http.Request) string {
	if strings.HasPrefix(r.Pattern, r.Method+" ") {
		return r.Pattern
	}
	return strings.TrimSpace(r.Method + " " + r.Pattern)
}

// DecodeJSON reads a JSON body of at most 256 KiB, rejecting unknown fields
// so a typo in a client never silently drops a security-relevant setting.
func DecodeJSON(r *http.Request, v any) error {
	return DecodeJSONLimit(r, v, 256<<10)
}

// DecodeJSONLimit is DecodeJSON with a smaller or larger body limit. Its
// errors name the JSON field at fault, never the Go type behind it.
func DecodeJSONLimit(r *http.Request, v any, limit int64) error {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		return errors.New("content-type must be application/json")
	}
	// MaxBytesReader, not LimitReader: a body over the limit is named as
	// such instead of looking like one that ends early. The nil writer only
	// forgoes the server's close-after-reply hint.
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("malformed JSON body: " + jsonProblem(err, limit))
	}
	// One value and nothing after it: a second value, or text trailing the
	// first, would be read by nobody and is a client bug worth telling.
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return errors.New("malformed JSON body: " + jsonProblem(err, limit))
		}
		return errors.New("malformed JSON body: unexpected data after the JSON value")
	}
	return nil
}

// Paging reads ?limit= and ?cursor= with bounds.
func Paging(r *http.Request, def, ceiling int) (limit int, cursor string) {
	limit = def
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > ceiling {
		limit = ceiling
	}
	return limit, r.URL.Query().Get("cursor")
}

// jsonProblem says what is wrong with a body in the client's terms.
func jsonProblem(err error, limit int64) string {
	var typeErr *json.UnmarshalTypeError
	var syntaxErr *json.SyntaxError
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		return fmt.Sprintf("the body is larger than %d KiB", limit>>10)
	case errors.As(err, &typeErr):
		what := "the body"
		if typeErr.Field != "" {
			what = strconv.Quote(typeErr.Field)
		}
		got, _, _ := strings.Cut(typeErr.Value, " ") // "number -5" is a number
		return fmt.Sprintf("%s must be %s, not %s", what, jsonKind(typeErr.Type), article(got))
	case errors.As(err, &syntaxErr):
		return fmt.Sprintf("invalid JSON at byte %d", syntaxErr.Offset)
	case errors.Is(err, io.EOF):
		return "the body is empty"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "the body ends early"
	}
	// The decoder's own words for an unknown field, `json: unknown field "x"`,
	// name only what the client sent.
	if field, ok := strings.CutPrefix(err.Error(), "json: unknown field "); ok {
		return "unknown field " + field
	}
	return "it could not be read"
}

// jsonKind names the JSON value that fills a Go type.
func jsonKind(t reflect.Type) string {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil {
		return "a value"
	}
	switch t.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
		return "a number"
	case reflect.String:
		return "a string"
	case reflect.Bool:
		return "true or false"
	case reflect.Slice, reflect.Array:
		return "a list"
	case reflect.Map, reflect.Struct:
		return "an object"
	default:
		return "a value"
	}
}

// article names a JSON value kind as encoding/json reports it ("bool",
// "array") in the same words as jsonKind.
func article(kind string) string {
	switch kind {
	case "number":
		return "a number"
	case "string":
		return "a string"
	case "bool":
		return "true or false"
	case "array":
		return "a list"
	case "object":
		return "an object"
	case "null":
		return "null"
	default:
		return "that"
	}
}
