// SPDX-License-Identifier: Apache-2.0

// Package httpx holds the small helpers every handler package shares: JSON
// encoding, the error envelope, request decoding limits and pagination.
package httpx

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Error is the JSON error body shared by every endpoint.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
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

// WriteError writes the error envelope.
func WriteError(w http.ResponseWriter, status int, code, msg string) {
	WriteJSON(w, status, Error{Code: code, Message: msg})
}

// DecodeJSON reads a JSON body of at most 256 KiB, rejecting unknown fields
// so a typo in a client never silently drops a security-relevant setting.
func DecodeJSON(r *http.Request, v any) error {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		return errors.New("content-type must be application/json")
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 256<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("malformed JSON body: " + err.Error())
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

// BadRequest is a convenience for validation failures.
func BadRequest(w http.ResponseWriter, msg string) {
	WriteError(w, http.StatusBadRequest, "bad_request", msg)
}
