// SPDX-License-Identifier: Apache-2.0

package httpx

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDecodeJSONNamesFieldsNotGoTypes: a 400 told the client about the
// server's internals, as in "cannot unmarshal string into Go struct field
// createInput.minutes of type int" (Q8). It names the JSON field and the
// JSON kinds now.
func TestDecodeJSONNamesFieldsNotGoTypes(t *testing.T) {
	type nested struct {
		Port int `json:"port"`
	}
	var into struct {
		Minutes int               `json:"minutes"`
		Name    string            `json:"name"`
		On      *bool             `json:"on"`
		Tags    []string          `json:"tags"`
		Labels  map[string]string `json:"labels"`
		Inner   nested            `json:"inner"`
	}
	for _, c := range []struct{ body, want string }{
		{`{"minutes":"60"}`, `"minutes" must be a number, not a string`},
		{`{"name":5}`, `"name" must be a string, not a number`},
		{`{"on":"yes"}`, `"on" must be true or false, not a string`},
		{`{"tags":"a"}`, `"tags" must be a list, not a string`},
		{`{"labels":[1]}`, `"labels" must be an object, not a list`},
		{`{"inner":{"port":-5.5}}`, `"inner.port" must be a number`},
		{`[1]`, `the body must be an object, not a list`},
		{`{"minutes":`, `the body ends early`},
		{`{"minutes":}`, `invalid JSON at byte`},
		{``, `the body is empty`},
		{`{"secret_field":1}`, `unknown field "secret_field"`},
		{`{"minutes":1} {"minutes":2}`, `unexpected data after the JSON value`},
		{`{"minutes":1} trailing`, `unexpected data after the JSON value`},
		{`{"name":"` + strings.Repeat("a", 256<<10) + `"}`, `the body is larger than 256 KiB`},
	} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(c.body))
		r.Header.Set("Content-Type", "application/json")
		err := DecodeJSON(r, &into)
		if err == nil {
			t.Errorf("%s: decoded", c.body)
			continue
		}
		msg := err.Error()
		if !strings.Contains(msg, c.want) {
			t.Errorf("%s: got %q, want it to contain %q", c.body, msg, c.want)
		}
		for _, leak := range []string{"Go ", "struct", "int64", "nested", "json:"} {
			if strings.Contains(msg, leak) {
				t.Errorf("%s: %q gives away %q", c.body, msg, leak)
			}
		}
	}
}

// TestDecodeJSONAcceptsWhitespaceAfterTheValue: a trailing newline, as every
// JSON encoder and curl -d @file writes, is not "data after the value".
func TestDecodeJSONAcceptsWhitespaceAfterTheValue(t *testing.T) {
	var into struct {
		Minutes int `json:"minutes"`
	}
	for _, body := range []string{"{\"minutes\":1}\n", "{\"minutes\":1}\r\n\t ", " {\"minutes\":1}"} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if err := DecodeJSON(r, &into); err != nil || into.Minutes != 1 {
			t.Errorf("%q: %v (minutes=%d)", body, err, into.Minutes)
		}
	}
}
