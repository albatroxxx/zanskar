// SPDX-License-Identifier: Apache-2.0

// Package winrmtest is a stand-in WinRM listener for tests: enough
// WS-Management over TLS for the real client to open a shell, run
// PowerShell lines and read their output. Release builds never import it.
package winrmtest

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/text/encoding/unicode"
)

// Server is a WinRM listener over TLS that speaks just enough
// WS-Management for the client: open a shell, run a command, return its
// output and exit code, signal and delete. A command echoes its PowerShell
// line; "exit N" in the line sets the exit code. User "admin" with password
// "pw-1" may open a shell; "limited" authenticates but gets the access-denied
// fault a real target sends to a non-administrator; anything else is 401.
type Server struct {
	srv *httptest.Server
	// Requests counts every request that reached the listener.
	Requests atomic.Int32
	lastLine atomic.Value // string
}

const wsmanEnvelope = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Header><a:Action>%s</a:Action></s:Header><s:Body>%s</s:Body></s:Envelope>`

var encodedCommand = regexp.MustCompile(`-EncodedCommand ([A-Za-z0-9+/=]+)`)

// New starts the listener for the life of the test.
func New(t *testing.T) *Server {
	t.Helper()
	f := &Server{}
	f.lastLine.Store("")
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.Requests.Add(1)
		user, pass, _ := r.BasicAuth()
		switch {
		case user == "limited" && pass == "pw-1":
			w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprint(w, `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault><s:Detail><f:WSManFault xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="5"><f:Message>Access is denied.</f:Message></f:WSManFault></s:Detail></s:Fault></s:Body></s:Envelope>`)
			return
		case user != "admin" || pass != "pw-1":
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		reply := func(action, inner string) {
			w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")
			_, _ = fmt.Fprintf(w, wsmanEnvelope, action, inner)
		}
		const shell = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/"
		switch {
		case bytes.Contains(body, []byte("transfer/Create<")):
			reply("http://schemas.xmlsoap.org/ws/2004/09/transfer/CreateResponse", `<rsp:Shell><rsp:ShellId>S1</rsp:ShellId></rsp:Shell>`)
		case bytes.Contains(body, []byte(shell+"Command<")):
			if m := encodedCommand.FindSubmatch(body); m != nil {
				raw, _ := base64.StdEncoding.DecodeString(string(m[1]))
				line, _ := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().Bytes(raw)
				f.lastLine.Store(strings.TrimPrefix(string(line), "$ProgressPreference = 'SilentlyContinue';"))
			}
			reply(shell+"CommandResponse", `<rsp:CommandResponse><rsp:CommandId>C1</rsp:CommandId></rsp:CommandResponse>`)
		case bytes.Contains(body, []byte(shell+"Receive<")):
			line := f.lastLine.Load().(string)
			code := 0
			if i := strings.Index(line, "exit "); i >= 0 {
				code, _ = strconv.Atoi(strings.TrimSpace(line[i+5:]))
			}
			out := base64.StdEncoding.EncodeToString([]byte("ran: " + line + "\r\n"))
			reply(shell+"ReceiveResponse", `<rsp:ReceiveResponse><rsp:Stream Name="stdout" CommandId="C1">`+out+`</rsp:Stream>`+
				`<rsp:Stream Name="stdout" CommandId="C1" End="true"></rsp:Stream>`+
				`<rsp:CommandState CommandId="C1" State="`+shell+`CommandState/Done"><rsp:ExitCode>`+strconv.Itoa(code)+`</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`)
		case bytes.Contains(body, []byte(shell+"Signal<")):
			reply(shell+"SignalResponse", `<rsp:SignalResponse/>`)
		default: // Delete
			reply("http://schemas.xmlsoap.org/ws/2004/09/transfer/DeleteResponse", ``)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// Address returns the listener's host and port.
func (f *Server) Address(t *testing.T) (string, int) {
	t.Helper()
	host, port, err := net.SplitHostPort(f.srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(port)
	return host, p
}

// Fingerprint is the SHA-256 of the listener's certificate, in hex, as a
// target pins it.
func (f *Server) Fingerprint() string {
	sum := sha256.Sum256(f.srv.Certificate().Raw)
	return hex.EncodeToString(sum[:])
}
