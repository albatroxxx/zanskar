// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/bootedit"
)

// helperEnv is a working proxy-mode environment file and a state directory.
func helperEnv(t *testing.T) (env, state string) {
	t.Helper()
	dir := t.TempDir()
	env, state = filepath.Join(dir, "env"), filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o750); err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	body := "# Zanskar\nZANSKAR_MASTER_KEY=" + key + "\nZANSKAR_DB_DSN=file:" + filepath.Join(dir, "z.db") +
		"\nZANSKAR_TLS_MODE=proxy\nZANSKAR_LISTEN_ADDR=127.0.0.1:8443\nZANSKAR_TRUST_PROXY_TLS=true\n"
	if err := os.WriteFile(env, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	// The package's umask (0077) narrowed it; the packaged file is 0640.
	if err := os.Chmod(env, 0o640); err != nil {
		t.Fatal(err)
	}
	return env, state
}

func request(t *testing.T, state string, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(state, bootedit.RequestFile), []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
}

func result(t *testing.T, state string) bootedit.Result {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(state, bootedit.ResultFile))
	if err != nil {
		t.Fatal(err)
	}
	var r bootedit.Result
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// fakeHost records systemctl and answers /readyz as told.
type fakeHost struct {
	runs    [][]string
	healthy bool
	asked   []string
}

func (f *fakeHost) helper(env, state string) *configHelper {
	return &configHelper{Env: env, State: state, Wait: 50 * time.Millisecond,
		Run: func(_ context.Context, name string, args ...string) error {
			f.runs = append(f.runs, append([]string{name}, args...))
			return nil
		},
		Health: func(_ context.Context, port string) error {
			f.asked = append(f.asked, port)
			if f.healthy {
				return nil
			}
			return errors.New("connection refused")
		},
	}
}

// TestConfigApply (ADR 0020, amended 2026-10-30): the helper changes only
// what was asked, keeps the previous file, restarts, and reports applied
// once the gateway answers where the new file says it listens.
func TestConfigApply(t *testing.T) {
	env, state := helperEnv(t)
	before, _ := os.ReadFile(env)
	request(t, state, `{"id":"r1","tls_mode":"managed","values":{"ZANSKAR_PUBLIC_URL":"https://gw.example.com","ZANSKAR_ISSUER":"Acme Corp"}}`)
	host := &fakeHost{healthy: true}
	if err := host.helper(env, state).Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := result(t, state)
	if r.ID != "r1" || r.State != bootedit.Applied || !slices.Contains(r.Changed, "ZANSKAR_PUBLIC_URL") || !slices.Contains(r.Changed, "ZANSKAR_LISTEN_ADDR") {
		t.Fatalf("result: %+v", r)
	}
	after, _ := os.ReadFile(env)
	for _, want := range []string{"ZANSKAR_PUBLIC_URL=https://gw.example.com\n", "ZANSKAR_ISSUER=\"Acme Corp\"\n", "ZANSKAR_TLS_MODE=managed\n", "ZANSKAR_LISTEN_ADDR=:443\n", "ZANSKAR_HTTP_REDIRECT_ADDR=:80\n", "ZANSKAR_TRUST_PROXY_TLS=false\n"} {
		if !strings.Contains(string(after), want) {
			t.Errorf("new file lacks %q:\n%s", want, after)
		}
	}
	if keyLine := strings.Split(string(before), "\n")[1]; !strings.Contains(string(after), keyLine+"\n") {
		t.Fatal("the master key line changed")
	}
	if prev, _ := os.ReadFile(env + ".previous"); string(prev) != string(before) {
		t.Fatal("the previous file was not kept")
	}
	if st, _ := os.Stat(env); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v, want 0640", st.Mode().Perm())
	}
	if len(host.runs) != 1 || strings.Join(host.runs[0], " ") != "systemctl restart zanskar" {
		t.Fatalf("runs: %v", host.runs)
	}
	if len(host.asked) == 0 || host.asked[0] != "443" {
		t.Fatalf("health asked about port %v, want the new file's 443", host.asked)
	}
	if _, err := os.Stat(filepath.Join(state, bootedit.RequestFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the request must be gone")
	}
	if strings.Contains(mustRead(t, filepath.Join(state, bootedit.ResultFile)), "ZANSKAR_MASTER_KEY=") {
		t.Fatal("the result names the master key's value")
	}
}

// TestConfigApplyRefuses: a request outside the allowlist, a hostile one
// and one the gateway would not start with each leave the file as it was,
// restart nothing, and say why.
func TestConfigApplyRefuses(t *testing.T) {
	for name, body := range map[string]string{
		"install-only key": `{"id":"r2","values":{"ZANSKAR_DB_DSN":"postgres://evil"}}`,
		"injected line":    `{"id":"r3","values":{"ZANSKAR_ISSUER":"x\nZANSKAR_DOCKER_PATH=/tmp/sh"}}`,
		"unknown field":    `{"id":"r4","exec":"sh"}`,
		"not JSON":         `ZANSKAR_DB_DSN=x`,
		"too big":          `{"id":"` + strings.Repeat("a", bootedit.MaxRequest) + `"}`,
		"bad value":        `{"id":"r5","values":{"ZANSKAR_LOG_FORMAT":"yaml"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			env, state := helperEnv(t)
			before, _ := os.ReadFile(env)
			request(t, state, body)
			host := &fakeHost{healthy: true}
			if err := host.helper(env, state).Apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			if r := result(t, state); r.State != bootedit.Refused || r.Message == "" {
				t.Fatalf("result: %+v", r)
			}
			if after, _ := os.ReadFile(env); string(after) != string(before) {
				t.Fatal("a refused request changed the file")
			}
			if len(host.runs) != 0 {
				t.Fatalf("a refused request restarted: %v", host.runs)
			}
			for _, leftover := range []string{bootedit.RequestFile} {
				if _, err := os.Stat(filepath.Join(state, leftover)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("%s left behind", leftover)
				}
			}
			if _, err := os.Stat(env + ".new"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("a refused candidate was left behind")
			}
		})
	}
}

// TestConfigApplyChecksTheNewFile: a valid change to a file serve would
// refuse (here, one with no master key) is not written: config check runs
// on the candidate before it replaces anything.
func TestConfigApplyChecksTheNewFile(t *testing.T) {
	env, state := helperEnv(t)
	before, _ := os.ReadFile(env)
	var kept []string
	for _, l := range strings.Split(string(before), "\n") {
		if !strings.HasPrefix(l, "ZANSKAR_MASTER_KEY=") {
			kept = append(kept, l)
		}
	}
	if err := os.WriteFile(env, []byte(strings.Join(kept, "\n")), 0o640); err != nil {
		t.Fatal(err)
	}
	before, _ = os.ReadFile(env)
	request(t, state, `{"id":"r7","values":{"ZANSKAR_LOG_FORMAT":"text"}}`)
	host := &fakeHost{healthy: true}
	if err := host.helper(env, state).Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r := result(t, state); r.State != bootedit.Refused || !strings.Contains(r.Message, "would not start") {
		t.Fatalf("result: %+v", r)
	}
	if after, _ := os.ReadFile(env); string(after) != string(before) || len(host.runs) != 0 {
		t.Fatal("a file serve would refuse was written or restarted")
	}
}

// TestConfigApplyRollsBack: when the gateway does not come back with the new
// file, the previous file goes back and the gateway restarts on it.
func TestConfigApplyRollsBack(t *testing.T) {
	env, state := helperEnv(t)
	before, _ := os.ReadFile(env)
	request(t, state, `{"id":"r6","tls_mode":"managed"}`)
	host := &fakeHost{healthy: false}
	if err := host.helper(env, state).Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := result(t, state)
	if r.State != bootedit.RolledBack || !strings.Contains(r.Message, "the previous file is back") {
		t.Fatalf("result: %+v", r)
	}
	if after, _ := os.ReadFile(env); string(after) != string(before) {
		t.Fatalf("the previous file is not back:\n%s", after)
	}
	if len(host.runs) != 2 {
		t.Fatalf("restarts: %v, want one for the change and one for the rollback", host.runs)
	}
}

// TestConfigApplyWithoutARequest does nothing at all.
func TestConfigApplyWithoutARequest(t *testing.T) {
	env, state := helperEnv(t)
	host := &fakeHost{}
	if err := host.helper(env, state).Apply(context.Background()); err != nil || len(host.runs) != 0 {
		t.Fatalf("%v %v", err, host.runs)
	}
	if _, err := os.Stat(filepath.Join(state, bootedit.ResultFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a result without a request")
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// fakePID is the gateway's process in a fake /proc.
const fakePID = 4242

// fakeProc lays out what /proc shows for fakePID: its socket descriptors
// (fd name -> inode) and its tcp6 table's rows.
func fakeProc(t *testing.T, sockets map[string]string, rows ...string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, strconv.Itoa(fakePID))
	for _, sub := range []string{"fd", "net"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for fd, inode := range sockets {
		if err := os.Symlink("socket:["+inode+"]", filepath.Join(dir, "fd", fd)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/dev/null", filepath.Join(dir, "fd", "0")); err != nil {
		t.Fatal(err)
	}
	table := "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" + strings.Join(rows, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "net", "tcp6"), []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

// row is one tcp6 table row: local port (hex), state, inode.
func row(port, state, inode string) string {
	return "   0: 00000000000000000000000000000000:" + port + " 00000000000000000000000000000000:0000 " + state + " 00000000:00000000 00:00000000 00000000   997        0 " + inode + " 1 0000000000000000 100 0 0 10 0"
}

// TestListens (2026-10-31): the helper counts the gateway up when its own
// process listens on the new port. The check it replaced asked /readyz over
// TLS without verifying the certificate (CodeQL, Sonar); this one speaks no
// TLS, and a proxy holding the port is another process, so it does not
// count.
func TestListens(t *testing.T) {
	ours := fakeProc(t, map[string]string{"7": "991"}, row("01BB", "0A", "991"))
	if err := listens(ours, fakePID, "443"); err != nil {
		t.Fatalf("the gateway listening on 443: %v", err)
	}
	for name, root := range map[string]string{
		// Caddy holds 443: a listener, but not one of this process's sockets.
		"another process": fakeProc(t, map[string]string{"7": "991"}, row("01BB", "0A", "555")),
		// The socket is the gateway's, but connected, not listening.
		"not listening": fakeProc(t, map[string]string{"7": "991"}, row("01BB", "01", "991")),
		// Listening, on the old port.
		"another port": fakeProc(t, map[string]string{"7": "991"}, row("20FB", "0A", "991")),
	} {
		if err := listens(root, fakePID, "443"); err == nil {
			t.Errorf("%s: counted as up", name)
		}
	}
	if err := listens(ours, fakePID+1, "443"); err == nil {
		t.Error("a process that does not exist counted as up")
	}
	if err := listens(ours, fakePID, "https"); err == nil {
		t.Error("a port that is not a number was accepted")
	}
}

// TestListensOnLinux reads the real /proc: this test process listening on
// an IPv4 and a dual-stack port counts as up, and on a port it does not hold
// does not.
func TestListensOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("reads /proc")
	}
	for _, addr := range []string{"127.0.0.1:0", ":0"} {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_, port, _ := net.SplitHostPort(l.Addr().String())
		if err := listens("/proc", os.Getpid(), port); err != nil {
			t.Errorf("listening on %s: %v", l.Addr(), err)
		}
		_ = l.Close()
		if err := listens("/proc", os.Getpid(), port); err == nil {
			t.Errorf("%s still counted after it closed", l.Addr())
		}
	}
}
