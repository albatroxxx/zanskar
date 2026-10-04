// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/albatroxxx/zanskar/internal/audit"
)

// sftpTarget is an SSH server offering only the sftp subsystem over the
// local filesystem, and a client connected to it as a live terminal
// session's connection would be.
func sftpTarget(t *testing.T) *ssh.Client {
	t.Helper()
	port, _, hostKey := fakeSSHTarget(t, "test", "pw", func(ch ssh.Channel, reqs <-chan *ssh.Request) {
		for r := range reqs {
			ok := r.Type == "subsystem" && len(r.Payload) > 4 && string(r.Payload[4:]) == "sftp"
			if r.WantReply {
				_ = r.Reply(ok, nil)
			}
			if ok {
				go func() {
					if srv, err := sftp.NewServer(ch); err == nil {
						_ = srv.Serve()
					}
					_ = ch.Close()
				}()
			}
		}
	})
	client, err := ssh.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), &ssh.ClientConfig{
		User: "test", Auth: []ssh.AuthMethod{ssh.Password("pw")}, HostKeyCallback: ssh.FixedHostKey(hostKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// TestFileTransferOverHTTP (ADR 0016): a session's owner lists, downloads and
// uploads files on the target, and each transfer is audited with its path
// and size, never its contents. Nobody else reaches the session's files, and
// a session without file transfer has no file endpoints at all.
func TestFileTransferOverHTTP(t *testing.T) {
	f := newConnectFixture(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hello from the target"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.h.Files.add("s1", &fileSession{client: sftpTarget(t), userID: f.alice.ID, targetKey: "t-web"})
	files := "/api/v1/sessions/s1/files"

	t.Run("list", func(t *testing.T) {
		rr := f.do("GET", files+"?path="+url.QueryEscape(dir), "", nil, f.cookie, f.csrf)
		if rr.Code != http.StatusOK {
			t.Fatalf("list: %d %s", rr.Code, rr.Body)
		}
		var out struct {
			Path    string `json:"path"`
			Entries []struct {
				Name string `json:"name"`
				Dir  bool   `json:"dir"`
			} `json:"entries"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		if out.Path != dir || len(out.Entries) != 1 || out.Entries[0].Name != "notes.txt" || out.Entries[0].Dir {
			t.Fatalf("list: %+v", out)
		}
	})

	t.Run("download", func(t *testing.T) {
		rr := f.do("GET", files+"/content?path="+url.QueryEscape(filepath.Join(dir, "notes.txt")), "", nil, f.cookie, f.csrf)
		if rr.Code != http.StatusOK || rr.Body.String() != "hello from the target" {
			t.Fatalf("download: %d %q", rr.Code, rr.Body)
		}
		if cd := rr.Header().Get("Content-Disposition"); !strings.Contains(cd, "notes.txt") || !strings.HasPrefix(cd, "attachment") {
			t.Fatalf("Content-Disposition %q", cd)
		}
		assertTransferAudited(t, f, "file.download", filepath.Join(dir, "notes.txt"), 21)
	})

	t.Run("upload", func(t *testing.T) {
		dest := filepath.Join(dir, "report.csv")
		rr := f.do("POST", files+"/content?path="+url.QueryEscape(dest), "application/octet-stream", strings.NewReader("a,b\n1,2\n"), f.cookie, f.csrf)
		if rr.Code != http.StatusOK {
			t.Fatalf("upload: %d %s", rr.Code, rr.Body)
		}
		if got, _ := os.ReadFile(dest); string(got) != "a,b\n1,2\n" {
			t.Fatalf("uploaded file holds %q", got)
		}
		assertTransferAudited(t, f, "file.upload", dest, 8)
	})

	t.Run("path is required", func(t *testing.T) {
		for _, m := range []string{"GET", "POST"} {
			if rr := f.do(m, files+"/content", "application/octet-stream", strings.NewReader("x"), f.cookie, f.csrf); rr.Code != http.StatusBadRequest {
				t.Errorf("%s without a path: %d, want 400", m, rr.Code)
			}
		}
	})

	t.Run("a missing file is an error, not a crash", func(t *testing.T) {
		rr := f.do("GET", files+"/content?path="+url.QueryEscape(filepath.Join(dir, "nope")), "", nil, f.cookie, f.csrf)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("download of a missing file: %d, want 400", rr.Code)
		}
	})

	t.Run("another user cannot reach the session's files", func(t *testing.T) {
		bob, bobCSRF := f.signIn(t, "bob")
		for _, rq := range []struct{ method, path string }{
			{"GET", files + "?path=" + url.QueryEscape(dir)},
			{"GET", files + "/content?path=" + url.QueryEscape(filepath.Join(dir, "notes.txt"))},
			{"POST", files + "/content?path=" + url.QueryEscape(filepath.Join(dir, "planted"))},
		} {
			rr := f.do(rq.method, rq.path, "application/octet-stream", strings.NewReader("x"), bob, bobCSRF)
			if rr.Code != http.StatusNotFound {
				t.Errorf("bob %s %s: %d, want 404", rq.method, rq.path, rr.Code)
			}
		}
		if _, err := os.Stat(filepath.Join(dir, "planted")); err == nil {
			t.Fatal("bob's upload reached the target")
		}
	})

	t.Run("a session without file transfer has no files", func(t *testing.T) {
		if rr := f.do("GET", "/api/v1/sessions/s2/files", "", nil, f.cookie, f.csrf); rr.Code != http.StatusNotFound {
			t.Fatalf("unregistered session: %d, want 404", rr.Code)
		}
	})

	t.Run("an ended session has no files", func(t *testing.T) {
		f.h.Files.remove("s1")
		if rr := f.do("GET", files, "", nil, f.cookie, f.csrf); rr.Code != http.StatusNotFound {
			t.Fatalf("after the session ended: %d, want 404", rr.Code)
		}
	})
}

func assertTransferAudited(t *testing.T, f *connectFixture, action, path string, size int) {
	t.Helper()
	evs, _, err := f.auditLog.List(f.ctx, audit.Filter{Action: action, Limit: 1})
	if err != nil || len(evs) != 1 {
		t.Fatalf("%s not audited: %v", action, err)
	}
	var d map[string]any
	_ = json.Unmarshal(evs[0].Details, &d)
	if evs[0].ActorUserID != f.alice.ID || d["path"] != path || d["bytes"] != float64(size) || d["target_id"] != "t-web" {
		t.Fatalf("%s audit details %v by %s", action, d, evs[0].ActorUserID)
	}
	for k := range d {
		if k != "path" && k != "bytes" && k != "target_id" {
			t.Errorf("%s audit carries unexpected detail %q", action, k)
		}
	}
}
