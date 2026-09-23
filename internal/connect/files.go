// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/gateway/sshgw"
	"github.com/albatroxxx/zanskar/internal/httpx"
)

// fileSession is a live SSH terminal session whose connection may also carry
// SFTP file transfer (ADR 0016). It exists only while the terminal session is
// open and only when the policy allowed file transfer.
type fileSession struct {
	client    *ssh.Client
	userID    string
	targetKey string // ep.LiveKey, for audit
}

// fileRegistry holds the SSH clients of live terminal sessions so the file
// endpoints can open an SFTP subsystem on the same connection. Added when a
// session's terminal connects with file transfer allowed; removed when it ends.
type fileRegistry struct {
	mu sync.Mutex
	m  map[string]*fileSession
}

func newFileRegistry() *fileRegistry { return &fileRegistry{m: make(map[string]*fileSession)} }

func (r *fileRegistry) add(sessionID string, fs *fileSession) {
	r.mu.Lock()
	r.m[sessionID] = fs
	r.mu.Unlock()
}

func (r *fileRegistry) remove(sessionID string) {
	r.mu.Lock()
	delete(r.m, sessionID)
	r.mu.Unlock()
}

// lookup returns the session's file client, but only for its owner. A session
// that disallowed file transfer is never in the map, so this also enforces the
// policy gate.
func (r *fileRegistry) lookup(sessionID, userID string) (*fileSession, bool) {
	r.mu.Lock()
	fs, ok := r.m[sessionID]
	r.mu.Unlock()
	if !ok || fs.userID != userID {
		return nil, false
	}
	return fs, true
}

// open resolves the session, checks ownership, and opens an SFTP subsystem on
// its SSH connection. The caller closes the returned SFTP.
func (h *Handler) openSessionSFTP(w http.ResponseWriter, r *http.Request) (*fileSession, *sshgw.SFTP, *auth.Principal, bool) {
	p, _ := auth.FromContext(r.Context())
	fs, ok := h.Files.lookup(r.PathValue("id"), p.User.ID)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "no file-transfer session; open the terminal and ensure the policy allows file transfer")
		return nil, nil, nil, false
	}
	s, err := sshgw.OpenSFTP(fs.client)
	if err != nil {
		httpx.WriteError(w, http.StatusConflict, "sftp_unavailable", "the target's SSH server does not offer file transfer")
		return nil, nil, nil, false
	}
	return fs, s, p, true
}

// listFiles lists a directory on the session's target.
func (h *Handler) listFiles(w http.ResponseWriter, r *http.Request) {
	_, s, _, ok := h.openSessionSFTP(w, r)
	if !ok {
		return
	}
	defer func() { _ = s.Close() }()
	dir := r.URL.Query().Get("path")
	if dir == "" {
		dir = s.Home()
	}
	entries, err := s.List(dir)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "sftp_error", err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"path": dir, "entries": entries})
}

// downloadFile streams a file from the session's target to the browser. The
// transfer is audited; its contents are not recorded.
func (h *Handler) downloadFile(w http.ResponseWriter, r *http.Request) {
	fs, s, p, ok := h.openSessionSFTP(w, r)
	if !ok {
		return
	}
	defer func() { _ = s.Close() }()
	rpath := r.URL.Query().Get("path")
	if rpath == "" {
		httpx.WriteError(w, http.StatusBadRequest, "bad_request", "path is required")
		return
	}
	f, fi, err := s.Open(rpath)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "sftp_error", err.Error())
		return
	}
	defer func() { _ = f.Close() }()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+url.PathEscape(path.Base(rpath)))
	n, _ := io.Copy(w, f)
	h.record(r, audit.Actor{UserID: p.User.ID, IP: auth.ClientIP(r)}.Event("file.download", "access_session", r.PathValue("id"), audit.Success,
		map[string]any{"path": rpath, "bytes": n, "target_id": fs.targetKey}))
}

// uploadFile writes the request body to a file on the session's target. The
// transfer is audited; its contents are not recorded.
func (h *Handler) uploadFile(w http.ResponseWriter, r *http.Request) {
	fs, s, p, ok := h.openSessionSFTP(w, r)
	if !ok {
		return
	}
	defer func() { _ = s.Close() }()
	rpath := r.URL.Query().Get("path")
	if rpath == "" {
		httpx.WriteError(w, http.StatusBadRequest, "bad_request", "path is required")
		return
	}
	f, err := s.Create(rpath)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "sftp_error", err.Error())
		return
	}
	n, cerr := io.Copy(f, r.Body)
	closeErr := f.Close()
	if cerr != nil || closeErr != nil {
		httpx.WriteError(w, http.StatusBadRequest, "sftp_error", "upload failed")
		return
	}
	h.record(r, audit.Actor{UserID: p.User.ID, IP: auth.ClientIP(r)}.Event("file.upload", "access_session", r.PathValue("id"), audit.Success,
		map[string]any{"path": rpath, "bytes": n, "target_id": fs.targetKey}))
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"path": rpath, "bytes": n})
}
