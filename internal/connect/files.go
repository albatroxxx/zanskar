// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"errors"
	"fmt"
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
		httpx.WriteError(w, r, http.StatusNotFound, "not_found", "no file-transfer session; open the terminal and ensure the policy allows file transfer")
		return nil, nil, nil, false
	}
	s, err := sshgw.OpenSFTP(fs.client)
	if err != nil {
		httpx.WriteError(w, r, http.StatusConflict, "sftp_unavailable", "the target's SSH server does not offer file transfer")
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
		httpx.WriteError(w, r, http.StatusBadRequest, "sftp_error", err.Error())
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
		httpx.WriteError(w, r, http.StatusBadRequest, "bad_request", "path is required")
		return
	}
	done := h.transferRecorder(r, p, fs, audit.FileDownload, rpath)
	f, fi, err := s.Open(rpath)
	if err != nil {
		done(0, err)
		httpx.WriteError(w, r, http.StatusBadRequest, "sftp_error", err.Error())
		return
	}
	defer func() { _ = f.Close() }()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+url.PathEscape(path.Base(rpath)))
	n, err := io.Copy(w, f)
	if err == nil && n != fi.Size() {
		err = fmt.Errorf("sent %d of %d bytes", n, fi.Size())
	}
	done(n, err)
	if err != nil && n == 0 {
		// Nothing has been sent yet, so the browser can still be told,
		// rather than handed an empty file.
		w.Header().Del("Content-Length")
		w.Header().Del("Content-Disposition")
		httpx.WriteError(w, r, http.StatusBadRequest, "sftp_error", "download failed: "+err.Error())
	}
}

// transferRecorder returns the function that audits one file transfer when
// it ends. Every attempt is recorded, with what moved and the error when it
// failed: an attempt to plant or take a file is worth knowing about whether
// or not it worked (L10).
func (h *Handler) transferRecorder(r *http.Request, p *auth.Principal, fs *fileSession, action, rpath string) func(n int64, err error) {
	return func(n int64, err error) {
		outcome, details := audit.Success, map[string]any{"path": rpath, "bytes": n, "target_id": fs.targetKey}
		if err != nil {
			outcome, details["error"] = audit.Failure, err.Error()
		}
		h.record(r, audit.Actor{UserID: p.User.ID, IP: auth.ClientIP(r)}.Event(action, "access_session", r.PathValue("id"), outcome, details))
	}
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
		httpx.WriteError(w, r, http.StatusBadRequest, "bad_request", "path is required")
		return
	}
	done := h.transferRecorder(r, p, fs, audit.FileUpload, rpath)
	f, err := s.Create(rpath)
	if err != nil {
		done(0, err)
		httpx.WriteError(w, r, http.StatusBadRequest, "sftp_error", err.Error())
		return
	}
	n, cerr := io.Copy(f, r.Body)
	if err := errors.Join(cerr, f.Close()); err != nil {
		done(n, err)
		httpx.WriteError(w, r, http.StatusBadRequest, "sftp_error", "upload failed")
		return
	}
	done(n, nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"path": rpath, "bytes": n})
}
