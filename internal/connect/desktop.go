// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/credential"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/gateway/guac"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/recording"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/target"
)

// desktopParams builds the guacd connection parameters for a target. The
// browser never sees these. RDP certificate trust is pinned to the TLS
// fingerprint captured at probe time (ADR 0012); without one the connection
// is refused rather than trusted blindly.
//
// File transfer uses guacd's drive redirection: when the policy allows it, a
// per-session directory under drivePath is exposed to the RDP session as a
// mapped drive named "Zanskar", and the browser uploads to and downloads from
// it through Guacamole object streams. The directory lives in guacd's tmpfs and
// disappears with the session. VNC has no file transfer.
func desktopParams(t *target.Target, proto target.Protocol, a *credential.Opened, userSecret []byte, username string, allowFiles bool, drivePath string) (guac.Params, error) {
	args := map[string]string{
		"hostname": t.Address,
		"port":     strconv.Itoa(t.Port(proto)),
	}
	password := ""
	if a != nil {
		password = a.Password
		if a.Username != "" {
			username = a.Username
		}
		if a.Domain != "" {
			args["domain"] = a.Domain
		}
	}
	if len(userSecret) > 0 {
		password = string(userSecret)
	}
	switch proto {
	case target.RDP:
		if t.TLSFingerprint == nil || *t.TLSFingerprint == "" {
			return guac.Params{}, errors.New("rdp target has no pinned certificate fingerprint; probe it first")
		}
		args["username"] = username
		args["password"] = password
		// Windows enforces Network Level Authentication (CredSSP) by default, and
		// guacd's auto-negotiate ("any") fails against such hosts with "security
		// negotiation failed". Require NLA explicitly.
		args["security"] = "nla"
		// The gateway verifies the pinned certificate itself immediately before
		// this connection (verifyPinnedCert). guacd's own cert-fingerprints
		// pinning is not used: FreeRDP refuses the session when the target is
		// dialled by IP while the self-signed certificate's CN is the hostname,
		// which is the normal case for these targets, and the desktop stays
		// blank. ignore-cert lets guacd proceed after the gateway has already
		// confirmed the exact certificate the server presents.
		args["ignore-cert"] = "true"
		args["resize-method"] = "display-update"
		// Modern Windows (Server 2019/2022) composes the desktop at 32-bit. guacd
		// defaults to 16-bit, which paints the simple logon screen but leaves the
		// composed desktop black. Request 32-bit so the desktop itself renders.
		args["color-depth"] = "32"
		// A visible wallpaper makes a working desktop obvious rather than a bare
		// black background that reads as "not rendering".
		args["enable-wallpaper"] = "true"
		args["disable-audio"] = "true"
		args["enable-printing"] = "false"
		// Disable the RDP Graphics Pipeline (EGFX). This guacd build negotiates
		// the RDPGFX channel with recent Windows but then unloads it ("RDPGFX
		// channel support unloaded") because its FreeRDP lacks the AVC/H.264
		// codec, so the composed desktop never arrives and stays black. Forcing
		// EGFX off makes Windows fall back to the bitmap/surface path guacd can
		// render. Verified against a stock Windows Server 2022 target with the
		// default WDDM display driver: the target needs no configuration of its
		// own for the desktop to paint, which is the point of an agentless
		// gateway.
		args["disable-gfx"] = "true"
		if allowFiles {
			args["enable-drive"] = "true"
			args["drive-name"] = "Zanskar"
			args["drive-path"] = drivePath
			args["create-drive-path"] = "true"
			args["disable-download"] = "false"
			args["disable-upload"] = "false"
		} else {
			args["enable-drive"] = "false"
		}
	case target.VNC:
		args["password"] = password
		if username != "" {
			args["username"] = username
		}
	default:
		return guac.Params{}, errors.New("not a desktop protocol")
	}
	return guac.Params{Protocol: string(proto), Args: args, Image: []string{"image/png", "image/jpeg", "image/webp"}}, nil
}

// desktop redeems a ticket and runs the guacd bridge for its lifetime.
// Route: GET /ws/desktop?ticket=...&width=&height=&dpi=
func (h *Handler) desktop(w http.ResponseWriter, r *http.Request) {
	ip := auth.ClientIP(r)
	g, err := h.Tickets.Redeem(r.URL.Query().Get("ticket"), ip)
	if err != nil {
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_ticket", "invalid or expired ticket")
		return
	}
	defer zero(g.UserSecret)
	proto := target.Protocol(g.Protocol)
	if proto != target.RDP && proto != target.VNC {
		httpx.WriteError(w, http.StatusBadRequest, "bad_request", "ticket is not for a desktop protocol")
		return
	}
	if h.GuacdAddr == "" {
		httpx.WriteError(w, http.StatusNotImplemented, "protocol_unavailable", "desktop sessions are not configured on this gateway")
		return
	}
	t, err := h.Targets.Get(r.Context(), g.TargetID)
	if err != nil || t.Status != "active" {
		httpx.WriteError(w, http.StatusConflict, "target_unavailable", "target is no longer available")
		return
	}

	var opened *credential.Opened
	if len(g.UserSecret) == 0 {
		opened, err = h.Vault.Open(r.Context(), g.CredentialID)
		if err != nil {
			h.Log.Error("open credential", "id", g.CredentialID, "err", err)
			httpx.WriteError(w, http.StatusConflict, "credential_unavailable", "credential could not be opened")
			return
		}
		defer opened.Close()
	}
	// Validate the target and credential before upgrading; the drive path is
	// filled in once the session id exists.
	params, err := desktopParams(t, proto, opened, g.UserSecret, g.Username, g.AllowFileTransfer, "")
	if err != nil {
		httpx.WriteError(w, http.StatusConflict, "target_unavailable", err.Error())
		return
	}
	// Enforce the certificate pin at the gateway before handing off to guacd,
	// which connects with cert checks disabled (see desktopParams).
	if proto == target.RDP {
		if err := h.verifyPinnedCert(r.Context(), t); err != nil {
			h.Log.Warn("rdp certificate pin check failed", "target", t.ID, "err", err)
			httpx.WriteError(w, http.StatusConflict, "certificate_mismatch", "the target's certificate does not match the pinned fingerprint")
			return
		}
	}
	params.Width, _ = strconv.Atoi(r.URL.Query().Get("width"))
	params.Height, _ = strconv.Atoi(r.URL.Query().Get("height"))
	params.DPI, _ = strconv.Atoi(r.URL.Query().Get("dpi"))
	if tz := r.URL.Query().Get("tz"); tz != "" && len(tz) < 64 {
		params.Timezone = tz
	}

	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"guacamole"}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ws.SetReadLimit(4 << 20)

	s := &session.Session{UserID: g.UserID, PolicyID: g.PolicyID, TargetID: t.ID, Protocol: g.Protocol, CredentialID: g.CredentialID, ClientIP: ip, UserAgent: r.UserAgent()}
	if err := h.Sessions.Start(r.Context(), s); err != nil {
		h.Log.Error("start session", "err", err)
		_ = ws.Close(websocket.StatusInternalError, "could not start session")
		return
	}
	actor := audit.Actor{UserID: g.UserID, IP: ip}
	endWith := func(reason, msg string) {
		_ = h.Sessions.End(context.Background(), s.ID, reason)
		h.record(r, actor.Event("session.end", "access_session", s.ID, audit.Success, map[string]string{"reason": reason, "target_id": t.ID}))
		if msg != "" {
			wctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = ws.Write(wctx, websocket.MessageText, []byte(guac.ErrorInstruction(msg, 519)))
			cancel()
			_ = ws.Close(websocket.StatusPolicyViolation, msg)
		}
	}

	if g.AllowFileTransfer && proto == target.RDP {
		params.Args["drive-path"] = drivePathFor(s.ID)
	}
	timeout := h.DialTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	gc, err := guac.Dial(r.Context(), h.GuacdAddr, params, timeout)
	if err != nil {
		h.Log.Warn("guacd dial failed", "target", t.ID, "err", err)
		endWith(session.EndError, "could not connect to the target")
		return
	}
	defer func() { _ = gc.Close() }()

	rec, uri, err := recording.NewGuacStream(r.Context(), h.Storage, s.ID+".guac")
	if err != nil {
		h.Log.Error("start recording", "err", err)
		endWith(session.EndError, "recording could not be started; session refused")
		return
	}
	recRow := &session.Recording{SessionID: s.ID, Format: "guac", StorageURI: uri}
	if err := h.Sessions.CreateRecording(r.Context(), recRow); err != nil {
		_, _, _ = rec.Close()
		endWith(session.EndError, "recording could not be registered; session refused")
		return
	}
	h.record(r, actor.Event("session.start", "access_session", s.ID, audit.Success, map[string]any{"target_id": t.ID, "protocol": g.Protocol, "policy_id": g.PolicyID, "recording_id": recRow.ID}))

	// guacamole-common-js expects the tunnel's internal opcode with an id first.
	// It is followed by a Zanskar-specific instruction carrying the policy
	// flags so the browser can show or hide the file and clipboard controls.
	// Guacamole.Client ignores opcodes it does not know, so it is harmless to
	// a stock client and never reaches guacd.
	if err := ws.Write(r.Context(), websocket.MessageText, []byte(guac.Encode("", s.ID)+FlagsInstruction(g.AllowFileTransfer, g.AllowClipboard))); err != nil {
		_, _, _ = rec.Close()
		endWith(session.EndError, "")
		return
	}

	ctx := h.Registry.Add(r.Context(), gateway.Live{SessionID: s.ID, UserID: g.UserID, TargetID: t.ID, Protocol: g.Protocol})
	h.Registry.SetGuacID(s.ID, gc.ID) // lets auditors join this desktop via guacd
	defer h.Registry.Remove(s.ID)
	reason, berr := guac.Bridge(ctx, h.Log, gc, ws, rec, guac.Limits{Idle: g.IdleTimeout, Max: g.MaxSession, AllowClipboard: g.AllowClipboard, AllowFileTransfer: g.AllowFileTransfer})
	size, sum, cerr := rec.Close()
	if cerr != nil {
		h.Log.Error("close recording", "session", s.ID, "err", cerr)
	}
	if err := h.Sessions.FinishRecording(context.Background(), recRow.ID, size, sum); err != nil {
		h.Log.Error("finish recording", "session", s.ID, "err", err)
	}
	if berr != nil {
		h.Log.Warn("desktop bridge ended with error", "session", s.ID, "err", berr)
	}
	endWith(reason, "")
	_ = ws.Close(websocket.StatusNormalClosure, reason)
}

// verifyPinnedCert reconnects to the target's RDP TLS listener and confirms it
// still presents the pinned certificate, immediately before guacd connects. The
// gateway enforces the pin (ADR 0012) because guacd's fingerprint pinning does
// not work for IP-dialled, self-signed certificates; guacd is then told to
// ignore the certificate it has already been vouched for.
func (h *Handler) verifyPinnedCert(ctx context.Context, t *target.Target) error {
	if h.Prober == nil {
		return errors.New("certificate verification is unavailable")
	}
	if t.TLSFingerprint == nil || *t.TLSFingerprint == "" {
		return errors.New("target has no pinned certificate; probe it first")
	}
	want := strings.ToLower(strings.ReplaceAll(*t.TLSFingerprint, ":", ""))
	timeout := h.DialTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	res, err := h.Prober.Probe(ctx, t.Address, map[target.Protocol]int{target.RDP: t.Port(target.RDP)}, timeout)
	if err != nil {
		return err
	}
	if res.TLS == nil {
		return errors.New("target presented no certificate")
	}
	if got := strings.ToLower(strings.ReplaceAll(res.TLS.Fingerprint, ":", "")); got != want {
		return fmt.Errorf("certificate fingerprint %s does not match pinned %s", got, want)
	}
	return nil
}

// drivePathFor is the per-session directory guacd exposes as the mapped drive.
// It sits directly under guacd's tmpfs root (see deploy/docker-compose.yml) so
// the parent always exists: guacd's create-drive-path is not recursive, and a
// nested path like /tmp/drives/<id> fails when /tmp/drives is absent, which it
// is on a fresh tmpfs. The directory is never visible to the gateway process.
func drivePathFor(sessionID string) string {
	return "/tmp/zanskar-drive-" + sessionID
}

// FlagsInstruction encodes policy flags for the browser as a custom
// Guacamole instruction: "zanskar,file,<0|1>,clipboard,<0|1>".
func FlagsInstruction(files, clipboard bool) string {
	b := func(v bool) string {
		if v {
			return "1"
		}
		return "0"
	}
	return guac.Encode("zanskar", "file", b(files), "clipboard", b(clipboard))
}

// ticketPathFor reports which WebSocket endpoint serves a protocol.
func ticketPathFor(p target.Protocol) string {
	switch p {
	case target.RDP, target.VNC:
		return "/ws/desktop"
	case target.WinRM:
		return "/ws/winrm"
	case target.Database:
		return "/ws/database"
	default:
		return "/ws/terminal"
	}
}
