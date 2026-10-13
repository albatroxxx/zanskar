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
	"github.com/albatroxxx/zanskar/internal/gateway/guac"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/protocol"
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
//
// The clipboard and file policy is enforced twice (ADR 0012): the bridge drops
// the instructions, and guacd is told here not to produce them in the first
// place. disable-copy keeps text copied inside the desktop from being sent to
// the browser and disable-paste keeps browser text out of the desktop (RDP and
// VNC); disable-download and disable-upload do the same for the mapped drive
// (RDP only, VNC has no file transfer).
func desktopParams(t *endpoint, proto target.Protocol, a *credential.Opened, userSecret []byte, username string, allowFiles, allowClipboard bool, drivePath string) (guac.Params, error) {
	args := map[string]string{
		"hostname":      t.Address,
		"port":          strconv.Itoa(t.port(proto)),
		"disable-copy":  strconv.FormatBool(!allowClipboard),
		"disable-paste": strconv.FormatBool(!allowClipboard),
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
		if t.TLSFingerprint == "" {
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
		args["disable-download"] = strconv.FormatBool(!allowFiles)
		args["disable-upload"] = strconv.FormatBool(!allowFiles)
		if allowFiles {
			args["enable-drive"] = "true"
			args["drive-name"] = "Zanskar"
			args["drive-path"] = drivePath
			args["create-drive-path"] = "true"
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

// desktopDialMessage words a failed desktop connection for the user. From the
// browser the two failures look alike, but they need different people: guacd
// not answering is the gateway operator's problem (it is not installed by the
// package and has to be started), while guacd answering and then failing to
// reach the machine is the target's. One message used to cover both
// (manual QA finding 4).
func desktopDialMessage(err error) string {
	if errors.Is(err, guac.ErrGuacdUnreachable) {
		return "the desktop service (guacd) is not running or not reachable from the gateway; an administrator must start it (the gateway journal names the address it tried)"
	}
	return "the desktop service could not open a connection to the machine: check that RDP or VNC is enabled, that its port is open from the gateway, and that the pinned certificate still matches"
}

// desktop redeems a ticket and runs the guacd bridge for its lifetime.
// Route: GET /ws/desktop?ticket=...&width=&height=&dpi=
func (h *Handler) desktop(w http.ResponseWriter, r *http.Request) {
	ip := auth.ClientIP(r)
	g, ok := h.redeem(w, r)
	if !ok {
		return
	}
	defer zero(g.UserSecret)
	proto := target.Protocol(g.Protocol)
	if proto != target.RDP && proto != target.VNC {
		httpx.WriteError(w, r, http.StatusBadRequest, "bad_request", "ticket is not for a desktop protocol")
		return
	}
	guacdAddr := h.guacd()
	if guacdAddr == "" {
		httpx.WriteError(w, r, http.StatusNotImplemented, "protocol_unavailable", "desktop sessions are not configured on this gateway")
		return
	}
	ep, err := h.resolveGrant(r.Context(), g)
	if err != nil || !ep.Active {
		httpx.WriteError(w, r, http.StatusConflict, "target_unavailable", "target is no longer available")
		return
	}
	// guacd is handed the name and looks it up again itself, so this refuses
	// a name that already leads somewhere forbidden; it cannot fix the
	// answer guacd gets.
	if _, err := h.checkAddress(r, g, ep); err != nil {
		refuseAddress(w, r, err)
		return
	}

	var opened *credential.Opened
	if len(g.UserSecret) == 0 {
		opened, err = h.Vault.Open(r.Context(), g.CredentialID)
		if err != nil {
			h.Log.Error("open credential", "id", g.CredentialID, "err", err)
			httpx.WriteError(w, r, http.StatusConflict, "credential_unavailable", "credential could not be opened")
			return
		}
		defer opened.Close()
	}
	// Validate the target and credential before upgrading; the drive path is
	// filled in once the session id exists.
	params, err := desktopParams(ep, proto, opened, g.UserSecret, g.Username, g.AllowFileTransfer, g.AllowClipboard, "")
	if err != nil {
		httpx.WriteError(w, r, http.StatusConflict, "target_unavailable", err.Error())
		return
	}
	// Enforce the certificate pin at the gateway before handing off to guacd,
	// which connects with cert checks disabled (see desktopParams).
	if proto == target.RDP {
		if err := h.verifyPinnedCert(r.Context(), ep); err != nil {
			// The pin check looks the name up once more; an answer refused
			// now is a refused address, not a changed certificate.
			if errors.Is(err, target.ErrAddressForbidden) {
				h.addressRefused(r, g, ep, err)
				refuseAddress(w, r, err)
				return
			}
			h.Log.Warn("rdp certificate pin check failed", "target", ep.LiveKey, "err", err)
			// A different certificate is the ADR 0012 case and is audited, as
			// WinRM's and SSH's are; an unreachable target is only logged.
			var mm *certMismatch
			if errors.As(err, &mm) {
				h.record(r, actorFor(g.UserID, ip).Event(audit.TargetTLSMismatch, "target", ep.LiveKey, audit.Failure,
					map[string]string{"protocol": protocol.RDP, "expected": mm.want, "seen": mm.got}))
			}
			httpx.WriteError(w, r, http.StatusConflict, "certificate_mismatch", "the target's certificate does not match the pinned fingerprint")
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

	run, ok := h.startRun(r, ws, g, ep, ip)
	if !ok {
		return
	}
	// The console reads why from a guacamole error instruction. A desktop
	// refused before its bridge starts was refused by the gateway, not lost,
	// so it is 523 (session closed) with the reason: 519 would offer another
	// instance of an autoscaling group, which cannot help when guacd is down
	// or the recording cannot be written.
	run.tell = func(msg string) {
		wctx, cancel := detach(r.Context(), frameTimeout)
		_ = ws.Write(wctx, websocket.MessageText, []byte(guac.ErrorInstruction(msg, guac.StatusSessionClosed)))
		cancel()
	}

	if g.AllowFileTransfer && proto == target.RDP {
		params.Args["drive-path"] = drivePathFor(run.s.ID)
	}
	timeout := h.DialTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	gc, err := guac.Dial(r.Context(), guacdAddr, params, timeout)
	if err != nil {
		h.Log.Warn("guacd dial failed", "target", ep.LiveKey, "guacd", guacdAddr, "err", err)
		run.end(session.EndError, desktopDialMessage(err))
		return
	}
	defer func() { _ = gc.Close() }()

	rec, recRow, ok := run.guacStream()
	if !ok {
		return
	}

	// guacamole-common-js expects the tunnel's internal opcode with an id first.
	// It is followed by a Zanskar-specific instruction carrying the policy
	// flags so the browser can show or hide the file and clipboard controls.
	// Guacamole.Client ignores opcodes it does not know, so it is harmless to
	// a stock client and never reaches guacd.
	if err := ws.Write(r.Context(), websocket.MessageText, []byte(guac.Encode("", run.s.ID)+FlagsInstruction(g.AllowFileTransfer, g.AllowClipboard))); err != nil {
		_, _, _ = rec.Close()
		run.end(session.EndError, "")
		return
	}

	ctx, done := run.live()
	defer done()
	h.Registry.SetGuacID(run.s.ID, gc.ID) // lets auditors join this desktop via guacd
	reason, berr := guac.Bridge(ctx, h.Log, gc, ws, rec, guac.Limits{Idle: g.IdleTimeout, Max: g.MaxSession, AllowClipboard: g.AllowClipboard, AllowFileTransfer: g.AllowFileTransfer})
	run.finish(rec, recRow, reason, berr)
}

// verifyPinnedCert reconnects to the target's RDP TLS listener and confirms it
// still presents the pinned certificate, immediately before guacd connects. The
// gateway enforces the pin (ADR 0012) because guacd's fingerprint pinning does
// not work for IP-dialled, self-signed certificates; guacd is then told to
// ignore the certificate it has already been vouched for.
func (h *Handler) verifyPinnedCert(ctx context.Context, t *endpoint) error {
	if h.Prober == nil {
		return errors.New("certificate verification is unavailable")
	}
	if t.TLSFingerprint == "" {
		return errors.New("target has no pinned certificate; probe it first")
	}
	want := strings.ToLower(strings.ReplaceAll(t.TLSFingerprint, ":", ""))
	timeout := h.DialTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	res, err := h.Prober.Probe(ctx, t.Address, map[target.Protocol]int{target.RDP: t.port(target.RDP)}, timeout)
	if err != nil {
		return err
	}
	if res.TLS == nil {
		return errors.New("target presented no certificate")
	}
	if got := strings.ToLower(strings.ReplaceAll(res.TLS.Fingerprint, ":", "")); got != want {
		return &certMismatch{got: got, want: want}
	}
	return nil
}

// certMismatch is a target that answered with a certificate other than the
// pinned one.
type certMismatch struct{ got, want string }

func (e *certMismatch) Error() string {
	return fmt.Sprintf("certificate fingerprint %s does not match pinned %s", e.got, e.want)
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
