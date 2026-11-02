// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/gateway/guac"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/target"
)

// desktopEndedByGuacd opens a VNC session on a fresh target, has the fake
// guacd emit the given frames, then end it with guacd's "Upstream error.",
// and returns the session id and the recording id its start named.
func desktopEndedByGuacd(t *testing.T, r *desktopRig, name string, frames int) (string, string) {
	t.Helper()
	id := r.addTarget(t, name, map[target.Protocol]int{target.VNC: 5900}, "")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ws, _, err := r.dial(ctx, r.ticket(t, id, "vnc")) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	if _, _, err := ws.Read(ctx); err != nil {
		t.Fatal(err)
	}
	start := lastEvent(t, r.connectFixture, "session.start")
	var d map[string]any
	_ = json.Unmarshal(start.Details, &d)
	for i := range frames {
		if err := ws.Write(ctx, websocket.MessageText, []byte(guac.Encode("emit", guac.Encode("sync", strings.Repeat("1", i+1))))); err != nil {
			t.Fatal(err)
		}
	}
	if err := ws.Write(ctx, websocket.MessageText, []byte(guac.Encode("emit", guac.Encode("error", "Upstream error.", "515")))); err != nil {
		t.Fatal(err)
	}
	if row, _ := r.endedWith(t, start.ObjectID); row != session.EndTargetLost {
		t.Fatalf("ended %q, want target_lost", row)
	}
	return start.ObjectID, d["recording_id"].(string)
}

// 2026-11-03 live audit, Q6 and Q7: a Windows host that refused the log-on
// left a session that said only "target lost" and a recording of a blank
// screen, six times in three minutes. The session now keeps what guacd said,
// and a desktop that never drew keeps no recording.
func TestBlankDesktopKeepsNoRecordingAndSaysWhy(t *testing.T) {
	r := newDesktopRig(t)
	sid, recID := desktopEndedByGuacd(t, r, "win-blank", 0)

	s, err := r.h.Sessions.Get(r.ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	if s.EndDetail != "Upstream error." {
		t.Fatalf("end detail %q, want guacd's words", s.EndDetail)
	}
	if s.RecordingID != "" {
		t.Fatalf("a blank desktop is listed with recording %q", s.RecordingID)
	}
	rec, err := r.h.Sessions.GetRecording(r.ctx, recID)
	if err != nil || rec.PurgedAt == nil {
		t.Fatalf("the discarded recording's row must stay, purged: %+v %v", rec, err)
	}
	if rc, err := r.h.Storage.Open(r.ctx, rec.StorageURI); err == nil {
		_ = rc.Close()
		t.Fatal("the blank recording's file is still there")
	}
	evs, _, _ := r.auditLog.List(r.ctx, audit.Filter{Action: "session.end", ObjectID: sid})
	if len(evs) != 1 || !strings.Contains(string(evs[0].Details), `"recording":"discarded: the session drew nothing"`) {
		t.Fatalf("session.end must say the recording was discarded: %v", evs)
	}
}

func TestDrawnDesktopKeepsItsRecording(t *testing.T) {
	r := newDesktopRig(t)
	sid, recID := desktopEndedByGuacd(t, r, "win-drawn", 2)
	s, err := r.h.Sessions.Get(r.ctx, sid)
	if err != nil || s.RecordingID != recID || s.EndDetail != "Upstream error." {
		t.Fatalf("a desktop that drew keeps its recording: %+v %v", s, err)
	}
	rec, err := r.h.Sessions.GetRecording(r.ctx, recID)
	if err != nil || rec.PurgedAt != nil || rec.FinishedAt == nil {
		t.Fatalf("recording %+v %v", rec, err)
	}
	rc, err := r.h.Storage.Open(r.ctx, rec.StorageURI)
	if err != nil {
		t.Fatalf("the recording's file is gone: %v", err)
	}
	_ = rc.Close()
}
