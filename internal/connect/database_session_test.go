// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/credential"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/gateway/dbgw/dbtest"
	"github.com/albatroxxx/zanskar/internal/recording"
	"github.com/albatroxxx/zanskar/internal/target"
)

// TestDatabaseSessionEndToEnd runs a database session the way a user does:
// a ticket for a PostgreSQL target, the /ws/database WebSocket, a query
// typed into psql, the result on screen, "\q". The session is recorded and
// its start and end are audited. It needs Docker (ZANSKAR_TEST_DOCKER=1).
func TestDatabaseSessionEndToEnd(t *testing.T) {
	dbtest.RequireDocker(t)
	const password = "vaulted-db-pw-9"
	host, port := dbtest.StartPostgres(t, password)

	f := newConnectFixture(t)
	f.h.Storage = &recording.LocalStorage{Dir: t.TempDir()}
	f.h.Registry = gateway.NewRegistry()
	cred := &credential.Credential{Name: "pg", Type: credential.TypePassword, Mode: credential.ModeVaulted, Username: "postgres"}
	if err := f.h.Vault.Create(f.ctx, cred, &credential.Secret{Password: password}, f.alice.ID); err != nil {
		t.Fatal(err)
	}
	tg := &target.Target{Name: "orders", Address: host, OSFamily: target.Linux, Engine: "postgres", DatabaseName: "app",
		TLSMode: "disable", Tags: map[string]string{"env": "test"},
		Ports: map[target.Protocol]int{target.Database: port}, Credentials: map[target.Protocol]string{target.Database: cred.ID}}
	if err := f.h.Targets.Create(f.ctx, tg); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(f.srv)
	t.Cleanup(srv.Close)

	code, out := f.postConnect(t, srv.URL, tg.ID, "database")
	tok, _ := out["ticket"].(string)
	if code != http.StatusOK || tok == "" || out["ws_path"] != "/ws/database" {
		t.Fatalf("connect: %d %v", code, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/ws/database?cols=100&rows=30&ticket="+tok, nil) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	send := func(d string) {
		b, _ := json.Marshal(map[string]string{"t": "i", "d": d})
		if err := ws.Write(ctx, websocket.MessageText, b); err != nil {
			t.Fatal(err)
		}
	}

	var screen, sessionID, reason string
	asked := false
	for reason == "" {
		typ, data, err := ws.Read(ctx)
		if err != nil {
			t.Fatalf("read: %v (screen %q)", err, screen)
		}
		if typ == websocket.MessageText {
			var c struct {
				T         string `json:"t"`
				SessionID string `json:"session_id"`
				Reason    string `json:"reason"`
			}
			_ = json.Unmarshal(data, &c)
			if c.T == "ready" {
				sessionID = c.SessionID
			}
			if c.T == "end" {
				reason = c.Reason
			}
			continue
		}
		screen += string(data)
		switch {
		case !asked && strings.Contains(screen, "app=#"):
			send("SELECT 41 + 1 AS answer;\r")
			asked = true
		case asked && strings.Contains(screen, " 42"):
			send("\\q\r")
			asked = false
		}
	}
	if reason != "user_exit" || !strings.Contains(screen, " 42") {
		t.Fatalf("end %q, screen %q", reason, screen)
	}
	start := lastEvent(t, f, "session.start")
	var d map[string]any
	_ = json.Unmarshal(start.Details, &d)
	if start.ObjectID != sessionID || d["engine"] != "postgres" || d["target_id"] != tg.ID {
		t.Fatalf("session.start %s %v; browser saw %s", start.ObjectID, d, sessionID)
	}
	for i := 0; i < 250; i++ {
		if s, err := f.h.Sessions.Get(f.ctx, sessionID); err == nil && s.EndedAt != nil {
			rec, err := f.h.Sessions.GetRecording(f.ctx, d["recording_id"].(string))
			if err != nil || rec.FinishedAt == nil || rec.SizeBytes == 0 {
				t.Fatalf("recording %+v %v", rec, err)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the database session never ended")
}
