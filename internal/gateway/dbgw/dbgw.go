// SPDX-License-Identifier: Apache-2.0

// Package dbgw brokers access to a managed/PaaS database (ADR 0017). On connect
// it launches an ephemeral, hardened container running the version-matched
// client (psql, mysql, ...) connected to the target, and bridges the client's
// interactive terminal to the browser over WebSocket. One container per
// session; it is removed when the session ends.
//
// Broker phase: the container connects directly to the database. The credential
// is injected into the container's environment (never placed on the host
// command line), but a determined user could still read it from inside the
// session via a client shell escape. Prefer short-lived credentials (e.g. RDS
// IAM auth tokens); the later protocol-proxy phase removes the credential from
// the container entirely.
package dbgw

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/creack/pty"

	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/recording"
)

// Spec describes the database connection a session container should open.
type Spec struct {
	Engine    string // postgres | mysql | mariadb
	Version   string // optional; selects the client image tag
	Host      string
	Port      int
	Database  string // optional database name to open
	Username  string
	Password  string // static password or a short-lived token; never logged
	SessionID string
	Network   string // docker network the container joins to reach the database
}

// ClientImage returns the container image that carries the version-matched
// client for the engine, or "" if the engine is unsupported. The client CLIs
// ship in the official engine images.
func ClientImage(engine, version string) string {
	switch engine {
	case "postgres":
		if version != "" {
			return "postgres:" + version + "-alpine"
		}
		return "postgres:16-alpine"
	case "mysql":
		if version != "" {
			return "mysql:" + version
		}
		return "mysql:8"
	case "mariadb":
		if version != "" {
			return "mariadb:" + version
		}
		return "mariadb:11"
	default:
		return ""
	}
}

// runArgs builds the `docker run` arguments and the environment the docker
// process must carry. The password is passed by name (-e PGPASSWORD) and set in
// the docker process's own environment, so it never appears in the host process
// list or in the argument vector. It is pure, so the hardening flags and the
// connection arguments are unit-tested.
func runArgs(s Spec) (args []string, env []string, err error) {
	image := ClientImage(s.Engine, s.Version)
	if image == "" {
		return nil, nil, fmt.Errorf("dbgw: unsupported engine %q", s.Engine)
	}
	if s.Host == "" || s.Port <= 0 || s.Username == "" {
		return nil, nil, fmt.Errorf("dbgw: host, port and username are required")
	}
	network := s.Network
	if network == "" {
		network = "bridge"
	}
	// Hardened, ephemeral container. Egress should additionally be confined to
	// the database endpoint; that network policy is applied by the deployment
	// and tracked as a hardening follow-up (ADR 0017).
	args = []string{
		"run", "--rm", "-i", "-t",
		"--name", "zanskar-db-" + s.SessionID,
		"--network", network,
		"--security-opt", "no-new-privileges",
		"--cap-drop", "ALL",
		"--read-only",
		"--pids-limit", "256",
		"--memory", "512m",
		"--cpus", "1",
	}
	var client []string
	switch s.Engine {
	case "postgres":
		args = append(args, "-e", "PGPASSWORD", "-e", "PGCONNECT_TIMEOUT=10")
		env = append(env, "PGPASSWORD="+s.Password)
		client = []string{"psql", "-h", s.Host, "-p", strconv.Itoa(s.Port), "-U", s.Username, "-w"}
		if s.Database != "" {
			client = append(client, "-d", s.Database)
		}
	case "mysql", "mariadb":
		args = append(args, "-e", "MYSQL_PWD")
		env = append(env, "MYSQL_PWD="+s.Password)
		client = []string{"mysql", "--protocol=TCP", "-h", s.Host, "-P", strconv.Itoa(s.Port), "-u", s.Username}
		if s.Database != "" {
			client = append(client, s.Database)
		}
	default:
		return nil, nil, fmt.Errorf("dbgw: unsupported engine %q", s.Engine)
	}
	args = append(args, image)
	args = append(args, client...)
	return args, env, nil
}

// clientFrame and control mirror the sshgw terminal protocol so the browser's
// terminal page drives a database session with no changes: binary frames carry
// output, text frames carry input ("i") and resize ("r"), and control frames
// announce "ready" and "end".
type clientFrame struct {
	T    string `json:"t"`
	D    string `json:"d,omitempty"`
	Cols int    `json:"c,omitempty"`
	Rows int    `json:"r,omitempty"`
}

type control struct {
	T         string `json:"t"`
	SessionID string `json:"session_id,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Msg       string `json:"msg,omitempty"`
}

// Limits bound a live session, taken from the policy decision.
type Limits struct {
	SessionID string
	Idle      time.Duration // ends the session after this long without input
	Max       time.Duration // absolute cap from start; zero means none
	tick      time.Duration // how often limits are checked; tests shorten it
}

// Bridge launches the client container under a pty and pumps it to the
// WebSocket until one side ends, returning the end reason for the
// access_sessions row. docker is the path to the docker CLI; rec may be nil.
func Bridge(ctx context.Context, log *slog.Logger, docker string, spec Spec, ws *websocket.Conn, rec *recording.Asciicast, cols, rows int, lim Limits) (string, error) {
	if log == nil {
		log = slog.Default()
	}
	args, env, err := runArgs(spec)
	if err != nil {
		return "error", err
	}
	if cols <= 0 || cols > 1000 {
		cols = 80
	}
	if rows <= 0 || rows > 500 {
		rows = 24
	}
	if docker == "" {
		docker = "docker"
	}

	cmd := exec.CommandContext(ctx, docker, args...)                                       // #nosec G204 -- args are built by runArgs from validated fields, no shell
	cmd.Env = append(os.Environ(), env...)                                                 // carries the password by name, never in argv
	f, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)}) //nolint:gosec // bounded above
	if err != nil {
		return "error", fmt.Errorf("dbgw: start client: %w", err)
	}
	defer func() { _ = f.Close() }()
	// Belt-and-suspenders teardown: --rm removes the container on a clean exit,
	// and this removes it if the process was killed before docker cleaned up.
	defer func() {
		rmCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = exec.CommandContext(rmCtx, docker, "rm", "-f", "zanskar-db-"+spec.SessionID).Run() // #nosec G204 -- fixed name
	}()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		mu     sync.Mutex
		reason = "user_exit"
		lastIn = time.Now()
		start  = time.Now()
		setEnd = func(r string) {
			mu.Lock()
			if reason == "user_exit" {
				reason = r
			}
			mu.Unlock()
		}
		current = func() string { mu.Lock(); defer mu.Unlock(); return reason }
		outDone = make(chan struct{})
		inDone  = make(chan struct{})
	)
	sendCtrl := func(c control) {
		b, _ := json.Marshal(c)
		wctx, wcancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer wcancel()
		_ = ws.Write(wctx, websocket.MessageText, b)
	}
	sendCtrl(control{T: "ready", SessionID: lim.SessionID})

	// client -> browser (+ recording)
	go func() {
		defer close(outDone)
		buf := make([]byte, 32<<10)
		for {
			n, rerr := f.Read(buf)
			if n > 0 {
				if rec != nil {
					if werr := rec.Output(buf[:n]); werr != nil {
						log.Error("recording write failed; ending session", "err", werr)
						setEnd("error")
						return
					}
				}
				if werr := ws.Write(ctx, websocket.MessageBinary, buf[:n]); werr != nil {
					return
				}
			}
			if rerr != nil {
				return // pty closed: the client exited
			}
		}
	}()

	// browser -> client
	go func() {
		defer close(inDone)
		for {
			typ, data, rerr := ws.Read(ctx)
			if rerr != nil {
				return
			}
			mu.Lock()
			lastIn = time.Now()
			mu.Unlock()
			if typ == websocket.MessageBinary {
				if _, werr := f.Write(data); werr != nil {
					return
				}
				continue
			}
			var fr clientFrame
			if json.Unmarshal(data, &fr) != nil {
				continue
			}
			switch fr.T {
			case "i":
				if rec != nil {
					_ = rec.Input([]byte(fr.D))
				}
				if _, werr := f.Write([]byte(fr.D)); werr != nil {
					return
				}
			case "r":
				if fr.Cols > 0 && fr.Rows > 0 && fr.Cols <= 1000 && fr.Rows <= 500 {
					_ = pty.Setsize(f, &pty.Winsize{Cols: uint16(fr.Cols), Rows: uint16(fr.Rows)}) //nolint:gosec // bounded above
					if rec != nil {
						_ = rec.Resize(fr.Cols, fr.Rows)
					}
				}
			}
		}
	}()

	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()
	if lim.tick <= 0 {
		lim.tick = 5 * time.Second
	}
	ticker := time.NewTicker(lim.tick)
	defer ticker.Stop()

	finish := func(r, msg string) (string, error) {
		setEnd(r)
		r = current()
		sendCtrl(control{T: "end", Reason: r, Msg: msg})
		cancel()
		return r, nil
	}
	for {
		select {
		case <-ctx.Done():
			reason, msg := gateway.CancelReason(ctx)
			return finish(reason, msg)
		case <-inDone:
			r := current()
			cancel()
			return r, nil
		case <-waitDone:
			<-outDone // drain remaining output before the end frame
			return finish("user_exit", "")
		case <-outDone:
			if r := current(); r != "user_exit" {
				return finish(r, "the database session ended")
			}
			select {
			case <-waitDone:
			case <-time.After(2 * time.Second):
			}
			return finish("user_exit", "")
		case now := <-ticker.C:
			mu.Lock()
			idle := now.Sub(lastIn)
			mu.Unlock()
			if lim.Idle > 0 && idle > lim.Idle {
				return finish("idle_timeout", "disconnected after "+lim.Idle.String()+" without input")
			}
			if lim.Max > 0 && now.Sub(start) > lim.Max {
				return finish("max_duration", "session reached the policy's maximum duration")
			}
		}
	}
}
