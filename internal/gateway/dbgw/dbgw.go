// SPDX-License-Identifier: Apache-2.0

// Package dbgw brokers access to a managed/PaaS database (ADR 0017) with no
// credential leak. Per session it creates a private Docker network, starts a
// proxy sidecar (pgbouncer) that holds the vaulted credential and authenticates
// upstream, and runs the version-matched client (psql) connected to the sidecar
// with no password over that private network. The client container never holds
// a credential, so a shell escape inside the session reveals nothing; access is
// proxied, recorded and torn down when the session ends. The client's terminal
// is bridged to the browser over the same protocol as sshgw.
package dbgw

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/creack/pty"

	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/recording"
)

// Spec describes the upstream database connection for a session.
type Spec struct {
	Engine    string // postgres (mysql/mariadb: follow-up)
	Version   string // optional; selects the client image tag
	Host      string // upstream database host
	Port      int
	Database  string
	Username  string
	Password  string // upstream credential; goes to the sidecar only, never the client
	SessionID string
}

// ClientImage returns the image carrying the version-matched client CLI.
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

// proxyImage returns the credential-holding proxy sidecar image for the engine.
func proxyImage(engine string) string {
	switch engine {
	case "postgres":
		return "edoburu/pgbouncer:v1.23.1-p3"
	default:
		return "" // mysql/mariadb (ProxySQL) is a follow-up
	}
}

// names returns the per-session Docker object names.
func names(sessionID string) (network, proxy, client string) {
	return "zanskar-net-" + sessionID, "zanskar-dbproxy-" + sessionID, "zanskar-dbcli-" + sessionID
}

const proxyPort = 6432 // port pgbouncer is configured to listen on

// proxyScript materialises the pgbouncer config from the sidecar's own
// environment and execs pgbouncer. Writing the config in-container keeps the
// upstream credential out of the host argument vector (it rides PGB_INI in the
// environment) while the client container never receives it at all.
const proxyScript = `umask 077; printf %s "$PGB_INI" > /etc/pgbouncer/pgbouncer.ini; printf %s "$PGB_USERLIST" > /etc/pgbouncer/userlist.txt; exec /usr/bin/pgbouncer /etc/pgbouncer/pgbouncer.ini`

// connQuote single-quotes a libpq/pgbouncer connection-string value so spaces
// or metacharacters in a credential cannot break the generated config.
func connQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return "'" + s + "'"
}

// proxyArgs builds the detached `docker run` for the sidecar and the environment
// carrying the upstream credential by name — so it never appears in the host
// argument vector. The credential lands only in the sidecar's environment
// (isolated, ephemeral, not reachable by the user's client container).
func proxyArgs(s Spec, network, name string) (args []string, env []string, err error) {
	img := proxyImage(s.Engine)
	if img == "" {
		return nil, nil, fmt.Errorf("dbgw: no proxy sidecar for engine %q", s.Engine)
	}
	if s.Host == "" || s.Port <= 0 || s.Username == "" {
		return nil, nil, fmt.Errorf("dbgw: host, port and username are required")
	}
	// pgbouncer authenticates to the upstream — commonly scram-sha-256, as on
	// RDS — with the plaintext password, and accepts the credential-less client
	// with auth_type=trust. An inline server password is required because trust
	// clients present no password for pgbouncer to forward. The config is built
	// from the sidecar's own environment at start-up (proxyScript), so the
	// credential never enters the host argument vector and never reaches the
	// client container. ADR 0017.
	ini := "[databases]\n" +
		s.Database + " = host=" + s.Host + " port=" + strconv.Itoa(s.Port) +
		" dbname=" + connQuote(s.Database) + " user=" + connQuote(s.Username) +
		" password=" + connQuote(s.Password) + "\n" +
		"[pgbouncer]\n" +
		"listen_addr=0.0.0.0\n" +
		"listen_port=" + strconv.Itoa(proxyPort) + "\n" +
		"auth_type=trust\n" +
		"auth_file=/etc/pgbouncer/userlist.txt\n" +
		"pool_mode=session\n" +
		"ignore_startup_parameters=extra_float_digits\n" +
		"max_client_conn=50\n" +
		"admin_users=" + s.Username + "\n"
	// Trust ignores the client password, but the connecting user must be listed.
	userlist := fmt.Sprintf("%q %q\n", s.Username, "x")
	args = []string{
		"run", "-d", "--rm", "--name", name, "--network", network,
		"--security-opt", "no-new-privileges", "--cap-drop", "ALL",
		"--pids-limit", "64", "--memory", "128m",
		"-e", "PGB_INI", "-e", "PGB_USERLIST",
		"--entrypoint", "sh", img,
		"-c", proxyScript,
	}
	env = []string{"PGB_INI=" + ini, "PGB_USERLIST=" + userlist}
	return args, env, nil
}

// clientArgs builds the interactive `docker run` for the client, pointed at the
// sidecar with no credential. Run under a pty and bridged to the browser.
func clientArgs(s Spec, network, name, proxyHost string) ([]string, error) {
	img := ClientImage(s.Engine, s.Version)
	if img == "" {
		return nil, fmt.Errorf("dbgw: unsupported engine %q", s.Engine)
	}
	args := []string{
		"run", "--rm", "-i", "-t", "--name", name, "--network", network,
		"--security-opt", "no-new-privileges", "--cap-drop", "ALL", "--read-only",
		"--pids-limit", "256", "--memory", "512m", "--cpus", "1",
		img,
	}
	switch s.Engine {
	case "postgres":
		args = append(args, "psql", "-h", proxyHost, "-p", strconv.Itoa(proxyPort), "-U", s.Username, "-w")
		if s.Database != "" {
			args = append(args, "-d", s.Database)
		}
	default:
		return nil, fmt.Errorf("dbgw: unsupported engine %q", s.Engine)
	}
	return args, nil
}

// clientFrame and control mirror the sshgw terminal protocol so the browser's
// terminal page drives a database session unchanged.
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
	Idle      time.Duration
	Max       time.Duration
	tick      time.Duration
}

// dockerRun runs a short docker command (network create, container start,
// teardown) with an optional extra environment and a bounded timeout.
func dockerRun(ctx context.Context, docker string, env []string, args ...string) error {
	cmd := exec.CommandContext(ctx, docker, args...) // #nosec G204 -- args built from fixed literals + validated fields
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker %s: %w: %s", args[0], err, string(out))
	}
	return nil
}

// Bridge sets up the per-session network + proxy sidecar, runs the client under
// a pty, and pumps it to the WebSocket until one side ends, returning the end
// reason. docker is the path to the docker CLI; rec may be nil.
func Bridge(ctx context.Context, log *slog.Logger, docker string, spec Spec, ws *websocket.Conn, rec *recording.Asciicast, cols, rows int, lim Limits) (string, error) {
	if log == nil {
		log = slog.Default()
	}
	if docker == "" {
		docker = "docker"
	}
	if cols <= 0 || cols > 1000 {
		cols = 80
	}
	if rows <= 0 || rows > 500 {
		rows = 24
	}
	network, proxy, client := names(spec.SessionID)

	// Set-up context is independent of the session context so teardown still
	// runs after the session's context is cancelled.
	suCtx, suCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer suCancel()

	if err := dockerRun(suCtx, docker, nil, "network", "create", network); err != nil {
		return "error", err
	}
	defer func() {
		tdCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = dockerRun(tdCtx, docker, nil, "network", "rm", network)
	}()

	pargs, penv, err := proxyArgs(spec, network, proxy)
	if err != nil {
		return "error", err
	}
	if err := dockerRun(suCtx, docker, penv, pargs...); err != nil {
		return "error", fmt.Errorf("dbgw: start proxy: %w", err)
	}
	defer func() {
		tdCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = dockerRun(tdCtx, docker, nil, "rm", "-f", proxy)
	}()

	cargs, err := clientArgs(spec, network, client, proxy)
	if err != nil {
		return "error", err
	}
	cmd := exec.CommandContext(ctx, docker, cargs...) // #nosec G204 -- args built by clientArgs from validated fields, no shell
	f, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
	if err != nil {
		return "error", fmt.Errorf("dbgw: start client: %w", err)
	}
	defer func() { _ = f.Close() }()
	defer func() {
		tdCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = dockerRun(tdCtx, docker, nil, "rm", "-f", client)
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
				return
			}
		}
	}()

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
					_ = pty.Setsize(f, &pty.Winsize{Cols: uint16(fr.Cols), Rows: uint16(fr.Rows)})
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
			<-outDone
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
