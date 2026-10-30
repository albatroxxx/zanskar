// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/albatroxxx/zanskar/internal/bootedit"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/lifecycle"
)

// runConfig dispatches `zanskar config <check|apply>` (ADR 0020, amended
// 2026-10-30). check reads an environment file as systemd would and loads
// it as serve would, without opening the database. apply is the root
// helper that zanskar-config.service runs when the console has asked for a
// change: the gateway never writes the environment file itself.
func runConfig(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: zanskar config <check|apply>", errUsage)
	}
	switch args[0] {
	case "check":
		fs := flag.NewFlagSet("config check", flag.ContinueOnError)
		env := fs.String("env", config.DefaultEnvFile, "the environment file to check")
		if err := fs.Parse(args[1:]); err != nil {
			return errUsage
		}
		if _, err := loadEnvFile(*env); err != nil {
			return err
		}
		fmt.Println("ok: the gateway would start with", *env)
		return nil
	case "apply":
		fs := flag.NewFlagSet("config apply", flag.ContinueOnError)
		env := fs.String("env", config.DefaultEnvFile, "the environment file to change")
		state := fs.String("state", "/var/lib/zanskar", "the state directory holding the request")
		if err := fs.Parse(args[1:]); err != nil {
			return errUsage
		}
		h := &configHelper{Env: *env, State: *state}
		return h.Apply(context.Background())
	}
	return fmt.Errorf("%w: unknown config subcommand %q (check, apply)", errUsage, args[0])
}

// loadEnvFile loads path as serve would load its environment: the file's
// ZANSKAR_* variables replace the process's for the call, and nothing else
// is touched. The error is serve's own refusal.
func loadEnvFile(path string) (*config.Config, error) {
	vals, err := lifecycle.ParseEnvFile(path)
	if err != nil {
		return nil, err
	}
	saved := map[string]string{}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok && strings.HasPrefix(k, lifecycle.Prefix) {
			saved[k] = v
			_ = os.Unsetenv(k)
		}
	}
	defer func() {
		for k := range vals {
			_ = os.Unsetenv(k)
		}
		for k, v := range saved {
			_ = os.Setenv(k, v)
		}
	}()
	for k, v := range vals {
		_ = os.Setenv(k, v)
	}
	return config.Load(config.Options{RequireMasterKey: true})
}

// configHelper applies one console request to the environment file, as
// root, trusting nothing the gateway wrote.
type configHelper struct {
	Env, State string
	// Run and Health stand in for systemctl and the listening check in
	// tests; nil is the real thing.
	Run    func(ctx context.Context, name string, args ...string) error
	Health func(ctx context.Context, port string) error
	// Wait is how long the restarted gateway has to answer; zero is 60 s.
	Wait time.Duration
}

// Apply reads the request, if there is one, and writes the result.
func (h *configHelper) Apply(ctx context.Context) error {
	reqPath := filepath.Join(h.State, bootedit.RequestFile)
	f, err := os.Open(reqPath) // #nosec G304 -- a fixed name under the state directory
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	req, perr := bootedit.ParseRequest(f)
	_ = f.Close()
	// The request goes first: whatever happens next, it is never read twice.
	if err := os.Remove(reqPath); err != nil {
		return err
	}
	res := h.apply(ctx, req, perr)
	res.ID, res.RequestedBy, res.At = req.ID, req.RequestedBy, time.Now().UTC()
	return h.writeResult(res)
}

func (h *configHelper) apply(ctx context.Context, req bootedit.Request, perr error) bootedit.Result {
	if perr != nil {
		return bootedit.Result{State: bootedit.Refused, Message: perr.Error()}
	}
	changes, err := bootedit.Changes(req)
	if err != nil {
		return bootedit.Result{State: bootedit.Refused, Message: err.Error()}
	}
	names := slices.Sorted(maps.Keys(changes))
	cur, err := os.ReadFile(h.Env) // #nosec G304 -- the helper's own --env
	if err != nil {
		return bootedit.Result{State: bootedit.Refused, Message: "cannot read the environment file: " + err.Error()}
	}
	st, err := os.Stat(h.Env)
	if err != nil {
		return bootedit.Result{State: bootedit.Refused, Message: err.Error()}
	}
	candidate := h.Env + ".new"
	if err := writeLike(candidate, bootedit.Merge(cur, changes), st); err != nil {
		return bootedit.Result{State: bootedit.Refused, Message: "cannot write the new file: " + err.Error()}
	}
	cfg, err := loadEnvFile(candidate)
	if err != nil {
		_ = os.Remove(candidate)
		return bootedit.Result{State: bootedit.Refused, Message: "the gateway would not start with it: " + err.Error()}
	}
	previous := h.Env + ".previous"
	if err := writeLike(previous, cur, st); err != nil {
		_ = os.Remove(candidate)
		return bootedit.Result{State: bootedit.Refused, Message: "cannot keep the previous file: " + err.Error()}
	}
	if err := os.Rename(candidate, h.Env); err != nil {
		return bootedit.Result{State: bootedit.Refused, Message: err.Error()}
	}
	syncDir(filepath.Dir(h.Env))
	if err := h.restartAndWait(ctx, cfg); err != nil {
		if rerr := writeLike(h.Env, cur, st); rerr != nil {
			return bootedit.Result{State: bootedit.RolledBack, Changed: names, Message: fmt.Sprintf("the gateway did not come back (%v), and the previous file could not be put back (%v): restore %s from %s by hand", err, rerr, h.Env, previous)}
		}
		_ = h.run(ctx, "systemctl", "restart", "zanskar")
		return bootedit.Result{State: bootedit.RolledBack, Changed: names, Message: fmt.Sprintf("the gateway did not come back with the new settings (%v); the previous file is back", err)}
	}
	return bootedit.Result{State: bootedit.Applied, Changed: names}
}

// restartAndWait restarts the service and waits for its new process to
// listen where the new file says.
func (h *configHelper) restartAndWait(ctx context.Context, cfg *config.Config) error {
	if err := h.run(ctx, "systemctl", "restart", "zanskar"); err != nil {
		return err
	}
	wait := h.Wait
	if wait <= 0 {
		wait = time.Minute
	}
	_, port, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("the new listen address %q: %w", cfg.ListenAddr, err)
	}
	deadline := time.Now().Add(wait)
	var last error
	for time.Now().Before(deadline) {
		if last = h.health(ctx, port); last == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return last
}

func (h *configHelper) run(ctx context.Context, name string, args ...string) error {
	if h.Run != nil {
		return h.Run(ctx, name, args...)
	}
	return exec.CommandContext(ctx, name, args...).Run() // #nosec G204 -- systemctl with fixed arguments
}

// health reports whether the restarted gateway is up (2026-10-31): the
// service's main process, as systemd knows it, holds a listening socket on
// the new port. serve binds only after its configuration, database and
// migrations check out, so a listener is a gateway that started. No request
// is made, so no TLS is spoken and no certificate is taken on trust; and a
// proxy still holding the port (Caddy, not yet stopped) is another process,
// so it does not count.
func (h *configHelper) health(ctx context.Context, port string) error {
	if h.Health != nil {
		return h.Health(ctx, port)
	}
	out, err := exec.CommandContext(ctx, "systemctl", "show", "--property=MainPID", "--value", "zanskar").Output() // #nosec G204 -- systemctl with fixed arguments
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || pid <= 0 {
		return errors.New("the gateway service has no running process")
	}
	return listens("/proc", pid, port)
}

// listens reports whether process pid holds a TCP socket listening on port,
// read from a proc filesystem at root: the inodes behind the process's
// socket descriptors against the LISTEN rows of its own tcp and tcp6
// tables (its network namespace's).
func listens(root string, pid int, port string) error {
	n, err := strconv.Atoi(port)
	if err != nil || n <= 0 || n > 65535 {
		return fmt.Errorf("port %q", port)
	}
	want := fmt.Sprintf("%04X", n)
	dir := filepath.Join(root, strconv.Itoa(pid))
	fds, err := os.ReadDir(filepath.Join(dir, "fd"))
	if err != nil {
		return err
	}
	sockets := map[string]bool{}
	for _, fd := range fds {
		link, err := os.Readlink(filepath.Join(dir, "fd", fd.Name()))
		if inode, ok := strings.CutPrefix(link, "socket:["); err == nil && ok {
			sockets[strings.TrimSuffix(inode, "]")] = true
		}
	}
	for _, table := range []string{"tcp", "tcp6"} {
		b, err := os.ReadFile(filepath.Join(dir, "net", table)) // #nosec G304 -- the process's own table under /proc
		if err != nil {
			continue
		}
		for _, row := range strings.Split(string(b), "\n")[1:] {
			f := strings.Fields(row)
			// local address, state, inode: "0100007F:20FB", "0A" (LISTEN), …
			if len(f) < 10 || f[3] != "0A" || !sockets[f[9]] {
				continue
			}
			if _, p, ok := strings.Cut(f[1], ":"); ok && p == want {
				return nil
			}
		}
	}
	return fmt.Errorf("the gateway (process %d) is not listening on port %s", pid, port)
}

// writeResult writes the result for the gateway to read, owned like the
// state directory so the service user can read and acknowledge it.
func (h *configHelper) writeResult(res bootedit.Result) error {
	b, err := json.Marshal(res)
	if err != nil {
		return err
	}
	st, err := os.Stat(h.State)
	if err != nil {
		return err
	}
	path := filepath.Join(h.State, bootedit.ResultFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil { // #nosec G306 -- read by the service user; no secret inside
		return err
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(tmp, int(sys.Uid), int(sys.Gid))
	}
	return os.Rename(tmp, path)
}

// writeLike writes data to path with the mode and owner of st, synced.
func writeLike(path string, data []byte, st os.FileInfo) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, st.Mode().Perm()) // #nosec G304 G302 -- beside the env file, with its own mode
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, st.Mode().Perm()); err != nil {
		return err
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(tmp, int(sys.Uid), int(sys.Gid))
	}
	return os.Rename(tmp, path)
}

// syncDir makes a rename in dir durable.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil { // #nosec G304 -- the env file's directory
		_ = d.Sync()
		_ = d.Close()
	}
}
