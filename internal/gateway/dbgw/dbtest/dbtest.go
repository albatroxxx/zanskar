// SPDX-License-Identifier: Apache-2.0

// Package dbtest starts real databases in Docker for tests of database
// sessions. Release builds never import it.
package dbtest

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// RequireDocker skips unless ZANSKAR_TEST_DOCKER=1 and a Docker daemon
// answers. These tests pull images and start containers, so they are opt-in
// (CI sets the variable; a laptop without Docker skips them).
func RequireDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("ZANSKAR_TEST_DOCKER") != "1" {
		t.Skip("set ZANSKAR_TEST_DOCKER=1 to run tests that start containers")
	}
	if err := exec.CommandContext(t.Context(), "docker", "info").Run(); err != nil {
		t.Skipf("docker is not available: %v", err)
	}
}

// Docker runs a docker command and returns its trimmed output, failing the
// test on error.
func Docker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "docker", args...).CombinedOutput() // #nosec G204 -- fixed test arguments
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// StartPostgres runs PostgreSQL (database "app", user "postgres") on the
// Docker host's own network, on a high port, and returns the address a
// session's containers reach it at: the default bridge's gateway, which is
// the Docker host on Linux and inside Colima alike. Host networking keeps
// the path free of Docker's isolation rules between bridge networks.
func StartPostgres(t *testing.T, password string) (string, int) {
	t.Helper()
	host := Docker(t, "network", "inspect", "bridge", "-f", "{{(index .IPAM.Config 0).Gateway}}")
	name := "zanskar-test-pg-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	port := 40000 + int(time.Now().UnixNano()%10000)
	Docker(t, "run", "-d", "--name", name, "--network", "host", "-e", "POSTGRES_PASSWORD="+password, "-e", "POSTGRES_DB=app",
		"postgres:16-alpine", "postgres", "-p", strconv.Itoa(port), "-c", "listen_addresses=*")
	t.Cleanup(func() {
		// The test's own context is already cancelled when cleanup runs.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = exec.CommandContext(ctx, "docker", "rm", "-f", name).Run() // #nosec G204 -- fixed test arguments
	})
	deadline := time.Now().Add(90 * time.Second)
	for exec.CommandContext(t.Context(), "docker", "exec", name, "pg_isready", "-h", "127.0.0.1", "-p", strconv.Itoa(port), "-U", "postgres", "-d", "app").Run() != nil { // #nosec G204 -- fixed test arguments
		if time.Now().After(deadline) {
			logs, _ := exec.CommandContext(t.Context(), "docker", "logs", name).CombinedOutput() // #nosec G204 -- fixed test arguments
			t.Fatalf("postgres never became ready:\n%s", logs)
		}
		time.Sleep(500 * time.Millisecond)
	}
	return host, port
}
