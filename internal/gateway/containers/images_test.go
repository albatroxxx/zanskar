// SPDX-License-Identifier: Apache-2.0

package containers

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// stubCLI writes a stand-in docker whose `image inspect` answers as told
// and which logs every call.
func stubCLI(t *testing.T, inspectExit int, pullExit int) (docker, calls string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in docker CLI is a shell script")
	}
	dir := t.TempDir()
	calls = filepath.Join(dir, "calls.log")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + calls + "'\n" +
		"if [ \"$1\" = image ] && [ \"$2\" = inspect ]; then exit " + itoa(inspectExit) + "; fi\n" +
		"if [ \"$1\" = pull ]; then exit " + itoa(pullExit) + "; fi\nexit 0\n"
	docker = filepath.Join(dir, "docker")
	if err := os.WriteFile(docker, []byte(script), 0o700); err != nil { // #nosec G306 -- an executable test stub
		t.Fatal(err)
	}
	return docker, calls
}

func itoa(n int) string { return string(rune('0' + n)) }

// TestEnsureImagePresent: an image the host has is inspected and not pulled.
func TestEnsureImagePresent(t *testing.T) {
	docker, calls := stubCLI(t, 0, 0)
	if err := EnsureImage(context.Background(), nil, docker, "ghcr.io/x/y:1"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(calls) // #nosec G304 -- test temp dir
	if !strings.Contains(string(b), "image inspect --format {{.Id}} ghcr.io/x/y:1") || strings.Contains(string(b), "pull") {
		t.Fatalf("calls:\n%s", b)
	}
}

// TestEnsureImagePulls: an absent image is pulled, by the reference given
// (a digest-pinned one included), and a pull that fails names the image
// and the command to run.
func TestEnsureImagePulls(t *testing.T) {
	docker, calls := stubCLI(t, 1, 0)
	ref := "ghcr.io/x/y@sha256:0000000000000000000000000000000000000000000000000000000000000000"
	if err := EnsureImage(context.Background(), nil, docker, ref); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(calls) // #nosec G304 -- test temp dir
	if !strings.Contains(string(b), "pull --quiet "+ref) {
		t.Fatalf("no pull:\n%s", b)
	}
	docker, _ = stubCLI(t, 1, 1)
	err := EnsureImage(context.Background(), nil, docker, "ghcr.io/x/y:1")
	if err == nil || !strings.Contains(err.Error(), "pull ghcr.io/x/y:1") {
		t.Fatalf("a failed pull was not reported with the command: %v", err)
	}
}

// TestEnsureImageStopsWithTheSession: a pull is cancelled with the context
// it was given.
func TestEnsureImageStopsWithTheSession(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in docker CLI is a shell script")
	}
	dir := t.TempDir()
	docker := filepath.Join(dir, "docker")
	// The sleep is the process itself (exec), so that killing the child
	// ends it; a sleep forked by the shell would outlive it and hold the
	// output pipe, which the command's wait delay then gives up on.
	if err := os.WriteFile(docker, []byte("#!/bin/sh\nif [ \"$1\" = pull ]; then exec sleep 30; fi\nexit 1\n"), 0o700); err != nil { // #nosec G306 -- test stub
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := EnsureImage(ctx, nil, docker, "ghcr.io/x/y:1"); err == nil {
		t.Fatal("a cancelled pull succeeded")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the pull outlived its context")
	}
}

// TestCommandGivesUpOnAHeldPipe: a grandchild that keeps the output pipe
// after the CLI is killed does not hold the gateway for its lifetime.
func TestCommandGivesUpOnAHeldPipe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in docker CLI is a shell script")
	}
	dir := t.TempDir()
	docker := filepath.Join(dir, "docker")
	if err := os.WriteFile(docker, []byte("#!/bin/sh\nsleep 30 &\nwait\n"), 0o700); err != nil { // #nosec G306 -- test stub
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_ = Run(ctx, docker, nil, "pull", "x")
	if time.Since(start) > 10*time.Second {
		t.Fatal("a held pipe outlived the wait delay")
	}
}
