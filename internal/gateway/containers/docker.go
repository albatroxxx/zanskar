// SPDX-License-Identifier: Apache-2.0

// Package containers holds what every per-session container the gateway
// starts has in common (ADR 0017, ADR 0034): the docker CLI calls and the
// environment a child gets, the per-session internal network, the labels
// that mark an object as this gateway's, and the reaper that removes what a
// crash left behind.
package containers

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Labels on every Docker object a session creates, so leftovers are found
// by label and never by guessing names.
const (
	LabelManaged = "zanskar.managed"
	LabelSession = "zanskar.session"
)

// Labels marks a Docker object as this gateway's and names its session, so
// Reap finds leftovers by label and never by guessing names.
func Labels(sessionID string) []string {
	return []string{"--label", LabelManaged + "=1", "--label", LabelSession + "=" + sessionID}
}

// Podman reports whether the container CLI is Podman, whose default network
// is named after it and whose bridge driver knows no Docker options. Not
// verified against a Podman host.
func Podman(docker string) bool { return filepath.Base(docker) == "podman" }

// EgressNetwork is the runtime's default bridge network, the one with a
// route out, which the proxy alone is attached to.
func EgressNetwork(docker string) string {
	if Podman(docker) {
		return "podman"
	}
	return "bridge"
}

// NetworkArgs builds `docker network create` for a session network:
// internal, so no route leads out of it and the client container reaches
// nothing but the proxy, and (isolated, Docker 28.1 and newer) in the
// isolated gateway mode, so the bridge carries no address of the gateway
// host either and the host's own listeners are out of reach too. The labels
// let Reap find it.
func NetworkArgs(sessionID, network string, isolated bool) []string {
	args := []string{"network", "create", "--internal"}
	if isolated {
		args = append(args, "-o", "com.docker.network.bridge.gateway_mode_ipv4=isolated")
	}
	args = append(args, Labels(sessionID)...)
	return append(args, network)
}

// ChildEnvVars are the only variables a docker (or podman) child takes from
// the gateway's environment: where to find programs, the home directory its
// configuration lives under, and the settings that say which daemon to talk
// to and how. The gateway's environment can hold the master key, the database
// DSN, the SIEM webhook secret and cloud credentials, and a child is handed
// whatever it is given, so it is given this list and nothing else. The Podman
// names (runtime directory, connection) are not verified against a Podman host.
var ChildEnvVars = []string{
	"PATH", "HOME",
	"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY", "DOCKER_TLS", "DOCKER_API_VERSION",
	"XDG_RUNTIME_DIR", "CONTAINER_HOST", "CONTAINER_CONNECTION", "CONTAINERS_CONF",
}

// ChildEnv builds a docker child's environment: those of ChildEnvVars that
// are set, then extra, a session's own variables (the proxy's configuration,
// which `docker run -e NAME` reads from here). It is never nil: exec.Cmd
// takes a nil Env to mean the gateway's whole environment.
func ChildEnv(extra []string) []string {
	env := make([]string, 0, len(ChildEnvVars))
	for _, k := range ChildEnvVars {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return append(env, extra...)
}

// Command is every docker child the gateway starts: the CLI with args,
// bound to ctx, in the environment ChildEnv builds.
func Command(ctx context.Context, docker string, extra []string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, docker, args...) // #nosec G204 G702 -- args built from fixed literals and validated fields (a stored, validated target), no shell
	cmd.Env = ChildEnv(extra)
	return cmd
}

// Output runs a short docker command (network create, container start,
// a listing, teardown) with an optional extra environment, bounded by the
// context, and returns its combined output.
func Output(ctx context.Context, docker string, env []string, args ...string) (string, error) {
	out, err := Command(ctx, docker, env, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("docker %s: %w: %s", args[0], err, string(out))
	}
	return string(out), nil
}

// Run is Output for a command whose output does not matter.
func Run(ctx context.Context, docker string, env []string, args ...string) error {
	_, err := Output(ctx, docker, env, args...)
	return err
}
