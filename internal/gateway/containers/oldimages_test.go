// SPDX-License-Identifier: Apache-2.0

package containers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/gateway/dbgw/dbtest"
)

// fakeImages scripts what the daemon holds and records what is removed.
type fakeImages struct {
	ids     map[string]string // reference -> id, for image inspect
	listing map[string]string // repository -> image ls output
	refuse  map[string]string // reference -> the daemon's refusal
	removed []string
	listed  [][]string
}

func (f *fakeImages) run(_ context.Context, args ...string) (string, error) {
	switch {
	case args[0] == "image" && args[1] == "inspect":
		if id, ok := f.ids[args[len(args)-1]]; ok {
			return id + "\n", nil
		}
		return "", errors.New("docker image: no such image")
	case args[0] == "image" && args[1] == "ls":
		f.listed = append(f.listed, args)
		return f.listing[args[len(args)-1]], nil
	case args[0] == "image" && args[1] == "rm":
		ref := args[2]
		if why, ok := f.refuse[ref]; ok {
			return "", fmt.Errorf("docker image: exit status 1: %s", why)
		}
		f.removed = append(f.removed, ref)
		return "", nil
	}
	return "", fmt.Errorf("unexpected docker %v", args)
}

const (
	browserRepo = "ghcr.io/albatroxxx/zanskar-browser"
	relayRepo   = "ghcr.io/albatroxxx/zanskar"
)

func line(id, repo, tag, digest string) string { return id + "\t" + repo + "\t" + tag + "\t" + digest }

// TestRemoveOldImages (2026-10-30, the live box's disk): every Zanskar image
// of a configured repository that is not the configured one goes, by tag, or
// by digest when it has none; the configured image stays under any of its
// tags; one a container uses is refused by the daemon and counted as kept,
// not as a failure; a line that cannot be read, or one from another
// repository, is left alone.
func TestRemoveOldImages(t *testing.T) {
	f := &fakeImages{
		ids: map[string]string{browserRepo + ":1.9.0": "sha256:b19", relayRepo + ":1.9.0": "sha256:r19"},
		listing: map[string]string{
			browserRepo: strings.Join([]string{
				line("sha256:b19", browserRepo, "1.9.0", "sha256:d19"),
				line("sha256:b19", browserRepo, "latest", "sha256:d19"),
				line("sha256:b18", browserRepo, "1.8.0", "sha256:d18"),
				line("sha256:b17", browserRepo, "1.7.2", "<none>"),
				line("sha256:b16", browserRepo, "<none>", "sha256:d16"),
				line("sha256:bxx", browserRepo, "<none>", "<none>"),
				line("sha256:other", "ghcr.io/someone/else", "1", "sha256:o"),
				"WARNING: a line the daemon added",
				"",
			}, "\n"),
			relayRepo: line("sha256:r19", relayRepo, "1.9.0", "") + "\n" + line("sha256:r18", relayRepo, "1.8.0", "") + "\n",
		},
		refuse: map[string]string{relayRepo + ":1.8.0": `Error response from daemon: conflict: unable to remove repository reference "ghcr.io/albatroxxx/zanskar:1.8.0" (must force) - container 1f2e is using its referenced image 9a8b`},
	}
	got, err := RemoveOldImagesWith(context.Background(), f.run, []string{browserRepo + ":1.9.0", " " + relayRepo + ":1.9.0 ", ""})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{browserRepo + ":1.8.0", browserRepo + ":1.7.2", browserRepo + "@sha256:d16"}
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(f.removed, want) {
		t.Fatalf("removed %v (reported %v), want %v", f.removed, got, want)
	}
	// Only labelled images are listed, one repository at a time.
	if len(f.listed) != 2 {
		t.Fatalf("listed %v", f.listed)
	}
	for _, args := range f.listed {
		if !slices.Contains(args, "label="+SourceLabel+"="+Source) || !slices.Contains(args, "--no-trunc") {
			t.Errorf("listing without the source label or full ids: %v", args)
		}
	}
}

// TestRemoveOldImagesBeforeThePull: the configured image is not on the host
// yet (an upgrade, before the first session pulls it). The old one still
// goes, so the pull has the room; a repository holding only a custom image
// gives no candidates, since the listing asks for Zanskar's label.
func TestRemoveOldImagesBeforeThePull(t *testing.T) {
	f := &fakeImages{listing: map[string]string{browserRepo: line("sha256:b18", browserRepo, "1.8.0", "") + "\n"}}
	got, err := RemoveOldImagesWith(context.Background(), f.run, []string{browserRepo + ":1.9.0"})
	if err != nil || !reflect.DeepEqual(got, []string{browserRepo + ":1.8.0"}) {
		t.Fatalf("removed %v, %v", got, err)
	}
	// A digest-pinned mirror: its repository is the one listed, and the
	// configured image is kept by id whatever it is tagged.
	mirror := "registry.example.com:5000/mirror/zanskar-browser"
	f = &fakeImages{
		ids:     map[string]string{mirror + "@sha256:" + strings.Repeat("a", 64): "sha256:m19"},
		listing: map[string]string{mirror: line("sha256:m19", mirror, "<none>", "sha256:"+strings.Repeat("a", 64)) + "\n" + line("sha256:m18", mirror, "1.8.0", "") + "\n"},
	}
	got, err = RemoveOldImagesWith(context.Background(), f.run, []string{mirror + "@sha256:" + strings.Repeat("a", 64)})
	if err != nil || !reflect.DeepEqual(got, []string{mirror + ":1.8.0"}) {
		t.Fatalf("mirror: removed %v, %v", got, err)
	}
}

// TestRemoveOldImagesReportsFailures: a removal that fails for another
// reason is reported and the rest go on; a listing that fails stops the
// pass, as the reaper's does.
func TestRemoveOldImagesReportsFailures(t *testing.T) {
	f := &fakeImages{
		listing: map[string]string{browserRepo: line("sha256:b17", browserRepo, "1.7.0", "") + "\n" + line("sha256:b18", browserRepo, "1.8.0", "") + "\n"},
		refuse:  map[string]string{browserRepo + ":1.7.0": "permission denied while trying to connect to the Docker daemon socket"},
	}
	got, err := RemoveOldImagesWith(context.Background(), f.run, []string{browserRepo + ":1.9.0"})
	if err == nil || !reflect.DeepEqual(got, []string{browserRepo + ":1.8.0"}) {
		t.Fatalf("removed %v, err %v", got, err)
	}
	failing := func(_ context.Context, args ...string) (string, error) { return "", exec.ErrNotFound }
	if _, err := RemoveOldImagesWith(context.Background(), failing, []string{browserRepo + ":1.9.0"}); !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("a failed listing: %v", err)
	}
}

func TestRepository(t *testing.T) {
	for ref, want := range map[string]string{
		"ghcr.io/albatroxxx/zanskar-browser:1.9.0":               "ghcr.io/albatroxxx/zanskar-browser",
		"ghcr.io/albatroxxx/zanskar-browser@sha256:abc":          "ghcr.io/albatroxxx/zanskar-browser",
		"ghcr.io/albatroxxx/zanskar-browser:1.9.0@sha256:abc":    "ghcr.io/albatroxxx/zanskar-browser",
		"registry.example.com:5000/mirror/zanskar-browser":       "registry.example.com:5000/mirror/zanskar-browser",
		"registry.example.com:5000/mirror/zanskar-browser:1.9.0": "registry.example.com:5000/mirror/zanskar-browser",
		"zanskar-browser:dev":                                    "zanskar-browser",
		"":                                                       "",
	} {
		if got := Repository(ref); got != want {
			t.Errorf("Repository(%q) = %q, want %q", ref, got, want)
		}
	}
}

// TestRemoveOldImagesWithDocker runs against a real daemon: two tags of a
// labelled image built here, one configured and one not, plus an unlabelled
// image in the same repository and a labelled one a stopped container uses.
// Only the unconfigured, unused, labelled one goes. Needs ZANSKAR_TEST_DOCKER=1.
func TestRemoveOldImagesWithDocker(t *testing.T) {
	dbtest.RequireDocker(t)
	repo := "zanskar-oldimages-test-" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-"))
	dir := t.TempDir()
	build := func(tag, label, marker string) {
		t.Helper()
		df := "FROM scratch\nLABEL " + label + "\nCOPY " + marker + " /" + marker + "\n"
		if err := os.WriteFile(dir+"/Dockerfile", []byte(df), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dir+"/"+marker, []byte(marker), 0o600); err != nil {
			t.Fatal(err)
		}
		dbtest.Docker(t, "build", "-q", "-t", repo+":"+tag, dir)
		t.Cleanup(func() { _ = exec.Command("docker", "image", "rm", "-f", repo+":"+tag).Run() }) // #nosec G204 -- fixed test arguments
	}
	ours := SourceLabel + "=" + Source
	build("new", ours, "new")
	build("old", ours, "old")
	build("custom", "org.example=1", "custom")
	build("inuse", ours, "inuse")
	name := repo + "-holder"
	dbtest.Docker(t, "create", "--name", name, repo+":inuse", "/inuse")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() }) // #nosec G204 -- fixed test arguments

	got, err := RemoveOldImages(context.Background(), "", []string{repo + ":new"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{repo + ":old"}) {
		t.Fatalf("removed %v, want only %s:old", got, repo)
	}
	left := dbtest.Docker(t, "image", "ls", "--format", "{{.Tag}}", repo)
	for _, tag := range []string{"new", "custom", "inuse"} {
		if !strings.Contains(left, tag) {
			t.Errorf("%s:%s was removed; left %q", repo, tag, left)
		}
	}
}
