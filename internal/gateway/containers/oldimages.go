// SPDX-License-Identifier: Apache-2.0

package containers

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
)

// SourceLabel and Source mark an image as Zanskar's own: the release sets
// the label on the gateway's image and on the browser's, and a registry
// mirror copies it with the image.
const (
	SourceLabel = "org.opencontainers.image.source"
	Source      = "https://github.com/albatroxxx/zanskar"
)

// RemoveOldImages removes from the repositories of the configured images
// every Zanskar image that is not one of them (2026-10-30: each upgrade left
// the previous browser image behind, more than a gigabyte a time, until the
// disk of a small gateway host filled). An image is a candidate only when it
// is in a configured image's repository and carries Zanskar's source label,
// so a custom image in the same repository is never touched. It is removed
// by reference and never forced, so one a container still uses (a Compose
// gateway's own image, a running session's relay) is refused by the daemon
// and kept. A configured image that is not on the host yet protects nothing
// and holds nothing back: the old image goes before the new one is pulled,
// the only order a nearly full disk allows. It returns the references
// removed. docker is the path to the docker CLI, empty for "docker" on PATH.
func RemoveOldImages(ctx context.Context, docker string, configured []string) ([]string, error) {
	if docker == "" {
		docker = "docker"
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	run := func(ctx context.Context, args ...string) (string, error) {
		return Output(ctx, docker, nil, args...)
	}
	return RemoveOldImagesWith(ctx, run, configured)
}

// RemoveOldImagesWith is RemoveOldImages over an injectable runner.
func RemoveOldImagesWith(ctx context.Context, run runFunc, configured []string) ([]string, error) {
	keep := map[string]bool{}
	var repos []string
	for _, ref := range configured {
		ref = strings.TrimSpace(ref)
		repo := Repository(ref)
		if repo == "" {
			continue
		}
		if !slices.Contains(repos, repo) {
			repos = append(repos, repo)
		}
		if id, err := run(ctx, "image", "inspect", "--format", "{{.Id}}", ref); err == nil {
			keep[strings.TrimSpace(id)] = true
		}
	}
	var removed []string
	var errs []error
	for _, repo := range repos {
		out, err := run(ctx, "image", "ls", "--no-trunc", "--filter", "label="+SourceLabel+"="+Source,
			"--format", "{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Digest}}", repo)
		if err != nil {
			return removed, err
		}
		for _, ref := range oldRefs(out, repo, keep) {
			if _, err := run(ctx, "image", "rm", ref); err != nil {
				if !inUse(err) {
					errs = append(errs, err)
				}
				continue
			}
			removed = append(removed, ref)
		}
	}
	return removed, errors.Join(errs...)
}

// oldRefs picks from a listing (one image per line: id, repository, tag,
// digest, tab separated) the references to remove: images of repo whose id
// is not kept, by tag, or by digest when the image has no tag. A line it
// cannot read is kept; nothing is removed on a guess.
func oldRefs(listing, repo string, keep map[string]bool) []string {
	var refs []string
	for line := range strings.SplitSeq(listing, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), "\t")
		for i := range f {
			f[i] = strings.TrimSpace(f[i])
		}
		if len(f) != 4 || f[0] == "" || keep[f[0]] || f[1] != repo {
			continue
		}
		switch {
		case f[2] != "" && f[2] != "<none>":
			refs = append(refs, repo+":"+f[2])
		case strings.HasPrefix(f[3], "sha256:"):
			refs = append(refs, repo+"@"+f[3])
		}
	}
	return refs
}

// inUse reports a removal the daemon refused because a container uses the
// image: Docker's "conflict ... is using its referenced image", Podman's
// "image is in use by a container".
func inUse(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "conflict") || strings.Contains(s, "in use") || strings.Contains(s, "is using")
}

// Repository is an image reference without its tag or digest:
// ghcr.io/albatroxxx/zanskar-browser for ghcr.io/albatroxxx/zanskar-browser:1.9.0
// or for the same name @sha256:…. A colon before the last slash is a
// registry's port, not a tag.
func Repository(ref string) string {
	ref, _, _ = strings.Cut(ref, "@")
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	return ref
}
