// SPDX-License-Identifier: Apache-2.0

package containers

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// PullTimeout bounds one image pull. A session's set-up has a budget of
// seconds; the first pull of an image on a host is minutes on a slow link,
// so it gets a deadline of its own and runs before the set-up starts.
const PullTimeout = 10 * time.Minute

// EnsureImage makes sure image is present on the host: a quick inspect, and
// when that fails a pull bounded by PullTimeout and by ctx (a user who leaves
// cancels it; the layers already fetched stay cached). The error names the
// image and the one-line pull an operator can run ahead of the first session.
func EnsureImage(ctx context.Context, log *slog.Logger, docker, image string) error {
	if log == nil {
		log = slog.Default()
	}
	if docker == "" {
		docker = "docker"
	}
	if err := Run(ctx, docker, nil, "image", "inspect", "--format", "{{.Id}}", image); err == nil {
		return nil
	}
	log.Info("image not present on this host; pulling it", "image", image)
	pctx, cancel := context.WithTimeout(ctx, PullTimeout)
	defer cancel()
	start := time.Now()
	if err := Run(pctx, docker, nil, "pull", "--quiet", image); err != nil {
		return fmt.Errorf("image %s is not present and could not be pulled (run `%s pull %s` on the gateway host): %w", image, docker, image, err)
	}
	log.Info("image pulled", "image", image, "took", time.Since(start).Round(time.Second).String())
	return nil
}
