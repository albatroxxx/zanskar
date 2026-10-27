// SPDX-License-Identifier: Apache-2.0

package browsergw

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/gateway/containers"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/user"
)

// Check is one prerequisite of application sessions, with its state.
type Check struct {
	Key    string `json:"key"`
	Title  string `json:"title"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Readiness answers what application sessions still need: a guacd
// address, a container runtime the service can reach, and a browser image.
// The Applications page shows the list until every check passes.
type Readiness struct {
	Guacd        func() string
	BrowserImage func() string
	Docker       string
	// Probe answers whether the container runtime is reachable; nil runs
	// `docker info`. Its answer is kept for a short while.
	Probe func(ctx context.Context) error

	mu      sync.Mutex
	probed  time.Time
	probeOK error
}

// Register mounts the route.
func (h *Readiness) Register(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/admin/applications/readiness", auth.RequireRole(user.RoleAdmin)(http.HandlerFunc(h.serve)))
}

// probeCacheTTL is how long a runtime probe's answer stands.
const probeCacheTTL = 15 * time.Second

func (h *Readiness) runtime(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.probed.IsZero() && time.Since(h.probed) < probeCacheTTL {
		return h.probeOK
	}
	probe := h.Probe
	if probe == nil {
		probe = func(ctx context.Context) error {
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			return containers.Run(ctx, h.Docker, nil, "info")
		}
	}
	h.probeOK, h.probed = probe(ctx), time.Now()
	return h.probeOK
}

// Checks evaluates every prerequisite.
func (h *Readiness) Checks(ctx context.Context) []Check {
	guacd := ""
	if h.Guacd != nil {
		guacd = strings.TrimSpace(h.Guacd())
	}
	image := ""
	if h.BrowserImage != nil {
		image = strings.TrimSpace(h.BrowserImage())
	}
	docker := h.Docker
	if docker == "" {
		docker = "docker"
	}
	out := []Check{{Key: "guacd", Title: "guacd address", OK: guacd != ""}}
	if guacd == "" {
		out[0].Detail = "Set the guacd address under Settings, Desktops: applications are drawn by guacd like a desktop."
	} else {
		out[0].Detail = guacd
	}
	rt := Check{Key: "runtime", Title: "Container runtime"}
	if err := h.runtime(ctx); err != nil {
		rt.Detail = "The service cannot reach " + docker + ": add the service user to the docker group (systemctl edit zanskar, SupplementaryGroups=docker) or set ZANSKAR_DOCKER_PATH, then restart."
	} else {
		rt.OK, rt.Detail = true, docker+" answers"
	}
	out = append(out, rt)
	img := Check{Key: "image", Title: "Browser image", OK: image != "", Detail: image}
	if image == "" {
		img.Detail = "Set the browser image under Settings, Applications."
	}
	return append(out, img)
}

func (h *Readiness) serve(w http.ResponseWriter, r *http.Request) {
	checks := h.Checks(r.Context())
	ready := true
	for _, c := range checks {
		ready = ready && c.OK
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ready": ready, "checks": checks})
}
