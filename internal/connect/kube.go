// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/gateway/kubegw"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/ticket"
)

// A Kubernetes session (ADR 0045, 3) has no socket: POST /connect starts it
// at once and answers a kubeconfig whose server is the gateway and whose
// token is the session's. Each request the person's tools make arrives at
// /k8s/{session}/, is checked against the token and the grant's scope, and
// goes to the cluster as the person. The session lives in the registry like
// a bridge, so it is watched, ended and revoked the same way, and ends by
// itself after the policy's idle time without a request or at its maximum.

// kubeIdleCeiling bounds a kube session whose policy sets no idle time: a
// kubeconfig left on a laptop is not a standing credential. A bridge needs
// no such bound, since its socket ends with the browser tab.
const kubeIdleCeiling = 8 * time.Hour

// kubeTick is how often a kube session's idle time is checked; kubeNow is
// the clock it is checked against. Tests shorten the one and move the other.
var (
	kubeTick = 15 * time.Second
	kubeNow  = time.Now
)

// kubeOff says why no kube session can start on this gateway, or "".
func (h *Handler) kubeOff() string {
	switch {
	case h.Kube == nil:
		return "cluster sessions are not available on this gateway"
	case h.PublicURL == "":
		return "cluster sessions need the gateway's public address (ZANSKAR_PUBLIC_URL)"
	}
	return ""
}

// startKube admits, starts and registers a kube session and returns its
// kubeconfig. A non-empty code is a user-facing refusal, as issueTicket's.
func (h *Handler) startKube(r *http.Request, p *auth.Principal, ip string, ep *endpoint) (*connectResponse, string, string, error) {
	ctx := r.Context()
	if msg := h.kubeOff(); msg != "" {
		return nil, "protocol_unavailable", msg, nil
	}
	if !ep.Active {
		return nil, "target_disabled", "target is disabled", nil
	}
	d, code, msg, err := h.admits(ctx, p.User.ID, ep, target.Kube)
	if err != nil || code != "" {
		return nil, code, msg, err
	}
	credID := ep.Credentials[target.Kube]
	if credID == "" {
		return nil, "no_credential", "no credential is configured for kube on this target", nil
	}
	// The slot's credential as the proxy takes it: a token or certificate
	// opened from the vault, or an EKS role's minted bearers (ADR 0045, 8).
	kc, closeCred, err := target.ResolveKubeCredential(ctx, h.Vault, &target.Target{KubePlatform: ep.KubePlatform, Credentials: ep.Credentials})
	switch {
	case errors.Is(err, target.ErrKubeCredential):
		return nil, "credential_mode_unavailable", strings.TrimPrefix(err.Error(), target.ErrKubeCredential.Error()+": "), nil
	case err != nil:
		h.Log.Error("open credential", "id", credID, "err", err)
		return nil, "credential_unavailable", "credential could not be opened", nil
	}
	defer closeCred()
	// The terms the session runs with, in a grant like a bridge's, so the
	// row, the recording and the registry entry are made the same way.
	g := &ticket.Grant{UserID: p.User.ID, Username: p.User.Username, SessionID: p.Session.ID, TargetID: ep.TargetID,
		Protocol: string(target.Kube), CredentialID: credID, PolicyID: d.Policy.ID,
		IdleTimeout: d.IdleTimeout, MaxSession: d.MaxSession, RetentionDays: retentionDays(ep, d), ClientIP: ip}
	// The API server's address passes the gateway's rules, once, and the
	// session dials what it resolved to (checkAddress).
	dialIP, err := h.checkAddress(r, g, ep)
	if err != nil {
		if errors.Is(err, target.ErrAddressForbidden) {
			return nil, "address_forbidden", addressRefusedMsg, nil
		}
		return nil, "target_unreachable", fmt.Sprintf("%s could not be found: its address %s does not resolve", ep.Name, ep.Address), nil
	}
	scope := policy.KubeScope{}
	if d.Kube != nil {
		scope = *d.Kube
	}
	identity := kubegw.Identity{}
	if ep.KubeImpersonate {
		groups, err := h.kubeGroups(ctx, p.User.ID, d)
		if err != nil {
			return nil, "", "", err
		}
		identity = kubegw.Identity{User: p.User.Username, Groups: groups}
	}
	// Nothing after this answer may hang off the request's context: the
	// session outlives it. Its values (the request id) stay.
	rr := r.WithContext(context.WithoutCancel(ctx))
	run, ok := h.startRun(rr, nil, g, ep, ip)
	if !ok {
		return nil, "", "", fmt.Errorf("kube: session row could not be written")
	}
	actsAs := "person"
	if identity.User == "" {
		actsAs = "shared identity"
	}
	run.startDetails = map[string]any{"namespaces": scope.Namespaces, "cluster_scope": scope.ClusterScope, "port_forward": scope.PortForward, "acts_as": actsAs}
	run.kube = &gateway.KubeTerms{Namespaces: scope.Namespaces, ClusterScope: scope.ClusterScope, PortForward: scope.PortForward,
		Impersonate: ep.KubeImpersonate, Groups: identity.Groups}
	rec, row, ok := run.asciicast(ep.Name, 120, 40)
	if !ok {
		return nil, "recording_unavailable", "the session's recording could not be started", nil
	}
	sctx, done := run.live()
	tap := h.Registry.Tap(run.s.ID)
	record := func(line string) {
		_ = rec.Marker(line)
		_ = rec.Output([]byte(line + "\r\n"))
		if tap != nil {
			tap.Write([]byte(line + "\r\n"))
		}
	}
	sess, token, err := kubegw.NewSession(kubegw.Options{SessionID: run.s.ID,
		Endpoint: kubegw.Endpoint{APIServer: ep.KubeAPIServer, CA: ep.KubeCA, DialIP: dialIP}, Credential: kc,
		Identity: identity, Scope: kubegw.Scope{Namespaces: scope.Namespaces, ClusterScope: scope.ClusterScope, PortForward: scope.PortForward},
		Record: record, Log: h.Log})
	if err != nil {
		done()
		run.finishRecording(rec, row)
		run.end(session.EndError, "", map[string]string{"detail": "the cluster's endpoint could not be used: " + err.Error()})
		return nil, "target_unavailable", "the cluster's endpoint could not be used", nil
	}
	h.Kube.Add(sess)
	go h.runKube(sctx, run, sess, rec, row, done)

	res := &connectResponse{SessionID: run.s.ID, IdleSeconds: int(effectiveIdle(g.IdleTimeout) / time.Second),
		Kubeconfig: kubegw.Kubeconfig(kubegw.KubeconfigOptions{Name: ep.Name, Server: h.PublicURL + "/k8s/" + run.s.ID, Token: token, CAPEM: h.gatewayCA()})}
	if g.MaxSession > 0 {
		t := time.Now().Add(g.MaxSession)
		res.ExpiresAt = &t
	}
	return res, "", "", nil
}

// effectiveIdle is the idle time a kube session ends after: the policy's,
// or the ceiling when the policy sets none.
func effectiveIdle(idle time.Duration) time.Duration {
	if idle <= 0 {
		return kubeIdleCeiling
	}
	return idle
}

// runKube keeps the session until the registry ends it, its maximum passes
// or it idles out, then closes it: the token is refused, open streams are
// cut, the recording closed, the row ended and the end audited.
func (h *Handler) runKube(ctx context.Context, run *sessionRun, sess *kubegw.Session, rec recorder, row *session.Recording, done func()) {
	defer done()
	defer h.Kube.Remove(run.s.ID)
	idle := effectiveIdle(run.g.IdleTimeout)
	var maxC <-chan time.Time
	if run.g.MaxSession > 0 {
		t := time.NewTimer(run.g.MaxSession)
		defer t.Stop()
		maxC = t.C
	}
	tick := time.NewTicker(kubeTick)
	defer tick.Stop()
	var reason, detail string
loop:
	for {
		select {
		case <-ctx.Done():
			reason, detail = gateway.CancelReason(ctx)
			break loop
		case <-maxC:
			reason, detail = session.EndMaxDuration, "ended after the policy's maximum of "+run.g.MaxSession.String()
			break loop
		case <-tick.C:
			if kubeNow().Sub(sess.LastActive()) >= idle && sess.Streams() == 0 {
				reason, detail = session.EndIdleTimeout, "ended after "+idle.String()+" without a request"
				break loop
			}
		}
	}
	sess.Close()
	run.finishRecording(rec, row)
	run.end(reason, "", map[string]string{"detail": detail})
}

// kubeGroups are the Zanskar groups the session acts as in the cluster (ADR
// 0045, 2): the person's groups that the deciding policies name, by name,
// sorted, those whose names the manifest can bind (kubegw.ValidGroupName).
func (h *Handler) kubeGroups(ctx context.Context, userID string, d policy.Decision) ([]string, error) {
	if h.Groups == nil {
		return nil, nil
	}
	mine, err := h.Groups.GroupsForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	deciding := map[string]bool{}
	for _, g := range d.Grants {
		deciding[g.PolicyID] = true
	}
	pols, err := h.Policies.ForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	named := map[string]bool{}
	for _, p := range pols {
		if !deciding[p.ID] {
			continue
		}
		for _, s := range p.Subjects {
			if s.Kind == policy.SubjectGroup {
				named[s.ID] = true
			}
		}
	}
	out := []string{}
	for _, g := range mine {
		if named[g.ID] && kubegw.ValidGroupName(g.Name) {
			out = append(out, g.Name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// kubeTermsHold reports whether a live kube session's terms are what a fresh
// decision gives: the scope and, for a session acting as the person, the
// groups. A change ends the session, since the proxy holds both for its
// life (revoke.go). A shared-identity session has no groups to compare.
func kubeTermsHold(l *gateway.KubeTerms, d policy.Decision, groups []string) bool {
	if l == nil {
		return true
	}
	have := &policy.KubeScope{Namespaces: l.Namespaces, ClusterScope: l.ClusterScope, PortForward: l.PortForward}
	want := d.Kube
	if want == nil {
		want = &policy.KubeScope{}
	}
	if !have.Equal(want) {
		return false
	}
	if !l.Impersonate {
		return true
	}
	if len(l.Groups) != len(groups) {
		return false
	}
	for i := range groups {
		if l.Groups[i] != groups[i] {
			return false
		}
	}
	return true
}

// gatewayCA is the gateway's own certificate when kubectl must be told to
// trust it: the self-signed one the gateway made or was given. Behind a
// certificate clients trust, or a proxy terminating TLS, nothing.
func (h *Handler) gatewayCA() string {
	if h.GatewayCert == nil {
		return ""
	}
	pem, selfSigned := h.GatewayCert()
	if !selfSigned {
		return ""
	}
	return pem
}

// kubeProxy serves /k8s/{id}/: the session named by the path, opened by the
// token in the Authorization header and nothing else; a token that is not
// the session's own, or a session that has ended, gets the API's 401.
func (h *Handler) kubeProxy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if h.Kube == nil {
		kubegw.WriteUnauthorized(w)
		return
	}
	sess, ok := h.Kube.Get(id, kubegw.Bearer(r))
	if !ok {
		kubegw.WriteUnauthorized(w)
		return
	}
	http.StripPrefix("/k8s/"+id, sess).ServeHTTP(w, r)
}
