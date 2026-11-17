// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/cloud"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/ticket"
)

// A cloud session (ADR 0050, 3) is the AWS session, started by Zanskar: POST
// /connect admits the person, registers a session and hands them a bearer
// token that is their handle on it. The command line takes credentials from
// /api/v1/cloud/{id}/credentials with that token: a fifteen-minute
// AssumeRole, re-minted while the session lives and reused for twelve of its
// minutes (the EKS token's pattern), so a terminate stops it within fifteen
// minutes. The console is a sign-in the portal POSTs into a new tab, from a
// mint that lives for the session's remaining time, which AWS gives no way
// to cut short: the session says when it ends. The gateway sees no request
// stream, so a cloud session has no idle: it ends at its duration, on
// terminate, on a policy change or when the role is edited.

// CloudTokenPrefix opens every cloud session token, so it is told apart from
// a Kubernetes session's (zk8s_) and an API token.
const CloudTokenPrefix = "zaws_" // #nosec G101 -- a prefix, not a credential

// The command-line credentials' life: minted for fifteen minutes (AWS's
// shortest), handed out until three minutes before they end.
const (
	cloudCLIDuration = 15 * time.Minute
	cloudCLIMargin   = 3 * time.Minute
)

// cloudNow is the clock cloud sessions read; tests move it.
var cloudNow = time.Now

// cloudOff says why no cloud session can start on this gateway, or "". The
// profile stanza's credentials URL and the console form's Issuer name the
// public address, so without it nothing a session hands out would work.
func (h *Handler) cloudOff() string {
	if h.PublicURL == "" {
		return "cloud sessions need the gateway's public address (ZANSKAR_PUBLIC_URL)"
	}
	return ""
}

// cloudSession is one live cloud session at the gateway.
type cloudSession struct {
	id       string
	hash     [sha256.Size]byte
	userID   string
	username string
	ep       *endpoint
	terms    policy.CloudTerms
	minter   cloud.RoleMinter
	endsAt   time.Time
	record   func(line string)

	mu           sync.Mutex
	cli          cloud.Credentials
	consoleUntil *time.Time
	closed       bool
}

// cloudSessions holds the live cloud sessions by id.
type cloudSessions struct{ m sync.Map }

func (s *cloudSessions) add(c *cloudSession) { s.m.Store(c.id, c) }
func (s *cloudSessions) remove(id string)    { s.m.Delete(id) }
func (s *cloudSessions) lookup(id string) (*cloudSession, bool) {
	v, ok := s.m.Load(id)
	if !ok {
		return nil, false
	}
	return v.(*cloudSession), true
}

// Len is how many cloud sessions are live; tests wait on it.
func (s *cloudSessions) Len() int {
	n := 0
	s.m.Range(func(any, any) bool { n++; return true })
	return n
}

// mintRequest is the AssumeRole a session makes, for d: the person's
// username as the source identity, the session's id as the session name,
// both as tags.
func (c *cloudSession) mintRequest(d time.Duration) cloud.MintRequest {
	return cloud.MintRequest{RoleARN: c.ep.CloudRoleARN, ExternalID: c.ep.CloudExternalID, SessionName: cloud.SessionNameFor(c.id),
		SourceIdentity: cloud.SourceIdentityFor(c.username), Duration: d, Tags: cloud.SessionTags(c.username, c.id)}
}

// cloudConnect is what connect answers for a cloud session beside the
// session id: the token and the profile stanza, filled when the command
// line is open and empty when it is not (the portal's type has them always;
// a token nothing would take is not handed out), and what the portal shows.
type cloudConnect struct {
	Token          string    `json:"token"`
	CredentialsURL string    `json:"credentials_url"`
	Profile        string    `json:"profile"`
	Console        bool      `json:"console"`
	CLI            bool      `json:"cli"`
	AccountID      string    `json:"account_id"`
	AccountAlias   string    `json:"account_alias,omitempty"`
	RoleName       string    `json:"role_name"`
	Region         string    `json:"region,omitempty"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// newMinter builds the minter a session assumes the role with.
func (h *Handler) newMinter(ctx context.Context, region string) (cloud.RoleMinter, error) {
	if h.NewMinter != nil {
		return h.NewMinter(ctx, region)
	}
	return target.NewRoleMinter(ctx, region)
}

// federation is the exchange a console sign-in goes through.
func (h *Handler) federation() *cloud.Federation {
	if h.Federation != nil {
		return h.Federation
	}
	return &cloud.Federation{}
}

// startCloud admits, starts and registers a cloud session and returns its
// handle. A non-empty code is a user-facing refusal, as issueTicket's.
func (h *Handler) startCloud(r *http.Request, p *auth.Principal, ip string, ep *endpoint) (*connectResponse, string, string, error) {
	ctx := r.Context()
	if msg := h.cloudOff(); msg != "" {
		return nil, "protocol_unavailable", msg, nil
	}
	if h.draining() {
		return nil, "restarting", restartingMsg, nil
	}
	if !ep.Active {
		return nil, "target_disabled", "target is disabled", nil
	}
	d, code, msg, err := h.admits(ctx, p.User.ID, ep, target.Cloud)
	if err != nil || code != "" {
		return nil, code, msg, err
	}
	terms := policy.CloudTerms{Console: true, CLI: true}
	if d.Cloud != nil {
		terms = *d.Cloud
	}
	// The session's length: the target's maximum, or the grant's where it
	// is shorter. No idle: the gateway sees no request stream.
	length := time.Duration(ep.CloudMaxMinutes) * time.Minute
	if d.MaxSession > 0 && d.MaxSession < length {
		length = d.MaxSession
	}
	minter, err := h.newMinter(ctx, ep.CloudRegion)
	if err != nil {
		h.Log.Error("cloud minter", "target", ep.TargetID, "err", err)
		return nil, "protocol_unavailable", "the gateway's own AWS identity is not configured", nil
	}
	g := &ticket.Grant{UserID: p.User.ID, Username: p.User.Username, SessionID: p.Session.ID, TargetID: ep.TargetID,
		Protocol: string(target.Cloud), PolicyID: d.Policy.ID, MaxSession: length, RetentionDays: retentionDays(ep, d), ClientIP: ip}
	// Nothing after this answer may hang off the request's context: the
	// session outlives it. Its values (the request id) stay.
	rr := r.WithContext(context.WithoutCancel(ctx))
	run, ok := h.startRun(rr, nil, g, ep, ip)
	if !ok {
		return nil, "", "", fmt.Errorf("cloud: session row could not be written")
	}
	now := cloudNow()
	endsAt := now.Add(length)
	run.startDetails = map[string]any{"account": ep.CloudAccountID, "role": ep.CloudRoleARN, "console": terms.Console, "cli": terms.CLI, "ends_at": endsAt.UTC().Format(time.RFC3339)}
	run.cloud = &gateway.CloudTerms{Console: terms.Console, CLI: terms.CLI}
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
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		done()
		run.finishRecording(rec, row)
		run.end(session.EndError, "", map[string]string{"detail": "the session token could not be made"})
		return nil, "", "", err
	}
	token := CloudTokenPrefix + base64.RawURLEncoding.EncodeToString(raw[:])
	sess := &cloudSession{id: run.s.ID, hash: sha256.Sum256([]byte(token)), userID: p.User.ID, username: p.User.Username, ep: ep,
		terms: terms, minter: minter, endsAt: endsAt, record: record}
	h.clouds.add(sess)
	record("session started as " + assumedRoleARN(ep.CloudRoleARN, cloud.SessionNameFor(sess.id)) + ", until " + clock(endsAt))
	go h.runCloud(sctx, run, sess, rec, row, done)

	res := &connectResponse{SessionID: run.s.ID, ExpiresAt: &endsAt,
		Cloud: &cloudConnect{Console: terms.Console, CLI: terms.CLI, AccountID: ep.CloudAccountID, AccountAlias: ep.CloudAccountAlias,
			RoleName: cloud.RoleNameOf(ep.CloudRoleARN), Region: ep.CloudRegion, ExpiresAt: endsAt}}
	if terms.CLI {
		// The token is the command line's: with the command line off nothing
		// would take it, so none is handed out.
		res.Cloud.Token = token
		res.Cloud.CredentialsURL = h.PublicURL + "/api/v1/cloud/" + run.s.ID + "/credentials"
		res.Cloud.Profile = cloudProfile(ep, token, res.Cloud.CredentialsURL)
	}
	return res, "", "", nil
}

// assumedRoleARN is the ARN the session acts as, built from the role's: the
// partition and account are the role's, the name and the session name follow.
func assumedRoleARN(roleARN, sessionName string) string {
	parts := strings.SplitN(roleARN, ":", 6)
	if len(parts) < 6 {
		return roleARN + "/" + sessionName
	}
	return "arn:" + parts[1] + ":sts::" + parts[4] + ":assumed-role/" + cloud.RoleNameOf(roleARN) + "/" + sessionName
}

// cloudProfile is the ~/.aws/config stanza the person pastes: a profile
// whose credentials come from the gateway through curl, which the AWS CLI
// and SDKs already know how to call (credential_process).
func cloudProfile(ep *endpoint, token, credentialsURL string) string {
	label := ep.CloudAccountAlias
	if label == "" {
		label = ep.CloudAccountID
	}
	name := profileWord("zanskar-" + label + "-" + cloud.RoleNameOf(ep.CloudRoleARN))
	s := "[profile " + name + "]\n" +
		"credential_process = curl -sf -H \"Authorization: Bearer " + token + "\" " + credentialsURL + "\n"
	if ep.CloudRegion != "" {
		s += "region = " + ep.CloudRegion + "\n"
	}
	return s
}

// profileWord keeps a profile name to what the AWS config file takes.
func profileWord(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

// clock is a time as the recording and the console say it.
func clock(t time.Time) string { return t.UTC().Format("15:04 UTC") }

// runCloud keeps the session until the registry ends it or its duration
// passes, then closes it: the token is refused, the recording closed, the
// row ended and the end audited, saying what the gateway cannot take back.
func (h *Handler) runCloud(ctx context.Context, run *sessionRun, sess *cloudSession, rec recorder, row *session.Recording, done func()) {
	defer done()
	defer h.clouds.remove(sess.id)
	// The end is a wall-clock moment, armed on the real clock: a test that
	// moves cloudNow back before its connect brings the end near.
	timer := time.NewTimer(time.Until(sess.endsAt))
	defer timer.Stop()
	var reason, detail string
	select {
	case <-ctx.Done():
		reason, detail = gateway.CancelReason(ctx)
	case <-timer.C:
		reason, detail = session.EndMaxDuration, "ended after the session's maximum of "+run.g.MaxSession.String()
	}
	remains := sess.close()
	if reason != session.EndMaxDuration {
		// Honest about what a terminate leaves: credentials already handed
		// out live on until they end by themselves.
		line := "terminated"
		if remains != "" {
			line += "; " + remains
		}
		sess.record(line)
	} else if remains != "" {
		sess.record("ended; " + remains)
	}
	run.finishRecording(rec, row)
	run.end(reason, "", map[string]string{"detail": detail})
}

// close marks the session ended and says what outlives it: the command-line
// credentials until their end, the console until its.
func (c *cloudSession) close() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	now := cloudNow()
	var parts []string
	if !c.cli.Expires.IsZero() && c.cli.Expires.After(now) {
		parts = append(parts, "command-line credentials end by "+clock(c.cli.Expires))
	}
	if c.consoleUntil != nil && c.consoleUntil.After(now) {
		parts = append(parts, "console by "+clock(*c.consoleUntil))
	}
	return strings.Join(parts, ", ")
}

// cliCredentials is the command line's credentials: the cached ones while
// they have more than the margin left, else a fresh mint, said to be fresh.
func (c *cloudSession) cliCredentials(ctx context.Context) (cloud.Credentials, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return cloud.Credentials{}, false, errCloudEnded
	}
	now := cloudNow()
	if c.cli.AccessKeyID != "" && now.Add(cloudCLIMargin).Before(c.cli.Expires) {
		return c.cli, false, nil
	}
	creds, err := c.minter.Mint(ctx, c.mintRequest(cloudCLIDuration))
	if err != nil {
		return cloud.Credentials{}, false, err
	}
	c.cli = creds
	return creds, true, nil
}

// consoleCredentials mints for the console: the session's remaining time,
// within what STS allows.
func (c *cloudSession) consoleCredentials(ctx context.Context) (cloud.Credentials, time.Duration, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return cloud.Credentials{}, 0, errCloudEnded
	}
	d := c.endsAt.Sub(cloudNow()).Round(time.Second)
	if d < cloud.MintMinDuration {
		d = cloud.MintMinDuration
	}
	if d > cloud.MintMaxDuration {
		d = cloud.MintMaxDuration
	}
	creds, err := c.minter.Mint(ctx, c.mintRequest(d))
	return creds, d, err
}

func (c *cloudSession) setConsoleUntil(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.consoleUntil = &t
}

var errCloudEnded = errors.New("cloud: the session has ended")

// bearerToken is the token in an Authorization header, "" without one.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// opens reports whether token is the session's own, in constant time.
func (c *cloudSession) opens(token string) bool {
	sum := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(sum[:], c.hash[:]) == 1
}

// cloudCredentials serves GET /api/v1/cloud/{id}/credentials: the AWS
// credential_process answer for the session named by the path, opened by
// its token and nothing else. A session that has ended is told so (410); a
// token that is not the session's gets 401 and learns nothing more.
func (h *Handler) cloudCredentials(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	w.Header().Set("Cache-Control", "no-store")
	sess, ok := h.clouds.lookup(id)
	if !ok {
		if s, err := h.Sessions.Get(r.Context(), id); err == nil && s.Protocol == string(target.Cloud) && s.EndedAt != nil {
			httpx.WriteError(w, r, http.StatusGone, "session_ended", "the session has ended; connect again from the portal")
			return
		}
		httpx.WriteError(w, r, http.StatusUnauthorized, "invalid_token", "the session token does not open a live cloud session")
		return
	}
	if !sess.opens(bearerToken(r)) {
		httpx.WriteError(w, r, http.StatusUnauthorized, "invalid_token", "the session token does not open a live cloud session")
		return
	}
	if !sess.terms.CLI {
		httpx.WriteError(w, r, http.StatusForbidden, "cli_off", "the policy opens the console of this account, not the command line")
		return
	}
	creds, fresh, err := sess.cliCredentials(r.Context())
	if err != nil {
		if errors.Is(err, errCloudEnded) {
			httpx.WriteError(w, r, http.StatusGone, "session_ended", "the session has ended; connect again from the portal")
			return
		}
		sess.record("command-line credentials refused: " + mintReason(err))
		h.record(r, actorFor(sess.userID, auth.ClientIP(r)).Event(audit.SessionCloudCredentials, "access_session", id, audit.Failure, map[string]any{"error": mintReason(err)}))
		httpx.WriteError(w, r, http.StatusBadGateway, "mint_failed", "Zanskar: the gateway could not assume the role for the command line ("+mintReason(err)+")")
		return
	}
	if fresh {
		sess.record("command-line credentials issued until " + clock(creds.Expires))
		h.record(r, actorFor(sess.userID, auth.ClientIP(r)).Event(audit.SessionCloudCredentials, "access_session", id, audit.Success,
			map[string]any{"target_id": sess.ep.TargetID, "account": sess.ep.CloudAccountID, "role": sess.ep.CloudRoleARN, "until": creds.Expires.UTC().Format(time.RFC3339)}))
	}
	// The client is told to come back by the session's end at the latest,
	// where it is refused; STS issues nothing shorter than fifteen minutes,
	// so the credentials themselves run on to their own end (ADR 0050, 3).
	expiration := creds.Expires
	if expiration.After(sess.endsAt) {
		expiration = sess.endsAt
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"Version": 1, "AccessKeyId": creds.AccessKeyID, "SecretAccessKey": creds.SecretAccessKey,
		"SessionToken": creds.SessionToken, "Expiration": expiration.UTC().Format(time.RFC3339)})
}

// mintReason is a mint error as the person may read it: Zanskar's words,
// never AWS's request ids.
func mintReason(err error) string {
	switch {
	case errors.Is(err, cloud.ErrMintRefused):
		return "the role refused the gateway; its trust policy may have changed"
	case errors.Is(err, cloud.ErrMintDuration):
		return "the role's maximum session is shorter than asked"
	case errors.Is(err, cloud.ErrFederation):
		return "AWS's sign-in endpoint refused the exchange"
	}
	return "AWS could not be reached"
}

// cloudConsoleResponse is the console sign-in as the portal posts it.
type cloudConsoleResponse struct {
	Action           string            `json:"action"`
	Fields           map[string]string `json:"fields"`
	ConsoleUntil     time.Time         `json:"console_until"`
	DurationHonoured bool              `json:"duration_honoured"`
}

// cloudConsole serves POST /api/v1/cloud/{id}/console for the session's own
// person, signed in to the portal: a fresh mint for the session's remaining
// time, exchanged for a sign-in the portal POSTs into a new tab. The URL is
// never built as a GET a browser would keep.
func (h *Handler) cloudConsole(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, _ := auth.FromContext(r.Context())
	w.Header().Set("Cache-Control", "no-store")
	sess, ok := h.clouds.lookup(id)
	if !ok || sess.userID != p.User.ID {
		if s, err := h.Sessions.Get(r.Context(), id); err == nil && s.UserID == p.User.ID && s.Protocol == string(target.Cloud) && s.EndedAt != nil {
			httpx.WriteError(w, r, http.StatusGone, "session_ended", "the session has ended; connect again")
			return
		}
		httpx.WriteError(w, r, http.StatusNotFound, "not_found", "no live cloud session of yours has that id")
		return
	}
	if !sess.terms.Console {
		httpx.WriteError(w, r, http.StatusForbidden, "console_off", "the policy opens the command line of this account, not the console")
		return
	}
	actor := actorFor(sess.userID, auth.ClientIP(r))
	creds, d, err := sess.consoleCredentials(r.Context())
	if err != nil {
		if errors.Is(err, errCloudEnded) {
			httpx.WriteError(w, r, http.StatusGone, "session_ended", "the session has ended; connect again")
			return
		}
		sess.record("console sign-in refused: " + mintReason(err))
		h.record(r, actor.Event(audit.SessionCloudConsole, "access_session", id, audit.Failure, map[string]any{"error": mintReason(err)}))
		httpx.WriteError(w, r, http.StatusBadGateway, "mint_failed", "Zanskar: the gateway could not assume the role for the console ("+mintReason(err)+")")
		return
	}
	signIn, honoured, err := h.federation().SignIn(r.Context(), creds, d, h.PublicURL, cloud.ConsoleDestination(sess.ep.CloudRegion))
	if err != nil {
		sess.record("console sign-in refused: " + mintReason(err))
		h.record(r, actor.Event(audit.SessionCloudConsole, "access_session", id, audit.Failure, map[string]any{"error": mintReason(err)}))
		httpx.WriteError(w, r, http.StatusBadGateway, "console_failed", "Zanskar: AWS did not issue the console sign-in ("+mintReason(err)+")")
		return
	}
	until := creds.Expires
	if until.IsZero() {
		until = cloudNow().Add(d)
	}
	sess.setConsoleUntil(until)
	h.Registry.SetCloudConsoleUntil(id, until)
	// Whether AWS took the duration decides how long a console may outlive
	// an hour (ADR 0050's measurement); the log keeps the answer per issue.
	h.Log.Debug("console sign-in issued", "session", id, "duration_honoured", honoured, "asked", d.String(), "until", until.UTC().Format(time.RFC3339))
	sess.record("console sign-in issued (runs until " + clock(until) + ")")
	h.record(r, actor.Event(audit.SessionCloudConsole, "access_session", id, audit.Success,
		map[string]any{"target_id": sess.ep.TargetID, "account": sess.ep.CloudAccountID, "role": sess.ep.CloudRoleARN,
			"console_until": until.UTC().Format(time.RFC3339), "duration_honoured": honoured}))
	httpx.WriteJSON(w, http.StatusOK, cloudConsoleResponse{Action: signIn.Action, Fields: signIn.Fields, ConsoleUntil: until, DurationHonoured: honoured})
}

// cloudTermsHold reports whether a live cloud session's switches are what a
// fresh decision gives. A switch changed either way ends the session (ADR
// 0050, 3), as a Kubernetes scope change does: the session was issued under
// the old terms (a token, or none), and the person connects again under the
// new ones.
func cloudTermsHold(l *gateway.CloudTerms, d policy.Decision) bool {
	if l == nil {
		return true
	}
	want := policy.CloudTerms{Console: true, CLI: true}
	if d.Cloud != nil {
		want = *d.Cloud
	}
	return l.Console == want.Console && l.CLI == want.CLI
}
