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
	"github.com/albatroxxx/zanskar/internal/recording"
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

// Phase C (ADR 0050, 4): a session's activity is what CloudTrail holds under
// its role session name, read on a reviewer's demand while it runs and once
// more after it, since CloudTrail delivers an event up to fifteen minutes
// late. The recording stays open for that last read.
var (
	// cloudActivityLateness is how long after the end the last read waits;
	// tests shorten it. The overlap between reads is the real lateness.
	cloudActivityLateness = session.CloudActivityLateness
	// cloudDrainPoll is how often the wait looks for a drain.
	cloudDrainPoll = time.Second
)

// cloudActivityTimeout bounds one read: a mint and up to forty pages at two
// a second.
const cloudActivityTimeout = 45 * time.Second

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
	// startedAt is where the first activity read begins; endsAt where the
	// session ends by itself.
	startedAt time.Time
	endsAt    time.Time
	record    func(line string)
	// activity is what the session's reads of CloudTrail hold between them.
	activity cloudActivity

	mu           sync.Mutex
	cli          cloud.Credentials
	consoleUntil *time.Time
	closed       bool
}

// cloudActivity is the state between a session's activity reads (phase C):
// the ids already on the record and the end of the last window read. Reads
// are one at a time.
type cloudActivity struct {
	mu        sync.Mutex
	seen      map[string]bool
	readUntil time.Time
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
		terms: terms, minter: minter, startedAt: now, endsAt: endsAt, record: record}
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
// passes, then closes it: the token is refused, the row ended and the end
// audited, saying what the gateway cannot take back. The recording stays
// open for the activity's last read (phase C) and is finished after it.
func (h *Handler) runCloud(ctx context.Context, run *sessionRun, sess *cloudSession, rec *recording.Asciicast, row *session.Recording, done func()) {
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
	// The session ends now: the registry forgets it, the token is refused,
	// the row closes and the end is audited, as before phase C.
	done()
	h.clouds.remove(sess.id)
	run.end(reason, "", map[string]string{"detail": detail})
	h.finishCloudRecording(run, sess, rec, row)
}

// finishCloudRecording keeps a cloud session's recording open after its end
// for the lateness CloudTrail allows itself, reads the activity once more,
// says the record is complete and finishes the recording (phase C). The
// session is in the awaiting set meanwhile, which tells the sweep the
// recording is this gateway's; a gateway that goes away inside the window
// leaves the recording to the next process's sweep, which finishes it with
// the line "activity not read: gateway restarted" (session.Sweeper). A drain
// cuts the wait short and reads what there is, so a graceful restart
// finishes and stores the recording itself rather than leave it behind.
func (h *Handler) finishCloudRecording(run *sessionRun, sess *cloudSession, rec *recording.Asciicast, row *session.Recording) {
	h.awaiting.m.Store(sess.id, time.Now())
	defer h.awaiting.m.Delete(sess.id)
	// What the session wrote is in storage before the wait: a crash inside
	// the window loses the activity, not the session.
	if err := rec.Flush(); err != nil {
		h.Log.Warn("flush recording", "session", sess.id, "err", err)
	}
	timer := time.NewTimer(cloudActivityLateness)
	defer timer.Stop()
	poll := time.NewTicker(cloudDrainPoll)
	defer poll.Stop()
	early := false
wait:
	for {
		select {
		case <-timer.C:
			break wait
		case <-poll.C:
			if h.draining() {
				early = true
				break wait
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(run.r.Context()), cloudActivityTimeout)
	defer cancel()
	n, until, err := h.readActivity(ctx, sess)
	details := map[string]any{"target_id": sess.ep.TargetID, "by": "the gateway, after the session"}
	outcome := audit.Success
	if err != nil {
		outcome, details["error"] = audit.Failure, activityReason(err)
	} else {
		details["events"], details["read_until"] = n, until.UTC().Format(time.RFC3339)
	}
	h.record(run.r, audit.Actor{IP: "system"}.Event(audit.SessionCloudActivity, "access_session", sess.id, outcome, details))
	if early {
		sess.record("activity not read in full: gateway restarting")
	} else {
		sess.record("activity complete")
	}
	run.finishRecording(rec, row)
}

// readActivity reads what CloudTrail holds of the session since the last
// read, less the lateness (an event may arrive after the window that covered
// its time was read; the seen set keeps each once), up to now, and writes it
// to the recording: a header with the count and one line an event, or why
// nothing was read. It returns the count and the end of the window read.
func (h *Handler) readActivity(ctx context.Context, sess *cloudSession) (int, time.Time, error) {
	sess.activity.mu.Lock()
	defer sess.activity.mu.Unlock()
	now := cloudNow()
	from := sess.startedAt
	if last := sess.activity.readUntil; !last.IsZero() && last.Add(-session.CloudActivityLateness).After(from) {
		from = last.Add(-session.CloudActivityLateness)
	}
	if sess.activity.seen == nil {
		sess.activity.seen = map[string]bool{}
	}
	reader := &cloud.ActivityReader{Minter: sess.minter, NewTrail: h.NewTrail, Log: h.Log}
	events, err := reader.Read(ctx, cloud.ActivityRequest{RoleARN: sess.ep.CloudRoleARN, ExternalID: sess.ep.CloudExternalID, Region: sess.ep.CloudRegion,
		SessionName: cloud.SessionNameFor(sess.id), From: from, To: now, Seen: sess.activity.seen})
	if err != nil {
		reason := activityReason(err)
		sess.record("activity not read: " + reason)
		// A role without the statement is the account's choice, logged
		// low; anything else is worth a look.
		if errors.Is(err, cloud.ErrLookupDenied) {
			h.Log.Debug("activity not read", "session", sess.id, "reason", reason)
		} else {
			h.Log.Warn("activity not read", "session", sess.id, "reason", reason)
		}
		return 0, sess.activity.readUntil, err
	}
	sess.activity.readUntil = now
	if len(events) == 0 {
		sess.record("activity from CloudTrail: none yet")
		return 0, now, nil
	}
	count := fmt.Sprintf("%d events", len(events))
	if len(events) == 1 {
		count = "1 event"
	}
	sess.record("activity from CloudTrail, " + count + " (events arrive up to 15 minutes late)")
	for _, ev := range events {
		sess.record(cloud.ActivityLine(ev))
	}
	return len(events), now, nil
}

// activityReason is a read's error as the recording and the reviewer read
// it: Zanskar's words, never AWS's request ids.
func activityReason(err error) string {
	switch {
	case errors.Is(err, cloud.ErrLookupDenied):
		return "the role lacks cloudtrail:LookupEvents"
	case errors.Is(err, cloud.ErrLookupThrottled):
		return "CloudTrail throttled the read"
	case errors.Is(err, context.DeadlineExceeded):
		return "CloudTrail did not answer in time"
	}
	return mintReason(err)
}

// cloudActivityResponse is what an on-demand read answers.
type cloudActivityResponse struct {
	Events    int       `json:"events"`
	ReadUntil time.Time `json:"read_until"`
}

// cloudActivity serves POST /api/v1/sessions/{id}/activity for a reviewer:
// the live cloud session's activity read now and appended to its recording,
// the count answered. A session that is not a cloud one (409 not_cloud) or
// has ended (410: its activity is in the recording) is told apart from one
// unknown (404) or not held here (409 not_live).
func (h *Handler) cloudActivity(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, _ := auth.FromContext(r.Context())
	actor := audit.Actor{UserID: p.User.ID, IP: auth.ClientIP(r)}
	sess, ok := h.clouds.lookup(id)
	if !ok {
		s, err := h.Sessions.Get(r.Context(), id)
		switch {
		case errors.Is(err, session.ErrNotFound):
			httpx.WriteError(w, r, http.StatusNotFound, "not_found", "no session has that id")
		case err != nil:
			httpx.Internal(w, r, h.Log, err)
		case s.Protocol != string(target.Cloud):
			httpx.WriteError(w, r, http.StatusConflict, "not_cloud", "activity is read for a cloud session; this is "+s.Protocol)
		case s.EndedAt != nil:
			httpx.WriteError(w, r, http.StatusGone, "session_ended", "the session has ended; the gateway reads its activity into the recording 15 minutes after the end")
		default:
			httpx.WriteError(w, r, http.StatusConflict, "not_live", "the session is not live on this gateway")
		}
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), cloudActivityTimeout)
	defer cancel()
	n, until, err := h.readActivity(ctx, sess)
	if err != nil {
		reason := activityReason(err)
		h.record(r, actor.Event(audit.SessionCloudActivity, "access_session", id, audit.Failure, map[string]any{"target_id": sess.ep.TargetID, "error": reason}))
		code := "activity_failed"
		if errors.Is(err, cloud.ErrLookupDenied) {
			code = "lookup_denied"
		}
		httpx.WriteError(w, r, http.StatusBadGateway, code, "Zanskar: the activity could not be read ("+reason+")")
		return
	}
	h.record(r, actor.Event(audit.SessionCloudActivity, "access_session", id, audit.Success,
		map[string]any{"target_id": sess.ep.TargetID, "events": n, "read_until": until.UTC().Format(time.RFC3339)}))
	httpx.WriteJSON(w, http.StatusOK, cloudActivityResponse{Events: n, ReadUntil: until})
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
// The mint runs with the lock released, so a terminate never waits on AWS
// (review 2026-11-17, L2); a session that closed meanwhile takes nothing
// from it. Two callers arriving on an empty cache mint twice, which is
// harmless: both answers are the role's for fifteen minutes.
func (c *cloudSession) cliCredentials(ctx context.Context) (cloud.Credentials, bool, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return cloud.Credentials{}, false, errCloudEnded
	}
	now := cloudNow()
	if c.cli.AccessKeyID != "" && now.Add(cloudCLIMargin).Before(c.cli.Expires) {
		creds := c.cli
		c.mu.Unlock()
		return creds, false, nil
	}
	c.mu.Unlock()
	creds, err := c.minter.Mint(ctx, c.mintRequest(cloudCLIDuration))
	if err != nil {
		return cloud.Credentials{}, false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		// Ended during the mint: close() named what it held, and credentials
		// it never named are not handed out.
		return cloud.Credentials{}, false, errCloudEnded
	}
	c.cli = creds
	return creds, true, nil
}

// consoleCredentials mints for the console: the session's remaining time,
// within what STS allows. A role whose maximum session is below that refuses
// the mint (ErrMintDuration); the console is then minted for an hour, the
// least a role's maximum can be, and shortened says so (ADR 0050's fallback:
// the grant's longer duration applies to the command line alone). A shorter
// refusal is the role's to explain. Nothing is held across the mint; the
// caller re-checks the session with setConsoleUntil.
func (c *cloudSession) consoleCredentials(ctx context.Context) (creds cloud.Credentials, d time.Duration, shortened bool, err error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return cloud.Credentials{}, 0, false, errCloudEnded
	}
	d = c.endsAt.Sub(cloudNow()).Round(time.Second)
	if d < cloud.MintMinDuration {
		d = cloud.MintMinDuration
	}
	if d > cloud.MintMaxDuration {
		d = cloud.MintMaxDuration
	}
	creds, err = c.minter.Mint(ctx, c.mintRequest(d))
	if errors.Is(err, cloud.ErrMintDuration) && d > time.Hour {
		d = time.Hour
		creds, err = c.minter.Mint(ctx, c.mintRequest(d))
		return creds, d, err == nil, err
	}
	return creds, d, false, err
}

// setConsoleUntil records the console's end, or reports false when the
// session closed while the sign-in was being issued: close() has already
// said what outlives the session, and a console it never named is not
// handed out (review 2026-11-17, C4).
func (c *cloudSession) setConsoleUntil(t time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	c.consoleUntil = &t
	return true
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
	creds, d, shortened, err := sess.consoleCredentials(r.Context())
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
	// The session may have ended during the two calls above (a terminate, a
	// policy change): its close() has said what outlives it, and a console
	// it did not name is discarded, never handed out (C4).
	if !sess.setConsoleUntil(until) {
		httpx.WriteError(w, r, http.StatusGone, "session_ended", "the session has ended; connect again")
		return
	}
	h.Registry.SetCloudConsoleUntil(id, until)
	// The session's duration was honoured when AWS took it and the role
	// allowed it; the fallback to an hour (L7) says it was not.
	honoured = honoured && !shortened
	// Whether AWS took the duration decides how long a console may outlive
	// an hour (ADR 0050's measurement); the log keeps the answer per issue.
	h.Log.Debug("console sign-in issued", "session", id, "duration_honoured", honoured, "shortened", shortened, "asked", d.String(), "until", until.UTC().Format(time.RFC3339))
	line := "console sign-in issued (runs until " + clock(until) + ")"
	if shortened {
		line = "console sign-in issued (runs until " + clock(until) + "; the role allowed less than the session)"
	}
	sess.record(line)
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
