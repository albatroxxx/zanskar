// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Direct mails a message to named people, outside any channel (ADR 0049):
// an access request whose grant names approvers reaches each of them who
// has an address, through the gateway's one mail server. Channels keep
// receiving what they asked for; this is in addition.
type Direct struct {
	Sender *Sender
	// Server reads the gateway's mail server (Repo.Server); nil from it
	// means none is set and nothing is sent.
	Server func(context.Context) (*Server, error)
	// Base is the console's public address, for the link.
	Base string
}

// ErrNoMailServer: no mail server is set, so nothing can be sent.
var ErrNoMailServer = errors.New("notify: no mail server is set")

// AccessRequested tells the approvers at to that who asked for proto access
// to target, with the link that opens the request in the approvals view.
// One message per address: an approver is not shown the others' addresses.
func (d *Direct) AccessRequested(ctx context.Context, to []string, who, proto, target, requestID string) error {
	if d == nil || d.Sender == nil || d.Server == nil {
		return ErrNoMailServer
	}
	if len(to) == 0 {
		return nil
	}
	srv, err := d.Server(ctx)
	if err != nil {
		return err
	}
	if srv == nil {
		return ErrNoMailServer
	}
	m := Message{Kind: EventAccessRequested, At: time.Now().UTC().Format("2006-01-02 15:04 UTC"),
		Subject: fmt.Sprintf("%s asks for %s access to %s", who, strings.ToUpper(proto), target),
		Link:    strings.TrimRight(d.Base, "/") + "/approvals?request=" + url.QueryEscape(requestID)}
	m.Text = m.Subject + ". Open it to approve or deny."
	m.Subject, m.Text = clean(m.Subject), clean(m.Text)
	var errs []error
	for _, rcpt := range to {
		errs = append(errs, d.sendOne(ctx, srv, rcpt, m))
	}
	return errors.Join(errs...)
}

// sendOne sends m to one address, within the send timeout.
func (d *Direct) sendOne(ctx context.Context, srv *Server, rcpt string, m Message) error {
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	return d.Sender.SendThrough(ctx, srv, []string{rcpt}, m)
}
