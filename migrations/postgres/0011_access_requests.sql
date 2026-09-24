-- Just-in-time access approvals (PIM, ADR 0018). A policy may require approval,
-- making it grant eligibility rather than standing access; an approved request
-- becomes a time-bounded grant, recorded here through its whole lifecycle.
ALTER TABLE access_policies ADD COLUMN require_approval BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE access_requests (
    id                TEXT PRIMARY KEY,
    user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,       -- requester
    policy_id         TEXT REFERENCES access_policies(id) ON DELETE SET NULL,     -- the eligible policy
    target_id         TEXT REFERENCES targets(id) ON DELETE CASCADE,
    asg_id            TEXT REFERENCES autoscaling_groups(id) ON DELETE CASCADE,
    protocol          TEXT NOT NULL CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'winrm', 'database')),
    reason            TEXT NOT NULL,
    requested_minutes INTEGER NOT NULL,
    status            TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'revoked')),
    approver_user_id  TEXT REFERENCES users(id) ON DELETE SET NULL,
    decision_note     TEXT NOT NULL DEFAULT '',
    decided_at        TIMESTAMPTZ,
    expires_at        TIMESTAMPTZ,                                                 -- set on approval; grant is active while now < expires_at
    created_at        TIMESTAMPTZ NOT NULL,
    updated_at        TIMESTAMPTZ NOT NULL,
    CHECK (target_id IS NOT NULL OR asg_id IS NOT NULL)
);
CREATE INDEX access_requests_user_idx ON access_requests (user_id);
CREATE INDEX access_requests_status_idx ON access_requests (status);
