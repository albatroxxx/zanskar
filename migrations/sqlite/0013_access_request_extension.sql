-- Approvals round two (ADR 0018, amended 2026-09-28): an approver may shorten
-- or lengthen the granted duration, so the approved minutes are stored beside
-- the requested ones; and a user may ask to extend an active grant, which is
-- a new request pointing at the grant it extends and, on approval, runs on
-- from that grant's expiry.
ALTER TABLE access_requests ADD COLUMN approved_minutes INTEGER;
ALTER TABLE access_requests ADD COLUMN extends_request_id TEXT REFERENCES access_requests(id) ON DELETE SET NULL;
