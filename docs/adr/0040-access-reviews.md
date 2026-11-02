# 0040. Access reviews: who a policy covers, kept or removed, on the record

Date: 2026-11-03

## Status

Accepted 2026-11-03, idea 4 of the 2026-11-03 live audit, which the owner asked to build.

## Context

Access accrues. A person moves teams and keeps the policy that named them; a group grows. SOC 2
(CC6.2, CC6.3) and ISO 27001 (A.5.18) ask for periodic user-access reviews and for evidence that
they happened: who reviewed, when, what was kept and what removed. Zanskar knew who a policy
covers and, from `access_sessions.policy_id`, who used it and when; it had no place to decide
and no record of a decision.

## Decision

1. **A review is per policy.** The page lists each subject (a group or a person), the people a
   group brings, and each person's last session under the policy; subjects with nobody who used
   it, or not in 90 days, are flagged.
2. **The decision is the subjects to remove, and a note.** Completing a review removes them as an
   edit would, re-checks their live sessions (what the removal took away ends), stamps the policy
   `reviewed_at` and `reviewed_by` (migration 0043), and records one `policy.review` event with
   the kept and removed subjects and the note. Keeping everyone is a decision too, and stamps the
   policy the same way.
3. **Subjects, not group members.** A review removes a group from the policy, or a person named
   directly; taking someone out of a group stays on the group's page (and with a provider that
   owns the person, at the provider, ADR 0035).
4. **Due after a quarter.** A policy never reviewed, or reviewed more than 90 days ago, carries a
   due mark on its Review button.
5. **Administrators only**, like every policy change; auditors read the `policy.review` events.

## Consequences

- An auditor's evidence is the Events page filtered to *Access review completed*, or its CSV.
- A removal through a review is a policy change: the same validation, the same re-check of live
  sessions, its own event.
- The 90 days are fixed; a setting can come when someone needs another rhythm.
