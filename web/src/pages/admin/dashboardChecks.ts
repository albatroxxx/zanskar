import { fmtTime } from '../../api/format'
import type { AdminOverview } from '../../api/types'

type Integrity = NonNullable<AdminOverview['integrity']>

/** exportSlack is how many events a SIEM sink may trail by in the normal
 *  course: the exporter ships every few seconds, up to 200 at a time. */
const exportSlack = 200

/**
 * integrityChecks reads the integrity row (2026-10-31): whether the audit
 * chain held at its last check (never "intact" before the first), recordings
 * lost this week, the identity providers' listings, the SIEM export. Each
 * line opens the page that explains it.
 */
export function integrityChecks(i: Integrity): { label: string; text: string; state: 'ok' | 'warn' | 'danger' | 'unknown'; to: string }[] {
  const chain = i.audit_chain
  const c = !chain
    ? { text: 'Not checked yet', state: 'unknown' as const }
    : chain.error
      ? { text: `Could not check (${fmtTime(chain.at)})`, state: 'warn' as const }
      : chain.intact
        ? { text: `Intact · checked ${fmtTime(chain.at)}`, state: 'ok' as const }
        : { text: `${chain.problems} ${chain.problems === 1 ? 'problem' : 'problems'} · checked ${fmtTime(chain.at)}`, state: 'danger' as const }
  const lost = i.recordings_lost_7d
  const d = i.directories
  const dir =
    d.listed === 0
      ? { text: 'None listed on a schedule', state: 'unknown' as const }
      : d.failing > 0
        ? { text: `${d.failing} failing`, state: 'danger' as const }
        : d.held_back > 0
          ? { text: `${d.held_back} ${d.held_back === 1 ? 'account' : 'accounts'} held back`, state: 'warn' as const }
          : d.not_run > 0
            ? { text: `${d.not_run} not run yet`, state: 'unknown' as const }
            : { text: 'In sync', state: 'ok' as const }
  const x = i.export
  const exp =
    x.sinks === 0
      ? { text: 'Not configured', state: 'unknown' as const }
      : x.behind > exportSlack
        ? { text: `${x.behind} events behind`, state: 'warn' as const }
        : { text: 'Up to date', state: 'ok' as const }
  return [
    { label: 'Audit chain', ...c, to: '/admin/events' },
    {
      label: 'Recordings',
      text: lost === 0 ? 'None lost in 7 days' : `${lost} lost in 7 days`,
      state: lost === 0 ? 'ok' : 'danger',
      to: lost === 0 ? '/admin/recordings' : '/admin/events?' + new URLSearchParams({ action: 'recording.lost', outcome: 'failure', range: '7d' }).toString(),
    },
    { label: 'Identity providers', ...dir, to: '/admin/identity-providers' },
    { label: 'SIEM export', ...exp, to: '/admin/logs' },
  ]
}
