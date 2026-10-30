import { useState, type ReactNode } from 'react'

/** Neutral glyphs drawn here, no third-party marks (trademark policy: the
 *  console ships nothing it would need permission for). A glyph never deletes
 *  information: OS and engine glyphs carry the name in text beside them, and
 *  a state glyph shows its words instantly on hover and pinned on click. */

function svgProps(size = 16) {
  return { width: size, height: size, viewBox: '0 0 24 24', fill: 'none' as const, stroke: 'currentColor', strokeWidth: 1.8, strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const, 'aria-hidden': true as const }
}

function Glyph({ label, tone, children }: { label: string; tone?: 'warn' | 'danger' | 'ok' | 'muted'; children: ReactNode }) {
  return (
    <span className={'glyph' + (tone ? ' ' + tone : '')} role="img" aria-label={label} title={label}>
      <svg {...svgProps()}>{children}</svg>
    </span>
  )
}

function osShape(os: string): { name: string; shape: ReactNode } {
  switch (os) {
    case 'linux':
      return {
        name: 'Linux',
        shape: (
          <>
            <rect x="3" y="4" width="18" height="16" rx="2" />
            <polyline points="7 9.5 10 12 7 14.5" />
            <line x1="12.5" y1="15.5" x2="16.5" y2="15.5" />
          </>
        ),
      }
    case 'windows':
      return {
        name: 'Windows',
        shape: (
          <>
            <rect x="3" y="4" width="18" height="16" rx="2" />
            <line x1="3" y1="9" x2="21" y2="9" />
            <line x1="6" y1="6.5" x2="6" y2="6.5" />
            <line x1="9" y1="6.5" x2="9" y2="6.5" />
          </>
        ),
      }
    default:
      return {
        name: os ? os.charAt(0).toUpperCase() + os.slice(1) : 'Unknown',
        shape: (
          <>
            <rect x="7" y="7" width="10" height="10" rx="1.5" />
            <line x1="10" y1="7" x2="10" y2="4" />
            <line x1="14" y1="7" x2="14" y2="4" />
            <line x1="10" y1="20" x2="10" y2="17" />
            <line x1="14" y1="20" x2="14" y2="17" />
            <line x1="7" y1="10" x2="4" y2="10" />
            <line x1="7" y1="14" x2="4" y2="14" />
            <line x1="20" y1="10" x2="17" y2="10" />
            <line x1="20" y1="14" x2="17" y2="14" />
          </>
        ),
      }
  }
}

/** OSIcon says what runs on a target: a glyph with the OS's name beside it,
 *  the way the database cylinder sits beside its engine's name. The glyph is
 *  decoration; the visible name carries the meaning. */
export function OSIcon({ os }: { os: string }) {
  const { name, shape } = osShape(os)
  return (
    <span className="glyph-name">
      <span className="glyph" aria-hidden="true">
        <svg {...svgProps()}>{shape}</svg>
      </span>
      {name}
    </span>
  )
}

/** DatabaseIcon is the one cylinder every engine shares; the engine's name
 *  stays in text beside it, because a neutral glyph cannot say which engine. */
export function DatabaseIcon({ label = 'Database' }: { label?: string }) {
  return (
    <Glyph label={label}>
      <ellipse cx="12" cy="5.5" rx="7.5" ry="2.5" />
      <path d="M4.5 5.5v13c0 1.4 3.4 2.5 7.5 2.5s7.5-1.1 7.5-2.5v-13" />
      <path d="M4.5 12c0 1.4 3.4 2.5 7.5 2.5s7.5-1.1 7.5-2.5" />
    </Glyph>
  )
}

/** StateIcon marks a row that needs a decision or gives reassurance. Its
 *  words appear the moment the pointer is over it and pin open on click (no
 *  slow native tooltip); screen readers get them from the button's label. */
export function StateIcon({ state, label }: { state: 'warn' | 'danger' | 'ok' | 'unknown' | 'info'; label: string }) {
  const [pinned, setPinned] = useState(false)
  const tone = state === 'unknown' || state === 'info' ? 'muted' : state
  return (
    <span className="glyph-wrap">
      <button
        type="button"
        className={'glyph-btn ' + tone}
        aria-label={label}
        aria-expanded={pinned}
        onClick={() => setPinned((p) => !p)}
        onBlur={() => setPinned(false)}
      >
        <svg {...svgProps()}>
          {state === 'ok' ? (
            <>
              <circle cx="12" cy="12" r="9" />
              <polyline points="8 12.5 11 15.5 16 9.5" />
            </>
          ) : state === 'unknown' ? (
            <>
              <circle cx="12" cy="12" r="9" />
              <line x1="8.5" y1="12" x2="15.5" y2="12" />
            </>
          ) : state === 'info' ? (
            <>
              <circle cx="12" cy="12" r="9" />
              <line x1="12" y1="11" x2="12" y2="16.5" />
              <line x1="12" y1="7.6" x2="12" y2="7.7" />
            </>
          ) : (
            <>
              <path d="M12 3.5 22 20.5 H2 Z" />
              <line x1="12" y1="10" x2="12" y2="14.5" />
              <line x1="12" y1="17.2" x2="12" y2="17.3" />
            </>
          )}
        </svg>
      </button>
      <span className={'glyph-tip' + (pinned ? ' open' : '')} aria-hidden="true">{label}</span>
    </span>
  )
}

/** TileIcon is a tile's identity mark: decorative (the caption carries the
 *  meaning), muted, one simple shape per kind. */
export function TileIcon({ kind }: { kind: 'approvals' | 'attention' | 'key' | 'ban' | 'session' | 'clock' | 'list' | 'server' | 'db' | 'stack' | 'app' }) {
  const shape = (() => {
    switch (kind) {
      case 'app':
        // A browser window: the frame, its title bar and one address field.
        return (
          <>
            <rect x="3" y="4" width="18" height="16" rx="2" />
            <line x1="3" y1="9" x2="21" y2="9" />
            <line x1="6" y1="6.5" x2="6" y2="6.6" />
            <rect x="6" y="12" width="12" height="2.5" rx="1" />
          </>
        )
      case 'approvals':
        return (
          <>
            <rect x="5" y="3" width="14" height="18" rx="2" />
            <polyline points="9 12.5 11.5 15 15.5 9.5" />
          </>
        )
      case 'attention':
        return (
          <>
            <path d="M12 3.5 22 20.5 H2 Z" />
            <line x1="12" y1="10" x2="12" y2="14.5" />
            <line x1="12" y1="17.2" x2="12" y2="17.3" />
          </>
        )
      case 'key':
        return (
          <>
            <circle cx="8" cy="15" r="4" />
            <line x1="11" y1="12" x2="20" y2="3" />
            <line x1="16" y1="7" x2="19" y2="10" />
          </>
        )
      case 'ban':
        return (
          <>
            <circle cx="12" cy="12" r="9" />
            <line x1="5.6" y1="5.6" x2="18.4" y2="18.4" />
          </>
        )
      case 'session':
        return (
          <>
            <rect x="3" y="4" width="18" height="13" rx="2" />
            <line x1="9" y1="20.5" x2="15" y2="20.5" />
            <line x1="12" y1="17" x2="12" y2="20.5" />
          </>
        )
      case 'clock':
        return (
          <>
            <circle cx="12" cy="12" r="9" />
            <polyline points="12 7 12 12 15.5 14" />
          </>
        )
      case 'list':
        return (
          <>
            <line x1="5" y1="7" x2="19" y2="7" />
            <line x1="5" y1="12" x2="19" y2="12" />
            <line x1="5" y1="17" x2="13" y2="17" />
          </>
        )
      case 'server':
        return (
          <>
            <rect x="3" y="4" width="18" height="7" rx="2" />
            <rect x="3" y="13" width="18" height="7" rx="2" />
            <line x1="7" y1="7.5" x2="7" y2="7.6" />
            <line x1="7" y1="16.5" x2="7" y2="16.6" />
          </>
        )
      case 'db':
        return (
          <>
            <ellipse cx="12" cy="5.5" rx="7.5" ry="2.5" />
            <path d="M4.5 5.5v13c0 1.4 3.4 2.5 7.5 2.5s7.5-1.1 7.5-2.5v-13" />
            <path d="M4.5 12c0 1.4 3.4 2.5 7.5 2.5s7.5-1.1 7.5-2.5" />
          </>
        )
      case 'stack':
        return (
          <>
            <rect x="7" y="4" width="14" height="9" rx="1.5" />
            <path d="M4 8v9a2 2 0 0 0 2 2h11" />
          </>
        )
    }
  })()
  return (
    <span className="glyph" aria-hidden="true">
      <svg {...svgProps(18)}>{shape}</svg>
    </span>
  )
}

/** BellIcon and GearIcon sit in the admin corner beside the command line,
 *  drawn at its size and weight. */
/** Signing in through another system: an arrow going in at a door. */
export function SignInIcon() {
  return (
    <svg {...svgProps(18)}>
      <path d="M14 4h4a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-4" />
      <polyline points="10 8 14 12 10 16" />
      <line x1="14" y1="12" x2="3" y2="12" />
    </svg>
  )
}

export function BellIcon() {
  return (
    <svg width="23" height="23" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M6 9a6 6 0 0 1 12 0c0 6 2.5 8 2.5 8h-17S6 15 6 9" />
      <path d="M10 20.5a2 2 0 0 0 4 0" />
    </svg>
  )
}

export function GearIcon() {
  return (
    <svg width="23" height="23" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" aria-hidden="true">
      <polygon points="19.4,9.0 22.3,10.2 22.3,13.8 19.4,15.0 19.4,15.2 20.6,18.0 18.0,20.6 15.2,19.4 15.0,19.4 13.8,22.3 10.2,22.3 9.0,19.4 8.8,19.4 6.0,20.6 3.4,18.0 4.6,15.2 4.6,15.0 1.7,13.8 1.7,10.2 4.6,9.0 4.6,8.8 3.4,6.0 6.0,3.4 8.8,4.6 9.0,4.6 10.2,1.7 13.8,1.7 15.0,4.6 15.2,4.6 18.0,3.4 20.6,6.0 19.4,8.8" />
      <circle cx="12" cy="12" r="3.2" />
    </svg>
  )
}

/** DoneIcon is the large tick a finished host action shows beside its words. */
export function DoneIcon() {
  return (
    <svg {...svgProps(28)}>
      <circle cx="12" cy="12" r="9" />
      <polyline points="8 12.5 11 15.5 16 9.5" />
    </svg>
  )
}

/** ThemeIcon is the corner's theme menu: a circle half light, half dark. */
export function ThemeIcon() {
  return (
    <svg width="23" height="23" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" aria-hidden="true">
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 3.5a8.5 8.5 0 0 1 0 17z" fill="currentColor" stroke="none" />
    </svg>
  )
}

/** CommandsIcon is the command line's list of commands. */
export function CommandsIcon() {
  return (
    <svg {...svgProps(16)}>
      <line x1="9" y1="6" x2="20" y2="6" />
      <line x1="9" y1="12" x2="20" y2="12" />
      <line x1="9" y1="18" x2="20" y2="18" />
      <circle cx="4.5" cy="6" r="1" />
      <circle cx="4.5" cy="12" r="1" />
      <circle cx="4.5" cy="18" r="1" />
    </svg>
  )
}

/** MinimiseIcon folds a panel away, keeping what it holds. */
export function MinimiseIcon() {
  return (
    <svg {...svgProps(16)}>
      <line x1="5" y1="18" x2="19" y2="18" />
    </svg>
  )
}

/** CloseIcon shuts a panel. */
export function CloseIcon() {
  return (
    <svg {...svgProps(16)}>
      <line x1="6" y1="6" x2="18" y2="18" />
      <line x1="18" y1="6" x2="6" y2="18" />
    </svg>
  )
}

/** AuditIcon marks something every use of which is recorded: a shield with a tick. */
export function AuditIcon() {
  return (
    <svg {...svgProps(16)}>
      <path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z" />
      <polyline points="9 12 11 14 15 10" />
    </svg>
  )
}

/** LockIcon is shut until a code is verified, then open. */
export function LockIcon({ open }: { open: boolean }) {
  return (
    <svg {...svgProps(16)}>
      <rect x="5" y="11" width="14" height="9" rx="2" />
      <path d={open ? 'M8 11V8a4 4 0 0 1 7.5-2' : 'M8 11V8a4 4 0 0 1 8 0v3'} />
    </svg>
  )
}
