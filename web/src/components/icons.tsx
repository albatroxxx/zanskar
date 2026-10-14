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
export function StateIcon({ state, label }: { state: 'warn' | 'danger' | 'ok' | 'unknown'; label: string }) {
  const [pinned, setPinned] = useState(false)
  const tone = state === 'unknown' ? 'muted' : state
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
