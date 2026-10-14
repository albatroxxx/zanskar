import type { ReactNode } from 'react'

/** Neutral glyphs drawn here, no third-party marks (trademark policy: the
 *  console ships nothing it would need permission for). Every icon carries its
 *  meaning in words too — aria-label for screen readers, title on hover — so
 *  replacing a word with an icon never deletes the information. */

function Glyph({ label, tone, children }: { label: string; tone?: 'warn' | 'danger' | 'ok' | 'muted'; children: ReactNode }) {
  return (
    <span className={'glyph' + (tone ? ' ' + tone : '')} role="img" aria-label={label} title={label}>
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        {children}
      </svg>
    </span>
  )
}

/** OSIcon says what runs on a target: a terminal for Linux, a window for
 *  Windows, a bare chip when the family is not known. */
export function OSIcon({ os }: { os: string }) {
  switch (os) {
    case 'linux':
      return (
        <Glyph label="Linux">
          <rect x="3" y="4" width="18" height="16" rx="2" />
          <polyline points="7 9.5 10 12 7 14.5" />
          <line x1="12.5" y1="15.5" x2="16.5" y2="15.5" />
        </Glyph>
      )
    case 'windows':
      return (
        <Glyph label="Windows">
          <rect x="3" y="4" width="18" height="16" rx="2" />
          <line x1="3" y1="9" x2="21" y2="9" />
          <line x1="6" y1="6.5" x2="6" y2="6.5" />
          <line x1="9" y1="6.5" x2="9" y2="6.5" />
        </Glyph>
      )
    default:
      return (
        <Glyph label={os || 'unknown'}>
          <rect x="7" y="7" width="10" height="10" rx="1.5" />
          <line x1="10" y1="7" x2="10" y2="4" />
          <line x1="14" y1="7" x2="14" y2="4" />
          <line x1="10" y1="20" x2="10" y2="17" />
          <line x1="14" y1="20" x2="14" y2="17" />
          <line x1="7" y1="10" x2="4" y2="10" />
          <line x1="7" y1="14" x2="4" y2="14" />
          <line x1="20" y1="10" x2="17" y2="10" />
          <line x1="20" y1="14" x2="17" y2="14" />
        </Glyph>
      )
  }
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

/** StateIcon marks a row that needs a decision or gives reassurance: the words
 *  stay available on hover and to screen readers, and the page behind the row
 *  spells them out. */
export function StateIcon({ state, label }: { state: 'warn' | 'danger' | 'ok' | 'unknown'; label: string }) {
  if (state === 'ok') {
    return (
      <Glyph label={label} tone="ok">
        <circle cx="12" cy="12" r="9" />
        <polyline points="8 12.5 11 15.5 16 9.5" />
      </Glyph>
    )
  }
  if (state === 'unknown') {
    return (
      <Glyph label={label} tone="muted">
        <circle cx="12" cy="12" r="9" />
        <line x1="8.5" y1="12" x2="15.5" y2="12" />
      </Glyph>
    )
  }
  return (
    <Glyph label={label} tone={state}>
      <path d="M12 3.5 22 20.5 H2 Z" />
      <line x1="12" y1="10" x2="12" y2="14.5" />
      <line x1="12" y1="17.2" x2="12" y2="17.3" />
    </Glyph>
  )
}
