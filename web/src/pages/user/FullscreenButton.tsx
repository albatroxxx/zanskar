/** Compact full-screen enter/exit toggle for the session bar. Shows the
 * familiar square "expand" corners, or the inward "contract" corners when the
 * session is already full screen. Label rides on aria-label/title. */
export function FullscreenButton({ isFull, onClick }: { isFull: boolean; onClick: () => void }) {
  const label = isFull ? 'Exit full screen' : 'Full screen'
  return (
    <button type="button" className="btn sm icon" onClick={onClick} aria-pressed={isFull} aria-label={label} title={label}>
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        {isFull ? (
          <path d="M8 3v3a2 2 0 0 1-2 2H3m18 0h-3a2 2 0 0 1-2-2V3M3 16h3a2 2 0 0 1 2 2v3m13-5h-3a2 2 0 0 0-2 2v3" />
        ) : (
          <path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3M3 16v3a2 2 0 0 0 2 2h3m13-5v3a2 2 0 0 1-2 2h-3" />
        )}
      </svg>
    </button>
  )
}
