import { useState } from 'react'

/** Copies text to the clipboard and says so for a moment. */
export function CopyButton({ text, label = 'Copy', name }: { text: string; label?: string; name?: string }) {
  const [done, setDone] = useState(false)
  return (
    <button
      type="button"
      className="btn sm"
      aria-label={name ? `${label} ${name}` : undefined}
      onClick={() => {
        void navigator.clipboard?.writeText(text).then(() => {
          setDone(true)
          setTimeout(() => setDone(false), 1500)
        })
      }}
    >
      {done ? 'Copied' : label}
    </button>
  )
}
