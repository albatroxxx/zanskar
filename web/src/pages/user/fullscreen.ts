import { useCallback, useEffect, useState, type RefObject } from 'react'

// Safari (and older Chromium) expose the Fullscreen API under webkit- prefixes.
type FullscreenElement = HTMLElement & { webkitRequestFullscreen?: () => void }
type FullscreenDocument = Document & {
  webkitFullscreenElement?: Element | null
  webkitExitFullscreen?: () => void
}

function fsElement(): Element | null {
  const d = document as FullscreenDocument
  return d.fullscreenElement ?? d.webkitFullscreenElement ?? null
}

/**
 * useFullscreen drives the browser Fullscreen API on the given element and
 * tracks whether that element is the one currently fullscreen. The browser's
 * own Esc, the returned toggle, and exit all leave fullscreen. Because the
 * whole session container (bar included) is fullscreened, the toolbar stays
 * usable and the terminal/desktop resize to fill via their ResizeObservers.
 */
export function useFullscreen(ref: RefObject<HTMLElement | null>) {
  const [isFull, setIsFull] = useState(false)
  useEffect(() => {
    const onChange = () => setIsFull(ref.current !== null && fsElement() === ref.current)
    document.addEventListener('fullscreenchange', onChange)
    document.addEventListener('webkitfullscreenchange', onChange)
    return () => {
      document.removeEventListener('fullscreenchange', onChange)
      document.removeEventListener('webkitfullscreenchange', onChange)
    }
  }, [ref])

  const exit = useCallback(() => {
    const d = document as FullscreenDocument
    if (!fsElement()) return
    if (d.exitFullscreen) void d.exitFullscreen().catch(() => {})
    else d.webkitExitFullscreen?.()
  }, [])

  const toggle = useCallback(() => {
    const el = ref.current as FullscreenElement | null
    if (!el) return
    if (fsElement()) {
      exit()
      return
    }
    if (el.requestFullscreen) void el.requestFullscreen().catch(() => {})
    else el.webkitRequestFullscreen?.()
  }, [ref, exit])

  return { isFull, toggle, exit }
}
