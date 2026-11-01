import { useEffect } from 'react'

/** useTitle names the browser tab after what it shows, so that one of several
 *  open sessions or recordings can be told from the others (ADR 0038). The
 *  previous title comes back when the page goes; nothing is set while the
 *  text is not known yet. */
export function useTitle(text: string | undefined) {
  useEffect(() => {
    if (!text) return
    const before = document.title
    document.title = `${text} · Zanskar`
    return () => {
      document.title = before
    }
  }, [text])
}
