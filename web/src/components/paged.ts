import { useCallback, useLayoutEffect, useRef, useState } from 'react'
import { errorMessage } from '../api/client'
import type { Page } from '../api/types'

/**
 * usePaged keeps a list that is read a page at a time behind a Load more
 * button: the rows read so far (null until the first page arrives), the
 * cursor of the next page ('' once there is none), the error of a read that
 * failed, and whether a Load more is on its way.
 *
 * fetchPage reads one page, the first without a cursor. The page calls load
 * to read its list from the first page, on mount and whenever what
 * fetchPage reads changes, and more to read the next one.
 *
 * Each load or restart starts a generation, and a page that arrives for an
 * older one is dropped: a Load more still in flight when the filters changed
 * would otherwise append rows from the old filters to the new list, and a
 * slow first page for old filters could replace a quick one for new (B30).
 */
export function usePaged<T>(fetchPage: (cursor?: string) => Promise<Page<T>>) {
  const [items, setItems] = useState<T[] | null>(null)
  const [next, setNext] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const generation = useRef(0)
  // The fetchPage of the latest render, so a read uses what the page shows
  // now while load, restart and the effects that call them stay put.
  const latest = useRef(fetchPage)
  useLayoutEffect(() => {
    latest.current = fetchPage
  })

  const read = useCallback((cursor?: string) => {
    const mine = generation.current
    return latest
      .current(cursor)
      .then((p) => {
        if (generation.current !== mine) return
        setItems((cur) => (cursor && cur ? [...cur, ...p.items] : p.items))
        setNext(p.next_cursor ?? '')
      })
      .catch((e) => {
        if (generation.current === mine) setErr(errorMessage(e))
      })
  }, [])

  const load = useCallback(() => {
    generation.current++
    return read()
  }, [read])

  const more = () => {
    setBusy(true)
    void read(next).finally(() => setBusy(false))
  }

  // restart empties the list at once, for a page whose filters just
  // changed: its next load is still to come, and a page that lands before it
  // has nowhere to go.
  const restart = useCallback(() => {
    generation.current++
    setErr('')
    setItems(null)
  }, [])

  return { items, next, err, setErr, busy, load, more, restart }
}
