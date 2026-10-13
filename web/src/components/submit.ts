import { useState } from 'react'
import { errorMessage } from '../api/client'

/**
 * useSubmit runs what a form or a dialog sends: busy while it runs, the
 * previous error cleared as it starts, and its failure kept as the error to
 * show, in errorMessage's words. A form that refuses a field before sending
 * says so with setErr; so may the function submit runs, since the error is
 * cleared before it starts.
 */
export function useSubmit() {
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const submit = async (fn: () => Promise<void>) => {
    setBusy(true)
    setErr('')
    try {
      await fn()
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }
  return { busy, err, setErr, submit }
}
