import { useLocation } from 'react-router-dom'

/** The audit pages are mounted twice: under /admin for admins, inside their
 *  own console, and under /audit for review-only accounts (ADR 0006). Links
 *  between them stay in whichever tree the reader is in. */
export function useRecordingsPath(): string {
  const { pathname } = useLocation()
  return pathname.startsWith('/admin') ? '/admin/recordings' : '/audit/recordings'
}
