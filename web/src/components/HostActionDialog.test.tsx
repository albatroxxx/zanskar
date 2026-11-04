import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'
import { FailedNotice } from './HostActionDialog'

afterEach(cleanup)

const log = [
  '{"time":"2026-11-04T05:45:10.24071685Z","level":"INFO","msg":"starting zanskar","version":"1.18.1","db_driver":"sqlite","key_version":1}',
  'error: listen tcp :80: bind: address already in use',
  'zanskar.service: Failed with result \'exit-code\'.',
].join('\n')

describe('FailedNotice', () => {
  // Live, 2026-11-04: a rolled-back install settings change put the
  // service's last lines, a kilobyte of JSON, in the message, which ran out
  // of the dialog. The cause is the message; the lines fold beneath it.
  it('says the cause, and keeps the service log folded until asked for', async () => {
    render(<FailedNotice progress={{ state: 'failed', step: 'back', message: 'The gateway did not start with the new settings: port 80 is in use.', log }} />)
    const alert = screen.getByRole('alert')
    expect(alert.textContent).toContain('port 80 is in use')
    const folded = alert.querySelector('details.alert-log') as HTMLDetailsElement
    expect(folded).not.toBeNull()
    expect(folded.open).toBe(false)
    expect(folded.querySelector('pre')?.textContent).toBe(log)
    await userEvent.setup().click(screen.getByText('Service log'))
    expect(folded.open).toBe(true)
  })

  it('has no log fold when there are no lines', () => {
    render(<FailedNotice progress={{ state: 'failed', step: 'install', message: 'The change was refused.' }} />)
    expect(screen.getByRole('alert').textContent).toBe('The change was refused.')
    expect(screen.queryByText('Service log')).toBeNull()
  })
})
