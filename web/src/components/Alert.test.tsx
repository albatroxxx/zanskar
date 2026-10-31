import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Alert, RemoveButton } from './ui'

afterEach(cleanup)

// 2026-11-01: a notice ("Keycloak: 1 listed") stayed until the page was left.
// Every notice now has an x that dismisses it.
describe('Alert', () => {
  it('dismisses itself, and shows a different message again', async () => {
    const user = userEvent.setup()
    const { rerender } = render(<Alert tone="ok">Keycloak: 1 listed</Alert>)
    expect(screen.getByRole('status').textContent).toBe('Keycloak: 1 listed')
    await user.click(screen.getByRole('button', { name: 'Dismiss' }))
    expect(screen.queryByRole('status')).toBeNull()
    rerender(<Alert tone="ok">Keycloak: 1 listed</Alert>)
    expect(screen.queryByRole('status')).toBeNull()
    rerender(<Alert tone="ok">Keycloak: 2 listed · 1 created</Alert>)
    expect(screen.getByRole('status').textContent).toBe('Keycloak: 2 listed · 1 created')
  })

  it('hands the dismissal to the page that holds the notice, so the next one shows', async () => {
    const user = userEvent.setup()
    function Page() {
      const [notice, setNotice] = useState<string | null>('Synced')
      return (
        <>
          {notice && <Alert onDismiss={() => setNotice(null)}>{notice}</Alert>}
          <button type="button" onClick={() => setNotice('Synced')}>Sync now</button>
        </>
      )
    }
    render(<Page />)
    await user.click(screen.getByRole('button', { name: 'Dismiss' }))
    expect(screen.queryByRole('status')).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Sync now' }))
    expect(screen.getByRole('status').textContent).toBe('Synced')
  })

  it('dismisses a danger alert, and one holding more than words', async () => {
    const user = userEvent.setup()
    render(<Alert tone="danger">The request failed: <strong>403</strong></Alert>)
    expect(screen.getByRole('alert')).toBeDefined()
    await user.click(screen.getByRole('button', { name: 'Dismiss' }))
    expect(screen.queryByRole('alert')).toBeNull()
  })
})

describe('RemoveButton', () => {
  it('is named for what it removes and removes it', async () => {
    const onClick = vi.fn()
    render(<RemoveButton label="Remove tag env" onClick={onClick} />)
    await userEvent.setup().click(screen.getByRole('button', { name: 'Remove tag env' }))
    expect(onClick).toHaveBeenCalledOnce()
    expect(screen.getByRole('button', { name: 'Remove tag env' }).querySelector('svg')).not.toBeNull()
  })
})
