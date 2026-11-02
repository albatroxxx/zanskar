import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../api/client'
import { type NotificationChannel, NotificationsCard } from './NotificationsCard'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// 2026-11-03, idea 3 (ADR 0039): who hears of what, without the console open.
const slack: NotificationChannel = {
  id: 'n1', name: 'ops', kind: 'webhook', events: ['access_requested', 'provider_failing'],
  config: { webhook_host: 'hooks.slack.com' }, enabled: true, has_secret: true, status: { last_sent_at: '2026-11-03T10:00:00Z' },
}
const mail: NotificationChannel = {
  id: 'n2', name: 'security', kind: 'email', events: ['disk_full'],
  config: { smtp_host: 'smtp.example.com', from: 'gw@example.com', to: ['sec@example.com'] }, enabled: true, has_secret: false,
  status: { last_error: 'the mail server refused the account', last_error_at: '2026-11-03T10:00:00Z' },
}

function serve(items: NotificationChannel[]) {
  return vi.spyOn(api, 'get').mockResolvedValue({ items, events: ['access_requested', 'access_decided', 'session_terminated', 'provider_failing', 'recording_lost', 'disk_full'] } as never)
}

describe('Notifications', () => {
  it('lists each channel, where it goes, what it tells and how its last delivery went', async () => {
    serve([slack, mail])
    render(<NotificationsCard />)
    const rows = (await screen.findAllByRole('row')).slice(1)
    expect(rows[0].textContent).toContain('Webhook · hooks.slack.com')
    expect(rows[0].textContent).toContain('Access requested; Sign-in provider failing its sync')
    expect(rows[1].textContent).toContain('Email · sec@example.com')
    expect(within(rows[1]).getByText('the mail server refused the account').className).toBe('sync-error')
  })

  it('adds a webhook and shows its signing key once', async () => {
    serve([])
    const post = vi.spyOn(api, 'post').mockResolvedValue({ channel: slack, signing_key: 'ab'.repeat(32) } as never)
    render(<NotificationsCard />)
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Add channel' }))
    await user.type(screen.getByLabelText('Name'), 'ops')
    await user.type(screen.getByLabelText('Webhook URL'), 'https://hooks.slack.com/services/T/B/X')
    await user.click(screen.getByLabelText('Access approved, denied or revoked'))
    await user.click(screen.getByRole('button', { name: 'Add' }))
    const [path, body] = post.mock.calls[0] as [string, Record<string, unknown>]
    expect(path).toBe('/admin/notifications')
    expect(body).toMatchObject({ name: 'ops', kind: 'webhook', webhook_url: 'https://hooks.slack.com/services/T/B/X', events: ['access_requested', 'provider_failing', 'access_decided'] })
    expect(await screen.findByText('ab'.repeat(32))).toBeDefined()
  })

  it('sends a test and says what came back', async () => {
    serve([mail])
    vi.spyOn(api, 'post').mockRejectedValue(new ApiError(502, { code: 'delivery_failed', message: 'the mail server refused the account' }, '502'))
    render(<NotificationsCard />)
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Test' }))
    expect(await screen.findByText('security: the mail server refused the account')).toBeDefined()
  })
})
