import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../api/client'
import { type EmailServer, type NotificationChannel, NotificationsCard } from './NotificationsCard'

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
  config: { to: ['sec@example.com'] }, enabled: true, has_secret: false,
  status: { last_error: 'the mail server refused the account', last_error_at: '2026-11-03T10:00:00Z' },
}
const smtp: EmailServer = { host: 'smtp.example.com', port: 587, username: 'svc', from: 'gw@example.com', has_password: true }

function serve(items: NotificationChannel[], server: EmailServer | null = null) {
  return vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    if (path === '/admin/notifications/email-server') return server as never
    return { items, events: ['access_requested', 'access_decided', 'session_terminated', 'provider_failing', 'recording_lost', 'disk_full'] } as never
  })
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
    expect(body).not.toHaveProperty('smtp_host')
    expect(await screen.findByText('ab'.repeat(32))).toBeDefined()
  })

  it('sends a test and says what came back', async () => {
    serve([mail], smtp)
    vi.spyOn(api, 'post').mockRejectedValue(new ApiError(502, { code: 'delivery_failed', message: 'the mail server refused the account' }, '502'))
    render(<NotificationsCard />)
    const rows = (await screen.findAllByRole('row')).slice(1)
    await userEvent.setup().click(within(rows[0]).getByRole('button', { name: 'Test' }))
    expect(await screen.findByText('security: the mail server refused the account')).toBeDefined()
  })
})

// 2026-11-03, later: the mail server is set once, apart from the channels;
// an email channel names its recipients alone.
describe('Notifications, the email server', () => {
  it('says none is set, and sets one from its own form', async () => {
    serve([])
    const put = vi.spyOn(api, 'put').mockResolvedValue(smtp as never)
    render(<NotificationsCard />)
    expect(await screen.findByText(/None: email channels send nothing/)).toBeDefined()
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Set the email server' }))
    await user.type(screen.getByLabelText('Server'), 'smtp.example.com')
    await user.type(screen.getByLabelText('Port'), '587')
    await user.type(screen.getByLabelText('Username'), 'svc')
    await user.type(screen.getByLabelText('Password'), 'p4ss')
    await user.type(screen.getByLabelText('From'), 'gw@example.com')
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(put).toHaveBeenCalledWith('/admin/notifications/email-server', { host: 'smtp.example.com', port: 587, username: 'svc', password: 'p4ss', from: 'gw@example.com' }))
    expect(await screen.findByText('smtp.example.com:587')).toBeDefined()
  })

  it('shows the server set, tests it to an address, and removes it', async () => {
    serve([], smtp)
    const post = vi.spyOn(api, 'post').mockResolvedValue(undefined as never)
    const del = vi.spyOn(api, 'del').mockResolvedValue(undefined as never)
    render(<NotificationsCard />)
    const block = within(await screen.findByTestId('email-server'))
    expect(block.getByText('smtp.example.com:587')).toBeDefined()
    expect(block.getByText(/account svc/)).toBeDefined()
    const user = userEvent.setup()
    await user.click(block.getByRole('button', { name: 'Test' }))
    await user.type(screen.getByLabelText('To'), 'me@example.com')
    await user.click(screen.getByRole('button', { name: 'Send' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/admin/notifications/email-server/test', { to: 'me@example.com' }))
    expect(await screen.findByText('Email server: test sent to me@example.com.')).toBeDefined()
    await user.click(block.getByRole('button', { name: 'Remove' }))
    const dialog = screen.getByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: 'Remove' }))
    await waitFor(() => expect(del).toHaveBeenCalledWith('/admin/notifications/email-server'))
    expect(await screen.findByText(/None: email channels send nothing/)).toBeDefined()
  })

  it('asks an email channel for its recipients alone, and says when no server is set', async () => {
    serve([])
    const post = vi.spyOn(api, 'post').mockResolvedValue({ channel: mail } as never)
    render(<NotificationsCard />)
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Add channel' }))
    await user.type(screen.getByLabelText('Name'), 'security')
    await user.selectOptions(screen.getByLabelText('Kind'), 'email')
    expect(screen.queryByLabelText('SMTP server')).toBeNull()
    expect(screen.getByText(/No email server is set yet/)).toBeDefined()
    await user.type(screen.getByLabelText('To'), 'sec@example.com, ops@example.com')
    await user.click(screen.getByRole('button', { name: 'Add' }))
    const [, body] = post.mock.calls[0] as [string, Record<string, unknown>]
    expect(body).toMatchObject({ kind: 'email', to: ['sec@example.com', 'ops@example.com'] })
    expect(body).not.toHaveProperty('from')
  })
})
