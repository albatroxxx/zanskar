import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../api/client'
import { ConsoleCLI } from './ConsoleCLI'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  sessionStorage.clear()
})

const state = (over: object = {}) => ({ enabled: true, unlocked: true, mfa_enrolled: true, idle_minutes: 15, ...over })

async function openPanel() {
  const user = userEvent.setup()
  await user.click(await screen.findByRole('button', { name: 'Command line' }))
  return user
}

describe('ConsoleCLI', () => {
  it('hides the icon when the gateway has the command line off', async () => {
    const get = vi.spyOn(api, 'get').mockRejectedValue(new ApiError(404, { code: 'not_found', message: 'no such route' }, '404'))
    render(<ConsoleCLI />)
    await waitFor(() => expect(get).toHaveBeenCalled())
    expect(screen.queryByRole('button', { name: 'Command line' })).toBeNull()
  })

  it('asks for a code first, then runs a line that had to wait', async () => {
    vi.spyOn(api, 'get').mockResolvedValue(state({ unlocked: false }) as never)
    const post = vi.spyOn(api, 'post').mockImplementation(async (path: string) => {
      if (path === '/admin/cli/unlock') return { unlocked: true } as never
      return { status: 'ok', lines: [{ text: 'healthy', style: 'ok' }] } as never
    })
    render(<ConsoleCLI />)
    const user = await openPanel()

    expect(screen.getByRole('heading', { name: "Confirm it's you" })).toBeDefined()
    await user.type(screen.getByLabelText('Authenticator code'), '123456')
    await user.click(screen.getByRole('button', { name: 'Open command line' }))

    expect(post).toHaveBeenCalledWith('/admin/cli/unlock', { code: '123456' })
    await user.type(await screen.findByLabelText('zanskar>'), 'status{Enter}')
    expect(post).toHaveBeenLastCalledWith('/admin/cli', { line: 'status', confirm: '' })
    expect(await screen.findByText('healthy')).toBeDefined()
    // The prompt is coloured apart from the command, so match the whole line.
    expect(screen.getByText((_, el) => !!el?.classList.contains('cli-line') && el.textContent === 'zanskar> status')).toBeDefined()
  })

  it('shows a wrong code without ending the sign-in', async () => {
    vi.spyOn(api, 'get').mockResolvedValue(state({ unlocked: false }) as never)
    vi.spyOn(api, 'post').mockRejectedValue(new ApiError(422, { code: 'bad_code', message: 'that code is not right' }, '422'))
    render(<ConsoleCLI />)
    const user = await openPanel()
    await user.type(screen.getByLabelText('Authenticator code'), '000000{Enter}')
    expect((await screen.findByRole('alert')).textContent).toBe('that code is not right')
  })

  it('says when an account has no authenticator', async () => {
    vi.spyOn(api, 'get').mockResolvedValue(state({ unlocked: false, mfa_enrolled: false }) as never)
    render(<ConsoleCLI />)
    await openPanel()
    expect(screen.getByRole('heading', { name: 'An authenticator is needed' })).toBeDefined()
    expect(screen.queryByLabelText('Authenticator code')).toBeNull()
  })

  it('asks for the word before a destructive command, and sends it back with the line', async () => {
    vi.spyOn(api, 'get').mockResolvedValue(state() as never)
    const post = vi.spyOn(api, 'post').mockImplementation(async (_p: string, body?: unknown) => {
      const { confirm } = body as { confirm: string }
      if (!confirm) return { status: 'confirm', expect: 'alice', lines: [{ text: "This ends alice's SSH session.", style: 'warn' }] } as never
      return { status: 'ok', lines: [{ text: '✓ Terminated.', style: 'ok' }] } as never
    })
    render(<ConsoleCLI />)
    const user = await openPanel()
    await user.type(screen.getByLabelText('zanskar>'), 'session terminate 3f9a1c20{Enter}')
    await user.type(await screen.findByLabelText('Type alice to confirm:'), 'alice{Enter}')

    expect(post).toHaveBeenLastCalledWith('/admin/cli', { line: 'session terminate 3f9a1c20', confirm: 'alice' })
    expect(await screen.findByText('✓ Terminated.')).toBeDefined()
    expect(screen.getByLabelText('zanskar>')).toBeDefined()
  })

  it('cancels a confirmation with Escape, without asking the gateway', async () => {
    vi.spyOn(api, 'get').mockResolvedValue(state() as never)
    const post = vi.spyOn(api, 'post').mockResolvedValue({ status: 'confirm', expect: 'restart', lines: [] } as never)
    render(<ConsoleCLI />)
    const user = await openPanel()
    await user.type(screen.getByLabelText('zanskar>'), 'restart{Enter}')
    await user.type(await screen.findByLabelText('Type restart to confirm:'), '{Escape}')
    expect(await screen.findByText('Cancelled.')).toBeDefined()
    expect(post).toHaveBeenCalledTimes(1)
  })

  it('keeps clear and history in the browser, and recalls lines with the arrows', async () => {
    vi.spyOn(api, 'get').mockResolvedValue(state() as never)
    const post = vi.spyOn(api, 'post').mockResolvedValue({ status: 'ok', lines: [{ text: 'out' }] } as never)
    render(<ConsoleCLI />)
    const user = await openPanel()
    const prompt = screen.getByLabelText('zanskar>') as HTMLInputElement
    await user.type(prompt, 'users{Enter}')
    await user.type(screen.getByLabelText('zanskar>'), 'targets{Enter}')
    await user.type(screen.getByLabelText('zanskar>'), 'history{Enter}')
    expect(await screen.findByText('2 targets')).toBeDefined()
    await user.type(screen.getByLabelText('zanskar>'), 'clear{Enter}')
    expect(screen.queryByText('out')).toBeNull()
    expect(post).toHaveBeenCalledTimes(2)

    const again = screen.getByLabelText('zanskar>') as HTMLInputElement
    await user.type(again, '{ArrowUp}')
    expect(again.value).toBe('clear')
    await user.type(again, '{ArrowUp}{ArrowUp}')
    expect(again.value).toBe('targets')
    await user.type(again, '{ArrowDown}{ArrowDown}{ArrowDown}')
    expect(again.value).toBe('')
  })

  it('goes back to the code when the command line closed while idle', async () => {
    vi.spyOn(api, 'get').mockResolvedValue(state() as never)
    vi.spyOn(api, 'post').mockRejectedValue(new ApiError(403, { code: 'cli_locked', message: 'enter a code' }, '403'))
    render(<ConsoleCLI />)
    const user = await openPanel()
    await user.type(screen.getByLabelText('zanskar>'), 'sessions{Enter}')
    expect(await screen.findByLabelText('Authenticator code')).toBeDefined()
  })

  it('opens and closes with Ctrl+`, and Close clears the transcript', async () => {
    vi.spyOn(api, 'get').mockResolvedValue(state() as never)
    vi.spyOn(api, 'post').mockResolvedValue({ status: 'ok', lines: [{ text: 'kept until closed' }] } as never)
    render(<ConsoleCLI />)
    await screen.findByRole('button', { name: 'Command line' })
    const user = userEvent.setup()
    await user.keyboard('{Control>}`{/Control}')
    await user.type(await screen.findByLabelText('zanskar>'), 'version{Enter}')
    expect(await screen.findByText('kept until closed')).toBeDefined()

    await user.click(screen.getByRole('button', { name: 'Minimise' }))
    expect(screen.queryByRole('region', { name: 'Command line' })).toBeNull()
    await user.keyboard('{Control>}`{/Control}')
    expect(await screen.findByText('kept until closed')).toBeDefined()

    await user.click(screen.getByRole('button', { name: 'Close' }))
    await user.keyboard('{Control>}`{/Control}')
    await screen.findByLabelText('zanskar>')
    expect(screen.queryByText('kept until closed')).toBeNull()
  })
})
