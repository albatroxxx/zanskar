import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import { TerminalFiles } from './TerminalFiles'

afterEach(cleanup)

const listing = (path: string) => ({
  path,
  entries: path === '/home/bob'
    ? [
        { name: 'logs', path: '/home/bob/logs', dir: true, size: 0, mode: 'drwx', mtime: 0 },
        { name: 'notes.txt', path: '/home/bob/notes.txt', dir: false, size: 12, mode: '-rw-', mtime: 0 },
      ]
    : [],
})

// #122: entries were clickable <div>s, so a keyboard user could not open a
// folder or download a file. They are buttons now.
describe('TerminalFiles from the keyboard', () => {
  it('lists folders and files as buttons', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (p: string) => listing(p.includes('logs') ? '/home/bob/logs' : '/home/bob') as never)
    render(<TerminalFiles sessionId="s1" />)

    expect(await screen.findByRole('button', { name: /logs/ })).toBeDefined()
    expect(screen.getByRole('button', { name: /notes\.txt/ })).toBeDefined()
    expect(screen.getByRole('button', { name: '..' })).toBeDefined()
  })

  it('opens a folder with Tab and Enter', async () => {
    const get = vi.spyOn(api, 'get').mockImplementation(async (p: string) => listing(p.includes('logs') ? '/home/bob/logs' : '/home/bob') as never)
    render(<TerminalFiles sessionId="s1" />)
    const folder = await screen.findByRole('button', { name: /logs/ })

    const user = userEvent.setup()
    for (let i = 0; i < 10 && document.activeElement !== folder; i++) await user.tab()
    expect(document.activeElement).toBe(folder)
    await user.keyboard('{Enter}')

    expect(get).toHaveBeenLastCalledWith(expect.stringContaining('path=%2Fhome%2Fbob%2Flogs'))
  })
})
