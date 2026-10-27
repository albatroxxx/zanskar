import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import { TerminalFiles } from './TerminalFiles'

vi.mock('./session', () => ({ saveBlob: vi.fn() }))
import { saveBlob } from './session'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// A name with the characters a URL reads as its own syntax: a space, a hash
// (fragment), an ampersand (next parameter), a plus and a percent sign.
const odd = { name: 'report #1 & notes 100%+.txt', path: '/home/bob/report #1 & notes 100%+.txt', dir: false, size: 12, mode: '-rw-', mtime: 0 }
const listing = { path: '/home/bob', entries: [odd] }

// Review finding F1: dropping encodeURIComponent from the download URL passed
// both TerminalFiles tests, which never downloaded. A path with # or & then
// fetches the wrong file, or none.
describe('TerminalFiles, transfers', () => {
  it('downloads the exact path, encoded, and hands the blob to the browser under the file name', async () => {
    vi.spyOn(api, 'get').mockResolvedValue(listing as never)
    const blob = new Blob(['hello world!'])
    const download = vi.spyOn(api, 'download').mockResolvedValue(blob)
    render(<TerminalFiles sessionId="s 1" />)

    await userEvent.setup().click(await screen.findByRole('button', { name: /report #1/ }))

    expect(download).toHaveBeenCalledTimes(1)
    const url = download.mock.calls[0][0]
    expect(url).toBe(`/sessions/${encodeURIComponent('s 1')}/files/content?path=${encodeURIComponent(odd.path)}`)
    expect(url).not.toContain('#')
    expect(url).not.toContain('&')
    expect(url).not.toContain(' ')
    expect(saveBlob).toHaveBeenCalledWith(blob, odd.name)
    expect(await screen.findByText(/downloaded report #1 & notes 100%\+\.txt/)).toBeDefined()
  })

  it('uploads into the current folder under the file name, encoded, and lists again', async () => {
    const get = vi.spyOn(api, 'get').mockResolvedValue(listing as never)
    const upload = vi.spyOn(api, 'upload').mockResolvedValue({ bytes: 5 } as never)
    render(<TerminalFiles sessionId="s1" />)
    await screen.findByRole('button', { name: /report #1/ })

    // The input is hidden behind the Upload button, so the change is fired
    // on it the way the browser does after the picker closes.
    const input = document.querySelector('input[type=file]') as HTMLInputElement
    fireEvent.change(input, { target: { files: [new File(['12345'], 'q&a #2.bin', { type: 'application/octet-stream' })] } })

    expect(upload).toHaveBeenCalledTimes(1)
    const [url, file, type] = upload.mock.calls[0]
    expect(url).toBe(`/sessions/s1/files/content?path=${encodeURIComponent('/home/bob/q&a #2.bin')}`)
    expect((file as File).name).toBe('q&a #2.bin')
    expect(type).toBe('application/octet-stream')
    // The folder is listed again afterwards (the listing resets the status
    // line, so the "uploaded" message is not asserted here).
    await vi.waitFor(() => expect(get.mock.calls.length).toBeGreaterThan(1))
    expect(String(get.mock.calls.at(-1)?.[0])).toContain('path=%2Fhome%2Fbob')
  })

  it('reports a failed download in the status line', async () => {
    vi.spyOn(api, 'get').mockResolvedValue(listing as never)
    vi.spyOn(api, 'download').mockRejectedValue(new Error('permission denied'))
    render(<TerminalFiles sessionId="s1" />)
    await userEvent.setup().click(await screen.findByRole('button', { name: /report #1/ }))
    expect(await screen.findByText(/permission denied/)).toBeDefined()
    expect(saveBlob).not.toHaveBeenCalledWith(expect.anything(), odd.name)
  })
})
