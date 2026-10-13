import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { FormModal } from './ui'

afterEach(cleanup)

function open(props: { err?: string; busy?: boolean; onSubmit?: () => void; onClose?: () => void } = {}) {
  render(
    <FormModal title="Add group" err={props.err ?? ''} busy={props.busy ?? false} submitLabel="Create" onSubmit={props.onSubmit ?? (() => {})} onClose={props.onClose ?? (() => {})}>
      <input aria-label="Name" />
    </FormModal>,
  )
}

// D14: the admin forms each wrote out this dialog, with the form, its error
// and its Cancel and submit buttons. FormModal is that dialog.
describe('FormModal', () => {
  it('sends the form on Enter without the browser leaving the page, and Cancel closes it', async () => {
    const onSubmit = vi.fn()
    const onClose = vi.fn()
    open({ onSubmit, onClose })
    const user = userEvent.setup()

    await user.type(screen.getByLabelText('Name'), 'ops{Enter}')
    expect(onSubmit).toHaveBeenCalledTimes(1)
    expect(fireEvent.submit(screen.getByLabelText('Name').closest('form')!)).toBe(false)

    await user.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('shows its error, and holds off only the submit button while busy', () => {
    open({ err: 'a group with that name exists', busy: true })

    expect(screen.getByRole('alert').textContent).toBe('a group with that name exists')
    expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Create' }).disabled).toBe(true)
    expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Cancel' }).disabled).toBe(false)
  })
})
