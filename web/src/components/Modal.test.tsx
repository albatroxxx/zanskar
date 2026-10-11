import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'
import { Modal } from './ui'

afterEach(cleanup)

function Page() {
  return (
    <>
      <button>Behind the dialog</button>
      <Modal title="Edit" onClose={() => {}}>
        <input aria-label="Name" />
        <button disabled>Disabled</button>
        <button>Save</button>
      </Modal>
    </>
  )
}

describe('Modal', () => {
  it('keeps Tab inside the dialog, both ways', async () => {
    render(<Page />)
    const user = userEvent.setup()
    const name = screen.getByLabelText('Name')
    const save = screen.getByRole('button', { name: 'Save' })
    name.focus()
    await user.tab()
    expect(document.activeElement).toBe(save)
    await user.tab() // past the last control: back to the first, not the page
    expect(document.activeElement).toBe(name)
    await user.tab({ shift: true }) // before the first control: to the last
    expect(document.activeElement).toBe(save)
  })

  it('brings focus back in from the dialog itself', async () => {
    render(<Page />)
    const user = userEvent.setup()
    screen.getByRole('dialog').focus()
    await user.tab()
    expect(document.activeElement).toBe(screen.getByLabelText('Name'))
  })
})
