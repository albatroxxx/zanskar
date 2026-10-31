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

// 2026-10-31, the live 1.9.0 console: after deleting an application from its
// detail dialog, the policy editor would not scroll. The delete dialog sits
// inside the detail dialog, a delete closes both at once, and the inner one,
// closing last, put back the `hidden` the outer one had set.
describe('Modal and the page behind it', () => {
  // A failing case must not leave the next one starting locked.
  afterEach(() => {
    cleanup()
    document.body.style.overflow = ''
  })

  function Nested({ outer, inner }: { outer: boolean; inner: boolean }) {
    return outer ? (
      <Modal title="Detail" onClose={() => {}}>
        {inner && (
          <Modal title="Delete?" onClose={() => {}}>
            <button>Delete</button>
          </Modal>
        )}
      </Modal>
    ) : null
  }

  it('lets the page scroll again after a delete from a detail dialog', () => {
    // The live sequence: the detail opens, then the delete dialog over it,
    // then a delete closes both in one render.
    const { rerender } = render(<Nested outer inner={false} />)
    rerender(<Nested outer inner />)
    expect(document.body.style.overflow).toBe('hidden')
    rerender(<Nested outer={false} inner={false} />)
    expect(document.body.style.overflow).toBe('')
  })

  it('lets the page scroll again when nested dialogs close together', () => {
    const { rerender } = render(<Nested outer inner />)
    expect(document.body.style.overflow).toBe('hidden')
    rerender(<Nested outer={false} inner={false} />)
    expect(document.body.style.overflow).toBe('')
  })

  it('lets the page scroll again when the inner dialog closes first, then the outer', () => {
    const { rerender } = render(<Nested outer inner />)
    rerender(<Nested outer inner={false} />)
    expect(document.body.style.overflow).toBe('hidden')
    rerender(<Nested outer={false} inner={false} />)
    expect(document.body.style.overflow).toBe('')
  })

  it('lets the page scroll again when sibling dialogs close out of order', () => {
    function Siblings({ a, b }: { a: boolean; b: boolean }) {
      return (
        <>
          {a && <Modal title="A" onClose={() => {}}>a</Modal>}
          {b && <Modal title="B" onClose={() => {}}>b</Modal>}
        </>
      )
    }
    const { rerender } = render(<Siblings a b={false} />)
    rerender(<Siblings a b />)
    rerender(<Siblings a={false} b />)
    expect(document.body.style.overflow).toBe('hidden')
    rerender(<Siblings a={false} b={false} />)
    expect(document.body.style.overflow).toBe('')
  })
})
