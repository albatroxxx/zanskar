import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'
import { Field } from './ui'

afterEach(cleanup)

describe('Field', () => {
  it('names its input, and clicking the label focuses it', async () => {
    render(<Field label="Username"><input /></Field>)
    const box = screen.getByLabelText('Username')
    expect(box.tagName).toBe('INPUT')
    await userEvent.setup().click(screen.getByText('Username'))
    expect(document.activeElement).toBe(box)
  })

  it('keeps an id the page gave the control', () => {
    render(<Field label="Code"><input id="totp" /></Field>)
    expect(screen.getByLabelText('Code').id).toBe('totp')
  })

  it('reads the hint as the description', () => {
    render(<Field label="New password" hint="At least 12 characters"><input type="password" /></Field>)
    expect(screen.getByLabelText('New password').getAttribute('aria-describedby')).toBe(screen.getByText('At least 12 characters').id)
  })

  it('names a select and a textarea', () => {
    render(
      <>
        <Field label="Protocol"><select><option>ssh</option></select></Field>
        <Field label="Banner"><textarea /></Field>
      </>,
    )
    expect(screen.getByLabelText('Protocol').tagName).toBe('SELECT')
    expect(screen.getByLabelText('Banner').tagName).toBe('TEXTAREA')
  })

  it('names a group of checkboxes as a group', () => {
    render(
      <Field label="Roles" hint="Pick at least one">
        <div className="actions">
          <label><input type="checkbox" /> admin</label>
          <label><input type="checkbox" /> user</label>
        </div>
      </Field>,
    )
    const group = screen.getByRole('group', { name: 'Roles' })
    expect(group.getAttribute('aria-describedby')).toBe(screen.getByText('Pick at least one').id)
    expect(screen.getByLabelText('admin')).toBeDefined()
  })
})
