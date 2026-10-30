import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { afterEach, describe, expect, it } from 'vitest'
import { PickList } from './PickList'

afterEach(cleanup)

const options = Array.from({ length: 8 }, (_, i) => ({ id: `t${i}`, label: `web-${i}`, detail: i % 2 ? 'windows' : 'linux' }))

function Harness({ many = false, opts = options }: { many?: boolean; opts?: typeof options }) {
  const [selected, setSelected] = useState<string[]>(['t5'])
  return (
    <PickList label="hosts" idPrefix="p" options={opts} selected={selected}
      onToggle={(id) => setSelected((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]))}
      onSelect={many ? (ids, on) => setSelected((s) => (on ? [...new Set([...s, ...ids])] : s.filter((x) => !ids.includes(x)))) : undefined}
      extra={(id) => <span>chips of {id}</span>} />
  )
}

describe('PickList', () => {
  it('puts the chosen first, searches by name or detail, and grows controls on a chosen row', async () => {
    render(<Harness />)
    const user = userEvent.setup()
    const rows = () => screen.getAllByRole('checkbox').map((c) => c.id)
    expect(rows()[0]).toBe('p-t5')
    expect(screen.getByText('chips of t5')).toBeDefined()
    expect(screen.getByText('1 of 8 chosen')).toBeDefined()
    await user.click(screen.getByLabelText('web-2'))
    expect(screen.getByText('chips of t2')).toBeDefined()
    await user.type(screen.getByLabelText('Search hosts'), 'windows')
    expect(rows().every((id) => Number(id.slice(3)) % 2 === 1)).toBe(true)
    await user.clear(screen.getByLabelText('Search hosts'))
    await user.type(screen.getByLabelText('Search hosts'), 'nothing')
    expect(screen.getByText('No hosts match')).toBeDefined()
  })

  // 2026-10-30: with 20 hosts each was ticked by hand.
  it('selects all the rows shown, clears them, and leaves inactive rows alone', async () => {
    const opts = options.map((o) => (o.id === 't7' ? { ...o, detail: 'linux · disabled', inactive: true } : o))
    render(<Harness many opts={opts} />)
    const user = userEvent.setup()
    const all = screen.getByLabelText('Select all hosts') as HTMLInputElement
    expect(all.checked).toBe(false)
    expect(all.indeterminate).toBe(true) // t5 is chosen
    await user.click(all)
    expect(screen.getByText('7 of 8 chosen')).toBeDefined()
    expect((screen.getByLabelText('web-7') as HTMLInputElement).checked).toBe(false)
    expect(all.checked).toBe(true)
    await user.click(all)
    expect(screen.queryByText(/chosen/)).toBeNull()

    // A search narrows it: only the matches are picked.
    await user.type(screen.getByLabelText('Search hosts'), 'windows')
    await user.click(screen.getByLabelText('Select all 3 shown'))
    await user.clear(screen.getByLabelText('Search hosts'))
    expect(screen.getByText('3 of 8 chosen')).toBeDefined()
    for (const id of ['web-1', 'web-3', 'web-5']) expect((screen.getByLabelText(id) as HTMLInputElement).checked).toBe(true)
    expect((screen.getByLabelText('web-2') as HTMLInputElement).checked).toBe(false)
  })

  it('offers no Select all without a way to pick many', () => {
    render(<Harness />)
    expect(screen.queryByLabelText(/Select all/)).toBeNull()
  })

  it('says when there is nothing to pick', () => {
    render(<PickList label="groups" idPrefix="g" options={[]} selected={[]} onToggle={() => {}} empty="No groups yet" />)
    expect(screen.getByText('No groups yet')).toBeDefined()
  })
})
