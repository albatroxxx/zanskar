import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { afterEach, describe, expect, it } from 'vitest'
import { PickList } from './PickList'

afterEach(cleanup)

const options = Array.from({ length: 8 }, (_, i) => ({ id: `t${i}`, label: `web-${i}`, detail: i % 2 ? 'windows' : 'linux' }))

function Harness() {
  const [selected, setSelected] = useState<string[]>(['t5'])
  return (
    <PickList label="hosts" idPrefix="p" options={options} selected={selected}
      onToggle={(id) => setSelected((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]))}
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
    expect(screen.getByText('1 chosen')).toBeDefined()
    await user.click(screen.getByLabelText('web-2'))
    expect(screen.getByText('chips of t2')).toBeDefined()
    await user.type(screen.getByLabelText('Search hosts'), 'windows')
    expect(rows().every((id) => Number(id.slice(3)) % 2 === 1)).toBe(true)
    await user.clear(screen.getByLabelText('Search hosts'))
    await user.type(screen.getByLabelText('Search hosts'), 'nothing')
    expect(screen.getByText('No hosts match')).toBeDefined()
  })

  it('says when there is nothing to pick', () => {
    render(<PickList label="groups" idPrefix="g" options={[]} selected={[]} onToggle={() => {}} empty="No groups yet" />)
    expect(screen.getByText('No groups yet')).toBeDefined()
  })
})
