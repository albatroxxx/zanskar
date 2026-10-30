import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { afterEach, describe, expect, it } from 'vitest'
import { TagEditor } from './TagEditor'
import { maxTags, rowsToTags, tagRows, tagSuggestions, type TagRow } from './tags'

afterEach(cleanup)

// 2026-10-30 walkthrough: tags were typed as key=value lines. They are rows
// of a Key box and a Value box now, everywhere tags are given.

describe('rowsToTags', () => {
  it('reads the rows, trimmed, and drops blank ones', () => {
    expect(rowsToTags([{ key: ' env ', value: ' prod ' }, { key: '', value: '' }, { key: 'team', value: 'ops' }])).toEqual({ tags: { env: 'prod', team: 'ops' } })
  })

  it('keeps an "=" inside a value whole: nothing is split on it', () => {
    expect(rowsToTags([{ key: 'query', value: 'a=b' }]).tags).toEqual({ query: 'a=b' })
  })

  it('refuses a value without a key, a key given twice, and an over-long box', () => {
    expect(rowsToTags([{ key: '', value: 'prod' }]).error).toBe('tag 1: key is empty')
    expect(rowsToTags([{ key: 'env', value: 'a' }, { key: 'env ', value: 'b' }]).error).toBe('tag env is given twice')
    expect(rowsToTags([{ key: 'k', value: 'v'.repeat(65) }]).error).toBe('tag k: at most 64 characters')
    const many = Array.from({ length: maxTags + 1 }, (_, i) => ({ key: `k${i}`, value: 'v' }))
    expect(rowsToTags(many).error).toBe(`at most ${maxTags} tags`)
  })

  it('lets a target carry a key alone, but a policy match needs a value', () => {
    expect(rowsToTags([{ key: 'gpu', value: '' }])).toEqual({ tags: { gpu: '' } })
    expect(rowsToTags([{ key: 'gpu', value: '' }], { valueRequired: true }).error).toBe('tag gpu: value is empty')
  })

  it('keeps a key that is an object property, rather than setting a prototype', () => {
    const { tags } = rowsToTags([{ key: '__proto__', value: 'x' }, { key: 'constructor', value: 'y' }])
    expect(Object.keys(tags)).toEqual(['__proto__', 'constructor'])
    expect(JSON.stringify(tags)).toBe('{"__proto__":"x","constructor":"y"}')
  })

  it('round-trips through the rows', () => {
    const tags = { env: 'prod', team: 'ops' }
    expect(rowsToTags(tagRows(tags)).tags).toEqual(tags)
  })
})

describe('tagSuggestions', () => {
  it('gathers the keys in use and the values under each, sorted and once each', () => {
    expect(tagSuggestions([{ tags: { env: 'prod' } }, { tags: { env: 'dev', gpu: '' } }, { tags: { env: 'prod' } }, {}])).toEqual({ env: ['dev', 'prod'], gpu: [] })
  })
})

function Harness({ initial = [], suggest }: { initial?: TagRow[]; suggest?: Record<string, string[]> }) {
  const [rows, setRows] = useState(initial)
  return (
    <>
      <TagEditor idPrefix="t" rows={rows} onChange={setRows} suggest={suggest} />
      <output data-testid="out">{JSON.stringify(rowsToTags(rows).tags)}</output>
    </>
  )
}

describe('TagEditor', () => {
  it('adds a row of two boxes, takes a key and a value, and removes it', async () => {
    render(<Harness />)
    const user = userEvent.setup()
    expect(screen.queryByLabelText('Tag 1 key')).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Add tag' }))
    await user.type(screen.getByLabelText('Tag 1 key'), 'env')
    await user.type(screen.getByLabelText('Tag 1 value'), 'prod')
    expect(screen.getByTestId('out').textContent).toBe('{"env":"prod"}')
    await user.click(screen.getByRole('button', { name: 'Remove tag env' }))
    expect(screen.queryByLabelText('Tag 1 key')).toBeNull()
    expect(screen.getByTestId('out').textContent).toBe('{}')
  })

  it('removes the row asked for, leaving the others as they were', async () => {
    render(<Harness initial={[{ key: 'a', value: '1' }, { key: 'b', value: '2' }, { key: 'c', value: '3' }]} />)
    await userEvent.setup().click(screen.getByRole('button', { name: 'Remove tag b' }))
    expect(screen.getByTestId('out').textContent).toBe('{"a":"1","c":"3"}')
    expect((screen.getByLabelText('Tag 2 key') as HTMLInputElement).value).toBe('c')
  })

  it('stops offering another row at the limit', () => {
    render(<Harness initial={Array.from({ length: maxTags }, (_, i) => ({ key: `k${i}`, value: 'v' }))} />)
    expect((screen.getByRole('button', { name: 'Add tag' }) as HTMLButtonElement).disabled).toBe(true)
  })

  it('offers the keys in use, and the values seen under the chosen key', async () => {
    render(<Harness initial={[{ key: '', value: '' }]} suggest={{ env: ['dev', 'prod'], team: ['ops'] }} />)
    const key = screen.getByLabelText('Tag 1 key') as HTMLInputElement
    const keys = document.getElementById(key.getAttribute('list')!)!
    expect([...keys.querySelectorAll('option')].map((o) => o.value)).toEqual(['env', 'team'])
    expect(screen.getByLabelText('Tag 1 value').getAttribute('list')).toBeNull()
    await userEvent.setup().type(key, 'env')
    const value = screen.getByLabelText('Tag 1 value')
    const values = document.getElementById(value.getAttribute('list')!)!
    expect([...values.querySelectorAll('option')].map((o) => o.value)).toEqual(['dev', 'prod'])
  })
})
