import { cleanup, render } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { Tags } from '../components/ui'
import css from './base.css?raw'

afterEach(cleanup)

// 1.7.2 split a tag's key and value with a hairline under `.tag-k + .tag-v`,
// but the markup puts a screen-reader ": " between the two spans, so the rule
// never applied and env=prod read as "envprod". Every rule that styles the
// value must reach the value as Tags renders it.
describe('tag chips', () => {
  it('style the value through the markup Tags renders', () => {
    const selectors = [...css.matchAll(/([^{}]*\.tag-v[^{}]*)\{/g)].flatMap((m) => m[1].split(',').map((s) => s.replace(/\/\*[\s\S]*?\*\//g, '').trim()))
    expect(selectors.length).toBeGreaterThan(0)
    const { container } = render(<Tags tags={{ env: 'prod' }} />)
    const value = container.querySelector('.tag-v')
    expect(value).not.toBeNull()
    for (const s of selectors) expect(value!.matches(s), s).toBe(true)
  })

  it('show a key without a value as the key alone', () => {
    const { container } = render(<Tags tags={{ gpu: '' }} />)
    expect(container.querySelector('.tag-v')).toBeNull()
    expect(container.textContent).toBe('gpu')
  })
})
