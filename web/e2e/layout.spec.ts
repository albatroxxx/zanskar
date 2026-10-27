import { expect, test } from '@playwright/test'

// Review U1: at phone width the list pages scrolled the whole page sideways
// and squeezed table columns to one character per line. The card scrolls
// inside itself now; the page never does. On failure the message names the
// elements that reach past the viewport.
test.describe('On a phone', () => {
  test.use({ viewport: { width: 390, height: 844 } })

  for (const path of ['/', '/admin/hosts', '/admin/users', '/admin/credentials']) {
    test(`${path} does not scroll sideways, its table card does`, async ({ page }) => {
      await page.goto(path)
      await expect(page.getByRole('table').first()).toBeVisible()
      const m = await page.evaluate(() => {
        const doc = document.documentElement
        const card = document.querySelector('.table-wrap')
        const wide = [...document.querySelectorAll<HTMLElement>('.main *')]
          .filter((el) => (el.scrollWidth > el.clientWidth + 1 || el.getBoundingClientRect().right > doc.clientWidth + 1) && !el.closest('table'))
          .slice(0, 10)
          .map((el) => `${el.tagName.toLowerCase()}.${String(el.className).split(' ').join('.')}:sw${el.scrollWidth}/cw${el.clientWidth}/r${Math.round(el.getBoundingClientRect().right)}/${getComputedStyle(el).position}`)
        const widths = ['html', 'body', '.shell', '.main', '.card.table-wrap'].map((sel) => {
          const el = sel === 'html' ? doc : document.querySelector<HTMLElement>(sel)
          return el ? `${sel}=${el.scrollWidth}/${Math.round(el.getBoundingClientRect().width)}/${getComputedStyle(el).overflowX}` : `${sel}=none`
        })
        const positioned = [...document.querySelectorAll<HTMLElement>('.table-wrap table *')]
          .filter((el) => getComputedStyle(el).position !== 'static')
          .slice(0, 6)
          .map((el) => `${el.tagName.toLowerCase()}.${String(el.className).split(' ').join('.')}/${getComputedStyle(el).position}`)
        const tabs = document.querySelector<HTMLElement>('.tabs')
        return {
          page: doc.scrollWidth, viewport: doc.clientWidth, card: card?.scrollWidth ?? 0, cardVisible: card?.clientWidth ?? 0, wide: [...wide, ...widths], positioned,
          tabs: tabs ? { scrollHeight: tabs.scrollHeight, clientHeight: tabs.clientHeight } : null,
        }
      })
      expect(m.page, `the page must not scroll sideways; past the edge: ${m.wide.join(', ') || 'nothing found'}; positioned in the table: ${m.positioned.join(', ') || 'none'}`).toBeLessThanOrEqual(m.viewport)
      expect(m.card, 'the table card scrolls inside itself').toBeGreaterThan(m.cardVisible)
      // A tab strip that scrolls sideways must not grow a vertical scrollbar
      // from the active tab's underline overlapping the strip's border.
      if (m.tabs) expect(m.tabs.scrollHeight, 'the tab strip must not scroll vertically').toBeLessThanOrEqual(m.tabs.clientHeight)
    })
  }
})
