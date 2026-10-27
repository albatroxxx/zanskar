import { expect, test } from '@playwright/test'

// Role separation, in a real browser, as the second account hack/e2e.sh seeds:
// a user in the ops group reaches the access portal and the machine the
// policy grants, and is refused the console and its API by the gateway, not
// only hidden from them by the page. The admin half of the suite proves the
// console; this proves its door is shut to everyone else.
test.describe('A plain user', () => {
  test('lands in the access portal and sees the machine the policy grants', async ({ page }) => {
    await page.goto('/')
    await expect(page).not.toHaveURL(/\/(login|admin)/)
    await expect(page.getByRole('heading', { name: 'Targets' })).toBeVisible()
    await expect(page.getByRole('row').filter({ hasText: 'fake-1' })).toBeVisible()
    const me = await page.evaluate(() => fetch('/api/v1/auth/me').then((r) => r.json()))
    expect(me.user?.roles ?? me.roles).toEqual(['user'])
  })

  test('is kept out of the console, and the API refuses the console reads behind it', async ({ page }) => {
    for (const path of ['/admin', '/admin/credentials', '/admin/policies', '/admin/events', '/audit']) {
      await page.goto(path)
      // The console sends the user away; waiting for the path to change is
      // the assertion (a timeout here fails the test and names the path).
      await page.waitForURL((url) => url.pathname !== path, { timeout: 10_000 })
      await expect(page.locator('body')).not.toContainText(/Add credential|Add policy|Audit events/)
    }
    const codes = await page.evaluate(async () => {
      const paths = ['/api/v1/credentials', '/api/v1/access-policies', '/api/v1/users', '/api/v1/audit/events', '/api/v1/sessions', '/api/v1/admin/settings']
      return Promise.all(paths.map((p) => fetch(p).then((r) => [p, r.status] as const)))
    })
    for (const [path, status] of codes) {
      expect(status, `${path} as a user`).toBe(403)
    }
    // A write is refused the same way, before anything is checked about it.
    const write = await page.evaluate(() => fetch('/api/v1/credentials', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }).then((r) => r.status))
    expect(write).toBe(403)
  })
})
