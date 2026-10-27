import { expect, test } from '@playwright/test'
import { user } from './helpers'

// An application behind the gateway (ADR 0033), end to end: the plain user
// opens it from the access portal, the gateway hands the browser to the
// application's own host with a one-time code, and the proxy forwards the
// request without the console cookie or any identity header. hack/e2e.sh
// seeded the application (the toy web app at the LAN address, label
// "notes") and a policy granting http on it; the browser resolves
// console.test and *.apps.test itself (host resolver rules), so no DNS is
// involved, which is also how an operator without DNS runs this. The
// gateway is the one hack/e2e.sh runs in managed TLS mode, the mode
// applications need: an https public address and a certificate for the
// apps domain.
test.describe('An application through the gateway', () => {
  test('opens at its own address with the request cleaned, and is listed as a session', async ({ page, context }) => {
    await page.goto('/login')
    await page.getByLabel('Username').fill(user.username)
    await page.getByLabel('Password').fill(user.password)
    await page.getByRole('button', { name: 'Sign in' }).click()
    await expect(page).not.toHaveURL(/\/login/)

    await page.getByRole('tab', { name: /Applications/ }).click()
    const row = page.getByRole('row').filter({ hasText: 'notes' })
    await expect(row).toBeVisible()
    await expect(row).toContainText('notes.apps.test')
    const open = row.getByRole('link', { name: 'Open' })
    await expect(open).toHaveAttribute('href', /^https:\/\/notes\.apps\.test:\d+\/$/)

    // The link opens a new tab; follow its address in this one so the
    // hand-off (application host → /launch → the gateway → the host with a
    // code → the application) runs in a page the test can watch.
    const url = (await open.getAttribute('href'))!
    await page.goto(url)
    await expect(page).toHaveURL(/^https:\/\/notes\.apps\.test:\d+\/$/)
    await expect(page.getByRole('heading', { name: 'fakehttp' })).toBeVisible()

    // What the application saw: its own host name, the address the person
    // used in X-Forwarded-Host, no gateway cookie, no identity header.
    const seen = JSON.parse((await page.locator('#seen').textContent()) ?? '{}') as { host: string; headers: Record<string, string[]> }
    const header = (name: string) => (seen.headers[name] ?? []).join(', ')
    expect(seen.host).not.toContain('apps.test')
    expect(header('X-Forwarded-Host')).toMatch(/^notes\.apps\.test:\d+$/)
    expect(header('X-Forwarded-Proto')).toBe('https')
    expect(header('Cookie')).not.toMatch(/zanskar/i)
    for (const name of ['X-Forwarded-User', 'X-Remote-User', 'X-Forwarded-Email', 'X-Forwarded-Groups']) {
      expect(header(name), `${name} must not reach the application`).toBe('')
    }
    // The application's own cookie is host-only on its address, and the
    // console cookie never travelled there.
    const cookies = await context.cookies(url)
    expect(cookies.some((c) => c.name.toLowerCase().includes('zanskar') && c.name.includes('session'))).toBe(false)

    // A redirect to the upstream's own origin comes back on the public address.
    await page.goto(url + 'redirect')
    await expect(page).toHaveURL(/^https:\/\/notes\.apps\.test:\d+\/landed$/)

    // The session is a session like any other, for the person and the audit trail.
    await page.goto('/sessions')
    const mine = page.getByRole('row').filter({ hasText: 'notes' }).first()
    await expect(mine).toBeVisible()
    await expect(mine).toContainText(/http/i)
  })
})
