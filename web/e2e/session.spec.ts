import { expect, test } from '@playwright/test'

// The whole reason the gateway exists: a person signs in, picks a machine,
// gets a shell in the browser, leaves, and the session and its recording are
// there for review. hack/e2e.sh seeded the machine (fake-1, the fake SSH
// server) and a policy granting ssh to the signed-in account's group.
test.describe('An SSH session from the browser', () => {
  test('connects in a tab of its own, shows the shell, ends on request, and leaves a reviewable recording', async ({ page, context }) => {
    // The longest path in the suite: a fresh runner loads xterm and the
    // asciinema bundle cold. The budget is against a hang, not a stopwatch.
    test.slow()
    await page.goto('/')
    const row = page.getByRole('row').filter({ hasText: 'fake-1' })
    await expect(row).toBeVisible()
    // ADR 0038: the session opens in a tab of its own and the list stays,
    // so a person can run several sessions at once.
    const [tab] = await Promise.all([context.waitForEvent('page'), row.getByRole('link', { name: 'SSH, opens in a new tab' }).click()])

    await expect(tab).toHaveURL(/\/terminal$/)
    await expect(tab).toHaveTitle('fake-1 · SSH · Zanskar')
    await expect(tab.locator('.term-bar .name')).toHaveText('fake-1')
    await expect(tab.getByText('Recording', { exact: true })).toBeVisible()
    // The fake server greets every shell and echoes a command back in upper
    // case; xterm renders its rows into the DOM, so both can be read.
    await expect(tab.locator('.xterm')).toContainText('welcome to fakessh', { timeout: 15_000 })
    await expect(tab.getByText(/elapsed /)).toBeVisible()
    await tab.keyboard.type('hello e2e\n')
    await expect(tab.locator('.xterm')).toContainText('HELLO E2E')

    await tab.getByRole('button', { name: 'Disconnect' }).click()
    const ended = tab.getByRole('dialog', { name: 'Session ended' })
    await expect(ended).toBeVisible()
    await expect(tab.getByText('Ended · recording saved')).toBeVisible()
    await ended.getByRole('button', { name: 'Back to targets' }).click()
    await expect(tab).toHaveURL(/\/$/)
    await tab.close()
    await expect(page).toHaveURL(/\/$/)

    // The person sees their session, without the recording.
    await page.goto('/sessions')
    const mine = page.getByRole('row').filter({ hasText: 'fake-1' }).first()
    await expect(mine).toBeVisible()
    await expect(mine).toContainText(/ssh/i)
    await expect(page.getByText('Sessions are recorded.')).toBeVisible()

    // The administrator sees it with its recording, which opens in a tab of
    // its own, and plays.
    await page.goto('/admin/sessions')
    const theirs = page.getByRole('row').filter({ hasText: 'fake-1' }).first()
    await expect(theirs).toBeVisible()
    await expect(theirs).toContainText('root')
    const [rec] = await Promise.all([context.waitForEvent('page'), theirs.getByRole('link', { name: 'play, opens in a new tab' }).click()])
    await expect(rec).toHaveURL(/\/admin\/recordings\//)
    await expect(rec.getByRole('link', { name: 'Download recording' })).toBeVisible()
    // Playing is a deliberate act: the page says a view is audited, then
    // loads the player on Play, and the audit log holds the view.
    await expect(rec.getByText('Playing is logged with your name.')).toBeVisible()
    await rec.getByRole('button', { name: 'Play' }).click()
    await expect(rec.locator('.player-host .ap-wrapper, .player-host .ap-player').first()).toBeVisible({ timeout: 15_000 })
    const views = await rec.evaluate(() => fetch('/api/v1/audit/events?action=recording.view').then((r) => r.json()))
    expect(views.items.length).toBeGreaterThan(0)
  })

  test('a ticket cannot be replayed: the terminal page opened fresh goes back to the targets', async ({ page }) => {
    await page.goto('/terminal')
    await expect(page).toHaveURL(/\/$/)
    await expect(page.getByRole('heading', { name: 'Targets' })).toBeVisible()
  })

  // 2026-11-01: a person could run one session at a time, the session taking
  // the page the list was on.
  test('runs two sessions at once, each in its own tab', async ({ page, context }) => {
    test.slow()
    await page.goto('/')
    const ssh = page.getByRole('row').filter({ hasText: 'fake-1' }).getByRole('link', { name: 'SSH, opens in a new tab' })
    const [first] = await Promise.all([context.waitForEvent('page'), ssh.click()])
    const [second] = await Promise.all([context.waitForEvent('page'), ssh.click()])
    for (const [tab, word] of [[first, 'one'], [second, 'two']] as const) {
      await expect(tab.locator('.xterm')).toContainText('welcome to fakessh', { timeout: 15_000 })
      await tab.locator('.xterm').click()
      await tab.keyboard.type(`tab ${word}\n`)
      await expect(tab.locator('.xterm')).toContainText(`TAB ${word.toUpperCase()}`)
    }
    // Both are live at once, and the list never left.
    await expect(first.locator('.xterm')).not.toContainText('TAB TWO')
    await expect(page.getByRole('heading', { name: 'Targets' })).toBeVisible()
    for (const tab of [first, second]) await tab.getByRole('button', { name: 'Disconnect' }).click()
  })

  // A link to /connect that no page of ours just clicked (another site, a
  // pasted address) must not start a session by itself: it asks first.
  test('a session link opened from elsewhere asks before it connects', async ({ page }) => {
    await page.goto('/')
    const href = await page.getByRole('row').filter({ hasText: 'fake-1' }).getByRole('link', { name: 'SSH, opens in a new tab' }).getAttribute('href')
    expect(href).toMatch(/^\/connect\?target=[0-9a-f]{32}&protocol=ssh$/)
    await page.goto(href!)
    await expect(page.getByText('Connect to fake-1 over SSH?')).toBeVisible()
    await expect(page.getByRole('button', { name: 'Connect' })).toBeEnabled()
    await expect(page).toHaveURL(/\/connect\?/)
  })

  // 2026-11-01: a session's own tab ended on a second targets list. It
  // offers to connect again, in the same tab, without asking first.
  test('connects again from the end of a session, in the same tab', async ({ page, context }) => {
    test.slow()
    await page.goto('/')
    const ssh = page.getByRole('row').filter({ hasText: 'fake-1' }).getByRole('link', { name: 'SSH, opens in a new tab' })
    const [tab] = await Promise.all([context.waitForEvent('page'), ssh.click()])
    await expect(tab.locator('.xterm')).toContainText('welcome to fakessh', { timeout: 15_000 })
    await tab.getByRole('button', { name: 'Disconnect' }).click()
    const ended = tab.getByRole('dialog', { name: 'Session ended' })
    await ended.getByRole('button', { name: 'Connect again' }).click()
    await expect(ended).toBeHidden()
    await expect(tab).toHaveURL(/\/terminal$/)
    // a live shell, not the one that ended: it echoes what is typed
    await expect(tab.locator('.xterm')).toContainText('welcome to fakessh', { timeout: 15_000 })
    await tab.locator('.xterm').click()
    await tab.keyboard.type('again\n')
    await expect(tab.locator('.xterm')).toContainText('AGAIN')
    await tab.getByRole('button', { name: 'Disconnect' }).click()
    await tab.close()
  })
})
