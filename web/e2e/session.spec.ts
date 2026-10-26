import { expect, test } from '@playwright/test'

// The whole reason the gateway exists: a person signs in, picks a machine,
// gets a shell in the browser, leaves, and the session and its recording are
// there for review. hack/e2e.sh seeded the machine (fake-1, the fake SSH
// server) and a policy granting ssh to the signed-in account's group.
test.describe('An SSH session from the browser', () => {
  test('connects, shows the shell, ends on request, and leaves a reviewable recording', async ({ page }) => {
    // The longest path in the suite: a fresh runner loads xterm and the
    // asciinema bundle cold. The budget is against a hang, not a stopwatch.
    test.slow()
    await page.goto('/')
    const row = page.getByRole('row').filter({ hasText: 'fake-1' })
    await expect(row).toBeVisible()
    await row.getByRole('button', { name: 'SSH' }).click()

    await expect(page).toHaveURL(/\/terminal$/)
    await expect(page.locator('.term-bar .name')).toHaveText('fake-1')
    await expect(page.getByText('Recording', { exact: true })).toBeVisible()
    // The fake server greets every shell and echoes a command back in upper
    // case; xterm renders its rows into the DOM, so both can be read.
    await expect(page.locator('.xterm')).toContainText('welcome to fakessh', { timeout: 15_000 })
    await expect(page.getByText(/elapsed /)).toBeVisible()
    await page.keyboard.type('hello e2e\n')
    await expect(page.locator('.xterm')).toContainText('HELLO E2E')

    await page.getByRole('button', { name: 'Disconnect' }).click()
    const ended = page.getByRole('dialog', { name: 'Session ended' })
    await expect(ended).toBeVisible()
    await expect(page.getByText('Ended · recording saved')).toBeVisible()
    await ended.getByRole('button', { name: 'Back to targets' }).click()
    await expect(page).toHaveURL(/\/$/)

    // The person sees their session, without the recording.
    await page.goto('/sessions')
    const mine = page.getByRole('row').filter({ hasText: 'fake-1' }).first()
    await expect(mine).toBeVisible()
    await expect(mine).toContainText(/ssh/i)
    await expect(page.getByText(/not shown here/)).toBeVisible()

    // The administrator sees it with its recording, and the recording plays.
    await page.goto('/admin/sessions')
    const theirs = page.getByRole('row').filter({ hasText: 'fake-1' }).first()
    await expect(theirs).toBeVisible()
    await expect(theirs).toContainText('root')
    await theirs.getByRole('link', { name: 'play' }).click()
    await expect(page).toHaveURL(/\/admin\/recordings\//)
    await expect(page.getByRole('link', { name: 'Download recording' })).toBeVisible()
    // Playing is a deliberate act: the page says a view is audited, then
    // loads the player on Play, and the audit log holds the view.
    await expect(page.getByText(/Pressing Play records a view/)).toBeVisible()
    await page.getByRole('button', { name: 'Play' }).click()
    await expect(page.locator('.player-host .ap-wrapper, .player-host .ap-player').first()).toBeVisible({ timeout: 15_000 })
    const views = await page.evaluate(() => fetch('/api/v1/audit/events?action=recording.view').then((r) => r.json()))
    expect(views.items.length).toBeGreaterThan(0)
  })

  test('a ticket cannot be replayed: the terminal page opened fresh goes back to the targets', async ({ page }) => {
    await page.goto('/terminal')
    await expect(page).toHaveURL(/\/$/)
    await expect(page.getByRole('heading', { name: 'Targets' })).toBeVisible()
  })
})
