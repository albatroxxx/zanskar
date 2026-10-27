import { expect, test } from '@playwright/test'

test.describe('Administering from the console', () => {
  test('adds a credential, whose secret is sealed and never shown again, and deletes it', async ({ page }) => {
    // A name of its own per run: names are unique, and a repeat or a retry
    // must not trip over the last run's row.
    const name = `e2e-password-${Date.now()}`
    await page.goto('/admin/credentials')
    await expect(page.getByRole('row').filter({ hasText: 'fake-pw' })).toBeVisible()
    await page.getByRole('button', { name: 'Add credential' }).click()
    const form = page.getByRole('dialog', { name: 'Add credential' })
    await form.getByLabel('Name', { exact: true }).fill(name)
    await form.getByLabel('Username on the target').fill('svc')
    await form.getByLabel('Password').fill('the sealed secret 7')
    await form.getByRole('button', { name: 'Create' }).click()
    await expect(form).toBeHidden()
    const row = page.getByRole('row').filter({ hasText: name })
    await expect(row).toBeVisible()
    await expect(row.getByRole('button', { name: 'Secret stored' })).toBeVisible()
    await expect(page.locator('body')).not.toContainText('the sealed secret 7')
    const body = await page.evaluate(() => fetch('/api/v1/credentials').then((r) => r.text()))
    expect(body).not.toContain('the sealed secret 7')
    // The type is named; a password field never is.
    expect(body).not.toContain('"password":')
    expect(body).not.toContain('"private_key"')

    // Unassigned, so it may go; the seeded one is in use and its Delete is off.
    await expect(page.getByRole('row').filter({ hasText: 'fake-pw' }).getByRole('button', { name: 'Delete' })).toBeDisabled()
    await row.getByRole('button', { name: 'Delete' }).click()
    const confirm = page.getByRole('dialog', { name: `Delete ${name}?` })
    await expect(confirm).toContainText('The sealed secret is destroyed.')
    await confirm.getByRole('button', { name: 'Delete' }).click()
    await expect(confirm).toBeHidden()
    await expect(page.getByRole('row').filter({ hasText: name })).toHaveCount(0)
  })

  test('shows the seeded policy and refuses a policy that grants nothing', async ({ page }) => {
    await page.goto('/admin/policies')
    await expect(page.getByRole('row').filter({ hasText: 'ops-test-ssh' })).toBeVisible()
    await page.getByRole('button', { name: 'Add policy' }).click()
    const form = page.getByRole('dialog', { name: 'Add policy' })
    await form.getByLabel('Name', { exact: true }).fill('e2e-empty')
    await form.getByRole('button', { name: 'Create' }).click()
    await expect(form).toContainText('the main rule has protocols but no targets')
    await form.getByRole('button', { name: 'Cancel' }).click()
    await expect(page.getByRole('row').filter({ hasText: 'e2e-empty' })).toHaveCount(0)
  })

  test('the audit log holds the sign-in and the session, and verifies', async ({ page }) => {
    await page.goto('/admin/events')
    await expect(page.getByRole('heading', { name: 'Audit events' })).toBeVisible()
    await expect(page.getByRole('row').filter({ hasText: /signed in|login/i }).first()).toBeVisible()
    const verify = await page.evaluate(() => fetch('/api/v1/audit/verify').then((r) => r.json()))
    // The positive claim: a renamed field or a chain reporting problems must
    // fail here, which "broken is absent" never did.
    expect(verify.intact).toBe(true)
    expect(verify.problems ?? []).toEqual([])
    expect(verify.checked).toBeGreaterThan(0)
  })
})
