import { expect, test } from '@playwright/test'
import { admin, signIn } from './helpers'

test.describe('Signing in', () => {
  test('a wrong password is refused without saying which half was wrong', async ({ page }) => {
    await page.goto('/login')
    await page.getByLabel('Username').fill(admin.username)
    await page.getByLabel('Password').fill('not the passphrase')
    await page.getByRole('button', { name: 'Sign in' }).click()
    const alert = page.getByRole('alert').or(page.locator('.alert'))
    await expect(alert.first()).toBeVisible()
    await expect(alert.first()).not.toContainText(/password is wrong|no such user/i)
    await expect(page).toHaveURL(/\/login/)
  })

  test('an administrator lands in the console and can reach the access portal and sign out', async ({ page }) => {
    await signIn(page)
    await expect(page).toHaveURL(/\/admin$/)
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
    await page.goto('/')
    await expect(page.getByRole('heading', { name: 'Targets' })).toBeVisible()
    // The session cookie is the browser's only credential: a protected API
    // call made from the page works, and after signing out it does not.
    const before = await page.evaluate(() => fetch('/api/v1/auth/me').then((r) => r.status))
    expect(before).toBe(200)
    await page.getByRole('button', { name: /sign out/i }).click()
    await expect(page).toHaveURL(/\/login/)
    const after = await page.evaluate(() => fetch('/api/v1/auth/me').then((r) => r.status))
    expect(after).toBe(401)
  })

  test('a protected page opened signed out goes to sign in and comes back afterwards', async ({ page }) => {
    await page.goto('/admin/policies')
    await expect(page).toHaveURL(/\/login/)
    await page.getByLabel('Username').fill(admin.username)
    await page.getByLabel('Password').fill(admin.password)
    await page.getByRole('button', { name: 'Sign in' }).click()
    await expect(page).toHaveURL(/\/admin\/policies$/)
    await expect(page.getByRole('heading', { name: 'Access policies' })).toBeVisible()
  })
})
