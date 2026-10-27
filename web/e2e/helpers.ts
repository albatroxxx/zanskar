import { expect, type Page } from '@playwright/test'

export const admin = { username: 'root', password: 'bootstrap passphrase 2026' }
/** A plain user in the ops group, seeded by hack/e2e.sh: reaches the access portal and nothing of the console. */
export const user = { username: 'alice', password: 'alice passphrase 2026' }

/** signIn fills the sign-in form as a person would and waits for a portal. */
export async function signIn(page: Page, who = admin) {
  await page.goto('/login')
  await page.getByLabel('Username').fill(who.username)
  await page.getByLabel('Password').fill(who.password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page).not.toHaveURL(/\/login/)
}
