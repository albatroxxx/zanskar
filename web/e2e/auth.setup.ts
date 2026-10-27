import { test as setup } from '@playwright/test'
import { signIn, user } from './helpers'

// One sign-in per account for the whole run, saved as the browser's cookies:
// the sign-in endpoint is rate-limited per address (ten in a burst, twenty a
// minute), as it should be, and a suite that signed in for every test would
// trip it. Only signin.spec.ts exercises the sign-in form itself.
export const adminState = 'e2e/.auth/admin.json'
export const userState = 'e2e/.auth/user.json'

setup('sign in as the administrator', async ({ page }) => {
  await signIn(page)
  await page.context().storageState({ path: adminState })
})

setup('sign in as a plain user', async ({ page }) => {
  await signIn(page, user)
  await page.context().storageState({ path: userState })
})
