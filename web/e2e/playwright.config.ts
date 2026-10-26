import { defineConfig, devices } from '@playwright/test'

// Browser end-to-end tests. hack/e2e.sh stands the gateway up and runs these;
// E2E_BASE_URL is where it listens. One browser, serial, because the tests
// share one gateway and one account.
export default defineConfig({
  testDir: '.',
  testMatch: '*.spec.ts',
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  timeout: 30_000,
  expect: { timeout: 10_000 },
  reporter: process.env.CI ? [['list'], ['html', { open: 'never', outputFolder: 'playwright-report' }]] : 'list',
  outputDir: 'test-results',
  use: {
    baseURL: process.env.E2E_BASE_URL ?? 'http://127.0.0.1:18444',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    ...devices['Desktop Chrome'],
  },
  projects: [
    // Sign in once; every project but the sign-in tests starts from that state.
    { name: 'setup', testMatch: /auth\.setup\.ts/ },
    { name: 'signin', testMatch: /signin\.spec\.ts/, use: { ...devices['Desktop Chrome'] } },
    { name: 'chromium', testIgnore: /signin\.spec\.ts/, dependencies: ['setup'], use: { ...devices['Desktop Chrome'], storageState: 'e2e/.auth/admin.json' } },
  ],
})
