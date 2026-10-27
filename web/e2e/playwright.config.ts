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
    { name: 'chromium', testIgnore: /(signin|roles|apps)\.spec\.ts/, dependencies: ['setup'], use: { ...devices['Desktop Chrome'], storageState: 'e2e/.auth/admin.json' } },
    // The plain user's half: what the user role reaches and what it is refused.
    { name: 'user', testMatch: /roles\.spec\.ts/, dependencies: ['setup'], use: { ...devices['Desktop Chrome'], storageState: 'e2e/.auth/user.json' } },
    // Applications (ADR 0033) live at their own host names. The browser
    // resolves console.test and *.apps.test to the gateway itself, so the run
    // needs no DNS; the console cookie is for console.test here, so this
    // project signs in on its own rather than reusing the saved state.
    // The browser resolves console.test and *.apps.test to the gateway itself,
    // so the run needs no DNS; the gateway's console certificate is
    // self-signed and the apps certificate comes from a throwaway CA, so
    // certificate errors are ignored for this project alone; the console
    // cookie is for console.test here, so this project signs in on its own.
    {
      name: 'apps',
      testMatch: /apps\.spec\.ts/,
      use: {
        ...devices['Desktop Chrome'],
        baseURL: process.env.E2E_TLS_BASE_URL ?? 'https://console.test:18445',
        ignoreHTTPSErrors: true,
        launchOptions: { args: ['--host-resolver-rules=MAP console.test 127.0.0.1, MAP *.apps.test 127.0.0.1'] },
      },
    },
  ],
})
