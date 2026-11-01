import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

// Development: Vite serves the SPA and proxies the API and WebSocket to a
// locally running `zanskar serve` (plain HTTP on loopback).
// Tests: `npm test` runs Vitest over src/**/*.test.ts(x) in a jsdom browser.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': { target: 'http://127.0.0.1:8443', changeOrigin: false },
      '/ws': { target: 'ws://127.0.0.1:8443', ws: true, changeOrigin: false },
    },
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.{ts,tsx}'],
    restoreMocks: true,
    setupFiles: ['src/test/setup.ts'],
    // Stylesheets stay empty in tests, except one imported as text (?raw),
    // which the colour test reads as written.
    css: { include: [/\.css\?raw$/] },
    // Coverage over every console source file, rendered or not: istanbul
    // instruments at transform time, so a page no test ever opens counts as
    // 0%, where the v8 provider reported it as 100% of nothing. The
    // thresholds are a floor just under the figures of 2026-10-27 (76.0% of
    // lines after the feature tests for the nine pages the review named
    // landed); raise them as tests land, never lower them.
    coverage: {
      provider: 'istanbul',
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/**/*.test.{ts,tsx}', 'src/**/*.d.ts', 'src/main.tsx', 'src/test/**'],
      reporter: ['text-summary', 'json-summary'],
      thresholds: { lines: 74, statements: 71, branches: 66, functions: 64 },
    },
  },
})
