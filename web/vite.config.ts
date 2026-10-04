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
  },
})
