import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Development: Vite serves the SPA and proxies the API and WebSocket to a
// locally running `zanskar serve` (plain HTTP on loopback).
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
})
