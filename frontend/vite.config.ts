import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// Dev-server proxy runs inside Docker; use the compose service name, not localhost.
const proxyTarget = process.env.VITE_PROXY_TARGET || 'http://backend:8080'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    host: '0.0.0.0',
    port: 3000,
    proxy: {
      '/auth': {
        target: proxyTarget,
        changeOrigin: true,
      },
      '/api': {
        target: proxyTarget,
        changeOrigin: true,
      },
    },
  },
})
