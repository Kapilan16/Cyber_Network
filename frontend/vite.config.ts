import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // Proxy /api requests to the backend during development
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/central-api': {
        target: 'http://localhost:8100',
        changeOrigin: true,
        rewrite: path => path.replace(/^\/central-api/, '/api/central'),
      },
    },
  },
})
