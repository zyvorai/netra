import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': { target: 'https://127.0.0.1:30870', secure: false, changeOrigin: true },
      '/healthz': { target: 'https://127.0.0.1:30870', secure: false, changeOrigin: true },
      '/livez': { target: 'https://127.0.0.1:30870', secure: false, changeOrigin: true },
    },
  },
})
