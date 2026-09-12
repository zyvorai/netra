import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': { target: 'http://127.0.0.1:8080', ws: true },
      '/healthz': 'http://127.0.0.1:8080',
    },
  },
  optimizeDeps: {
    include: ['@novnc/novnc/lib/rfb.js'],
  },
});
