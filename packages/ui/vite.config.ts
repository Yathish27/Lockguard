import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The UI is served by the Safetyfirst server in production. In dev, Vite proxies /api to it.
export default defineConfig({
  plugins: [react()],
  build: { outDir: '../server/ui-dist', emptyOutDir: true },
  server: {
    proxy: {
      '/api': { target: 'http://127.0.0.1:4477', changeOrigin: false }
    }
  }
});
