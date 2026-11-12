import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// The console talks to the SentinelAI API through /api, proxied to the local server
// (`python -m app.main serve`, 127.0.0.1:8000), so no CORS setting is needed on the API.
const target = process.env.SENTINEL_API_URL ?? 'http://127.0.0.1:8000';

export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    // the Security notes page imports ../docs/security-notes.md as raw text
    fs: { allow: ['.', '../docs'] },
    proxy: {
      '/api': { target, changeOrigin: false, rewrite: (path) => path.replace(/^\/api/, '') },
    },
  },
});
