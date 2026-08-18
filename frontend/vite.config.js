import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    watch: {
      usePolling: true,
    },
    hmr: true,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:5000',
        changeOrigin: true,
        secure: false,
        ws: true,
        timeout: 30000,          // 30s proxy timeout
        proxyTimeout: 30000,     // 30s backend response timeout
        configure: (proxy) => {
          // Use setTimeout to run after Vite attaches its own error handler
          setTimeout(() => {
            // Remove existing error listeners (Vite's default noisy logger)
            proxy.removeAllListeners('error');
            
            // Attach our own silent error handler
            proxy.on('error', (err, req, res) => {
              // Only log non-ECONNREFUSED errors
              if (err.code !== 'ECONNREFUSED') {
                console.warn(`[WSS Proxy] ${req.method} ${req.url} — ${err.message}`);
              }
              
              // Return a clean JSON error to the frontend instead of crashing
              if (res && !res.headersSent) {
                res.writeHead(503, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                  error: 'backend_unavailable',
                  message: 'Flask backend is not ready yet.'
                }));
              }
            });
          }, 0);

          proxy.on('proxyReq', (proxyReq, req) => {
            // Suppress the spammy proxy logs in the console
            // by leaving this empty or only logging specific things if needed.
          });
        }
      },
      '/uploads': {
        target: 'http://127.0.0.1:5000',
        changeOrigin: true,
        secure: false
      }
    }
  }
})
