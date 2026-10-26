import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3001,
    proxy: {
      '/p1': {
        target: 'http://localhost:5101',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/p1/, '')
      },
      '/p2': {
        target: 'http://localhost:5102',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/p2/, '')
      },
      '/p3': {
        target: 'http://localhost:5103',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/p3/, '')
      }
    }
  }
})
