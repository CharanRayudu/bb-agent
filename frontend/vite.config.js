import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

function withScheme(value, scheme) {
  if (!value) return ''
  if (/^https?:\/\//.test(value) || /^wss?:\/\//.test(value)) return value
  return `${scheme}://${value}`
}

function originOnly(value) {
  try {
    return new URL(value).origin
  } catch {
    return value
  }
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const apiTarget = originOnly(withScheme(env.VITE_API_URL || 'localhost:8443', 'http'))
  const wsTarget = originOnly(
    withScheme(env.VITE_WS_URL || apiTarget.replace(/^http/, 'ws'), 'ws'),
  )

  return {
    plugins: [react()],
    server: {
      port: Number(env.VITE_PORT) || 3000,
      host: env.VITE_HOST || '0.0.0.0',
      proxy: {
        '/api': {
          target: apiTarget,
          changeOrigin: true,
        },
        '/ws': {
          target: wsTarget,
          ws: true,
        },
      },
    },
  }
})
