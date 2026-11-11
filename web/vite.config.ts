import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"

// In dev, proxy /api to the Go API (aegisd) so the SPA and API share an origin.
// In prod the nginx container does the same proxying.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8080", changeOrigin: true },
      "/health": { target: "http://localhost:8080", changeOrigin: true },
    },
  },
})
