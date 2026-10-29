import { resolve } from "node:path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// Wormway serves the dashboard under /ui/ on the Admin API port. During development the Vite
// server forwards API calls to a Wormway running with the default Admin address.
export default defineConfig({
  base: "/ui/",
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": resolve(import.meta.dirname, "src"),
    },
  },
  server: {
    proxy: {
      "/api": "http://127.0.0.1:9872",
    },
  },
})
