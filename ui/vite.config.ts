import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// Tauri expects a fixed port and does not need Vite's own error overlay.
export default defineConfig({
  plugins: [svelte()],
  clearScreen: false,
  server: { port: 5173, strictPort: true, host: '127.0.0.1' },
  build: {
    target: 'chrome120',
    // Everything is bundled: the app loads nothing from the network.
    assetsInlineLimit: 0,
    sourcemap: false,
  },
});
