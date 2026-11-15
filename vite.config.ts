import { defineConfig } from 'vite';

// Served from https://<user>.github.io/dfir-range/ on GitHub Pages.
// Relative base keeps the build working from any path, including a local static server.
export default defineConfig({
  base: './',
  build: {
    outDir: 'dist',
    assetsInlineLimit: 0,
    sourcemap: false,
  },
});
