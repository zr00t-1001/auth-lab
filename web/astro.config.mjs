import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';

// Single static page + a bundled client script. Tailwind v4 via the Vite plugin
// (CSS-first config lives in src/styles/global.css).
export default defineConfig({
  server: { port: 4321 },
  vite: { plugins: [tailwindcss()] },
});
