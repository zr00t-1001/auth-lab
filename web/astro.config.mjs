import { defineConfig } from 'astro/config';

// Single static page + a bundled client script. No integrations, no SSR.
export default defineConfig({
  server: { port: 4321 },
});
