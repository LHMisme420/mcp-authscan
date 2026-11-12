import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { renderPageMetadata } from './shared/siteMetadata';

export default defineConfig({
  root: 'client',
  plugins: [
    react(),
    {
      name: 'public-page-metadata',
      // Vite's SPA fallback uses /index.html as path; preserve the requested
      // route for Preview as well as the production Express renderer.
      transformIndexHtml: (html, context) => renderPageMetadata(html, context.originalUrl || context.path),
    },
  ],
  server: { allowedHosts: true },
  build: { outDir: '../build/client', emptyOutDir: true },
});
