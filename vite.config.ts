import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  root: 'client',
  plugins: [react()],
  server: { allowedHosts: true },
  build: { outDir: '../build/client', emptyOutDir: true },
});
