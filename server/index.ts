import express from 'express';
import { createProxyMiddleware } from 'express-http-proxy';
import { startFlask } from './startup.js';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

startFlask();

app.use(express.json());
app.use('/api', createProxyMiddleware({
  target: 'http://127.0.0.1:5001',
  changeOrigin: false,
  pathRewrite: { '^/api': '/api' }
}));

app.use(express.static(path.join(__dirname, '../dist')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../dist/index.html'));
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`[Server] Running on port ${PORT}`);
});
