import express from 'express';
import { clerkMiddleware, getAuth } from '@clerk/express';
import { publishableKeyFromHost } from '@clerk/shared/keys';
import path from 'node:path';
import { CLERK_PROXY_PATH, clerkProxyMiddleware, getClerkProxyHost } from './middlewares/clerkProxyMiddleware';
import { accountRoutes } from './accountRoutes';
import { appOrigin } from './appOrigin';
import { proxyScanner } from './flaskBridge';
import { accountFor } from './db';
import { tierRoutes, tokenAuthentication } from './tierRoutes';
import { TierError } from './tiers';
import { startApplication } from './startup';
import { requirePro } from './billing';

if (!process.env.CLERK_SECRET_KEY || !process.env.CLERK_PUBLISHABLE_KEY) {
  throw new Error('Secure sign-in is not configured.');
}
const app = express();
app.set('trust proxy', 1);
const start = await startApplication(app);
app.use(CLERK_PROXY_PATH, clerkProxyMiddleware());
// Retired payment URLs remain explicit tombstones, including old webhook URLs.
// No environment variable can reactivate payments in this release.
app.use(['/api/test-checkout', '/api/checkout', '/api/billing', '/api/stripe'], (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.status(410).json({ error: 'Payments are not enabled.' });
});
app.use(express.json({ limit: '32kb' }));
app.use(express.urlencoded({ extended: true }));
app.use('/api', (_req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });
app.use(tokenAuthentication);
const clerkAuth = clerkMiddleware((req) => ({
    publishableKey: publishableKeyFromHost(
      getClerkProxyHost(req) ?? "",
      process.env.CLERK_PUBLISHABLE_KEY,
    ),
  }));
app.use((req: any, res, next) => req.authMethod === 'api_key' ? next() : clerkAuth(req, res, next));
app.use('/auth', (_req, res) => res.status(410).json({ error: 'Use secure account sign-in.' }));
app.use('/api', (req: any, res, next) => {
  const auth = req.authMethod === 'api_key' ? null : getAuth(req);
  const userId = auth?.userId;
  if (!userId && req.authMethod !== 'api_key') return res.status(401).json({ error: 'Unauthorized' });
  if (userId) req.userId = userId;
  req.authMethod ??= req.get('authorization')?.startsWith('Bearer ') ? 'bearer' : 'session';
  if (req.method !== 'GET' && req.get('origin') && req.get('origin') !== appOrigin()) {
    return res.status(403).json({ error: 'Cross-origin account changes are not allowed.' });
  }
  res.setHeader('Cache-Control', 'no-store');
  next();
});
app.use('/api', async (req: any, _res, next) => {
  req.account ??= await accountFor(req.userId);
  // A Clerk bearer token must not bypass the paid programmatic API gate.
  // Downgraded team members retain cleanup/status controls, not owner findings.
  if (req.authMethod === 'bearer' ||
      (req.account.role === 'member' && !/^\/(account$|team(?:\/|$)|billing(?:\/|$))/.test(req.path))) {
    await requirePro(req.account);
  }
  next();
});
app.use('/api', accountRoutes);
app.use('/api', tierRoutes);
app.post('/api/scan', async (req: any, res) => {
  await proxyScanner(req, res);
});
for (const route of ['/api/test', '/api/findings', '/api/threat-intelligence', '/api/reports/compliance', '/api/reports/pdf', '/api/scans/mcp']) {
  app.get(route, proxyScanner);
}
app.post('/api/scans/mcp', proxyScanner);
app.post('/api/findings', async (req: any, res) => {
  await proxyScanner(req, res);
});
app.use('/api', (_req, res) => res.status(404).json({ error: 'Unknown API endpoint.' }));
app.use((error: any, _req: any, res: any, _next: any) => {
  if (!(error instanceof TierError) || error.status >= 500) {
    console.error('Request failed:', error?.type || error?.name || 'Error');
  }
  res.status(error instanceof TierError ? error.status : 503).json({
    error: error instanceof TierError ? error.message : 'This service is temporarily unavailable. Please retry.',
  });
});

if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.resolve('build/client')));
  app.use((req, res, next) => req.method === 'GET' ? res.sendFile(path.resolve('build/client/index.html')) : next());
} else {
  const { createServer } = await import('vite');
  const vite = await createServer({ server: { middlewareMode: true }, appType: 'spa' });
  app.use(vite.middlewares);
}
await start();
