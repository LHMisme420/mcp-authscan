import express from 'express';
import { clerkMiddleware, getAuth } from '@clerk/express';
import { publishableKeyFromHost } from '@clerk/shared/keys';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { CLERK_PROXY_PATH, clerkProxyMiddleware, getClerkProxyHost } from './middlewares/clerkProxyMiddleware';
import { accountRoutes } from './accountRoutes';
import { appOrigin } from './appOrigin';
import { proxyScanner } from './flaskBridge';
import { accountFor } from './db';
import { tierRoutes, tokenAuthentication } from './tierRoutes';
import { TierError } from './tiers';
import { startApplication } from './startup';
import { billingRoutes } from './billingRoutes';
import { initializeBilling, requirePro } from './billing';
import { WebhookHandlers } from './webhookHandlers';
import { createTestCheckoutRoutes } from './testCheckoutRoutes';
import { createTestWebhookHandler } from './testWebhook';
import { billingMode } from './billingMode';

if (!process.env.CLERK_SECRET_KEY || !process.env.CLERK_PUBLISHABLE_KEY) {
  throw new Error('Secure sign-in is not configured.');
}
const app = express();
app.set('trust proxy', 1);
const start = await startApplication(app);
app.use(CLERK_PROXY_PATH, clerkProxyMiddleware());
app.use(['/api/test-checkout'], (_req, res, next) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(410).json({ error: 'Live payments are disabled. Test checkout is available in Preview only.' });
  }
  next();
});
app.use(['/api/checkout', '/api/billing', '/api/stripe'], (_req, res, next) => {
  if (billingMode() === 'disabled') return res.status(410).json({ error: 'Payments are not enabled.' });
  next();
});
// Both signed callbacks must receive original bytes before JSON parsing or Clerk.
app.post('/api/test-checkout/webhook',
  express.raw({ type: 'application/json', limit: '256kb' }), createTestWebhookHandler());
app.post('/api/stripe/webhook', express.raw({ type: 'application/json', limit: '1mb' }), async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const signature = req.get('stripe-signature');
  if (!signature) return res.status(400).json({ error: 'Missing webhook signature.' });
  try {
    await WebhookHandlers.processWebhook(req.body, signature);
    res.json({ received: true });
  } catch (error: any) {
    const invalid = error?.type === 'StripeSignatureVerificationError';
    res.status(invalid ? 400 : 503).json({ error: invalid ? 'Invalid webhook signature.' : 'Webhook processing is temporarily unavailable.' });
  }
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
app.use('/api', billingRoutes);
app.use('/api', createTestCheckoutRoutes());
app.use('/api', accountRoutes);
app.use('/api', tierRoutes);
app.post('/api/scan', async (req: any, res) => {
  await proxyScanner(req, res);
});
for (const route of ['/api/test', '/api/findings', '/api/threat-intelligence', '/api/reports/compliance', '/api/scans/mcp']) {
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
// Explicit operator opt-in permits setup inside the published environment,
// using its own live connector identity. Never run live setup in Preview.
// It runs after HTTP readiness; Stripe can deliver to the callback while setup
// waits for its signed catalog event. Failures never stop free scanning.
if (billingMode() === 'live' && process.env.VATA_PREPARE_LIVE_BILLING === '1') {
  const preparation = spawn(process.execPath,
    [path.resolve('build/server/prepare-live-billing.js'), '--confirm-live-catalog'],
    { stdio: 'inherit' });
  const stopPreparation = () => { preparation.kill('SIGTERM'); };
  process.once('exit', stopPreparation);
  let finalized = false;
  const finishPreparation = (success: boolean) => {
    if (finalized) return;
    finalized = true;
    process.off('exit', stopPreparation);
    if (!success) console.warn('Optional live billing setup did not finish. Review Stripe authorization and delivery; basic scans remain available.');
    void initializeBilling();
  };
  preparation.once('error', () => finishPreparation(false));
  preparation.once('exit', code => finishPreparation(code === 0));
} else {
  void initializeBilling();
}
