import express from 'express';
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { ReplitConnectors } from '@replit/connectors-sdk';
import { assessmentPackages, emailPattern, validateInquiry, type AssessmentInquiry } from '../shared/assessmentInquiry';

type DeliveryConfig = { from: string; to: string };
type Message = DeliveryConfig & { replyTo: string; subject: string; text: string; idempotencyKey: string };
type Options = {
  config?: () => DeliveryConfig | null;
  send?: (message: Message) => Promise<string>;
  now?: () => number;
  origins?: () => string[];
};
const TTL = 30 * 60_000;
const sha = (value: string) => createHash('sha256').update(value).digest('hex');

export function inquiryConfig(): DeliveryConfig | null {
  const from = process.env.ASSESSMENT_EMAIL_FROM?.trim() ?? '';
  const to = process.env.ASSESSMENT_EMAIL_TO?.trim() ?? '';
  // Resend's default domain is for owner-inbox diagnostics, never a live sender.
  if (process.env.NODE_ENV === 'production' && from.toLowerCase().endsWith('@resend.dev')) return null;
  // Plain addresses only: caller data can never become an envelope recipient.
  return emailPattern.test(from) && emailPattern.test(to) ? { from, to } : null;
}

async function sendInquiry(message: Message): Promise<string> {
  const response = await new ReplitConnectors().proxy('resend', '/emails', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Idempotency-Key': message.idempotencyKey },
    body: JSON.stringify({
      from: `MCP AuthScan <${message.from}>`,
      to: [message.to],
      reply_to: message.replyTo,
      subject: message.subject,
      text: message.text,
    }),
    signal: AbortSignal.timeout(15_000),
  });
  const result = await response.json() as { id?: unknown };
  if (!response.ok || typeof result.id !== 'string' || !result.id) throw new Error('INQUIRY_DELIVERY_UNAVAILABLE');
  return result.id;
}

function allowedOrigins() {
  if (process.env.NODE_ENV === 'production') {
    try { return [new URL(process.env.PUBLIC_APP_URL ?? '').origin]; } catch { return []; }
  }
  const host = process.env.REPLIT_DEV_DOMAIN;
  // The development webview exposes its existing port-specific HTTPS URL.
  return host ? [`https://${host}`, `https://${host}:5000`] : ['http://localhost:5000', 'http://127.0.0.1:5000'];
}

function emailText(value: AssessmentInquiry) {
  return [
    'Assessment inquiry — not authorization to scan',
    `Contact: ${value.name}`, `Business email: ${value.email}`, `Company: ${value.company}`,
    `Website: ${value.website || 'Not supplied'}`, `Package: ${assessmentPackages[value.service]}`,
    `MCP servers: ${value.servers}`, `Timeframe: ${value.timeframe}`, '', 'Scope:', value.scope, '',
    'Do not begin testing without separately agreed scope and written authorization.',
  ].join('\n');
}

// Public marketing intake only. No imports from findings/account storage and no
// exemption from the existing /api authentication or writer-readiness gates.
export function assessmentInquiryRoutes(options: Options = {}) {
  const router = express.Router();
  const now = options.now ?? Date.now;
  const config = options.config ?? inquiryConfig;
  const send = options.send ?? sendInquiry;
  const origins = options.origins ?? allowedOrigins;
  const key = randomBytes(32);
  const sign = (payload: string) => createHmac('sha256', key).update(payload).digest('hex');
  const ipKey = (ip: string) => createHmac('sha256', key).update(ip).digest('hex');
  const rates = new Map<string, { count: number; until: number }>();
  const requests = new Map<string, { digest: string; until: number; promise: Promise<string> }>();
  let deliveryUnavailableUntil = 0;
  function limited(key: string, max: number, window: number) {
    for (const [id, rate] of rates) if (rate.until <= now()) rates.delete(id);
    const rate = rates.get(key);
    if (rate && rate.count >= max) return true;
    if (!rate && rates.size >= 10_000) return true;
    rates.set(key, { count: (rate?.count ?? 0) + 1, until: rate?.until ?? now() + window });
    return false;
  }
  function challenge(ip: string) {
    const payload = `${now()}.${randomBytes(16).toString('hex')}.${ip}`;
    return `${payload}.${sign(payload)}`;
  }
  function validChallenge(token: unknown, ip: string) {
    if (typeof token !== 'string' || token.length > 300) return false;
    const parts = token.split('.');
    if (parts.length !== 4 || parts[2] !== ip || !/^[a-f0-9]{64}$/.test(parts[3])) return false;
    const expected = sign(parts.slice(0, 3).join('.'));
    if (!timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(parts[3], 'hex'))) return false;
    const elapsed = now() - Number(parts[0]);
    return elapsed >= 2000 && elapsed <= TTL;
  }
  router.use((_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    next();
  });
  router.get('/assessment/status', (req, res) => {
    const ip = ipKey(req.ip ?? 'unknown');
    if (limited(`status:${ip}`, 40, 15 * 60_000)) {
      res.setHeader('Retry-After', '900');
      return res.status(429).json({ error: 'Too many requests. Please try again later.' });
    }
    const available = Boolean(config()) && deliveryUnavailableUntil <= now();
    return res.json({ available, testMode: Boolean(config()?.from.toLowerCase().endsWith('@resend.dev')), challenge: available ? challenge(ip) : null });
  });
  router.post('/assessment',
    (req, res, next) => {
      if (!origins().includes(req.get('origin') ?? '') || req.get('sec-fetch-site') === 'cross-site') {
        return res.status(403).json({ error: 'Please submit this form from this website.' });
      }
      if (!req.is('application/json')) return res.status(415).json({ error: 'Use a JSON form submission.' });
      next();
    },
    express.json({ limit: '12kb', strict: true }),
    async (req, res) => {
      const ip = ipKey(req.ip ?? 'unknown');
      if (limited(`post:${ip}`, 5, 15 * 60_000) || limited('global-post', 100, 60 * 60_000)) {
        res.setHeader('Retry-After', '900');
        return res.status(429).json({ error: 'Too many requests. Please try again later or use the email link.' });
      }
      const { value, errors } = validateInquiry(req.body);
      if (!value) return res.status(400).json({ error: 'Please correct the highlighted fields.', errors });
      if (req.body.websiteExtra !== '' || !validChallenge(req.body.challenge, ip)) {
        return res.status(400).json({ error: 'Form verification expired or failed. Refresh form verification, wait two seconds, then retry.' });
      }
      const delivery = config();
      if (!delivery || deliveryUnavailableUntil > now()) return res.status(503).json({ error: 'Inquiry delivery is unavailable. Please use the email link instead.' });
      for (const [id, entry] of requests) if (entry.until <= now()) requests.delete(id);
      const id = sha(req.body.challenge);
      const digest = sha(JSON.stringify(value));
      const previous = requests.get(id);
      if (previous && previous.digest !== digest) {
        return res.status(409).json({ error: 'This form verification was already used for different details. Refresh verification to send a new inquiry.' });
      }
      if (!previous && requests.size >= 1000) return res.status(429).json({ error: 'The inquiry service is busy. Please use the email link.' });
      const promise = previous?.promise ?? send({
        ...delivery, replyTo: value.email, subject: `${delivery.from.toLowerCase().endsWith('@resend.dev') ? '[TEST] ' : ''}MCP AuthScan assessment inquiry`,
        text: emailText(value), idempotencyKey: `assessment-${id}`,
      });
      if (!previous) requests.set(id, { digest, until: now() + TTL, promise });
      try {
        const reference = await promise;
        return res.status(202).json({
          accepted: true, reference,
          message: 'Your inquiry was accepted by our email service for delivery. This is not confirmation of inbox receipt or authorization to scan.',
        });
      } catch {
        // Retrying the same signed form reuses the provider idempotency key,
        // including after a network timeout with uncertain acceptance.
        requests.delete(id);
        deliveryUnavailableUntil = now() + 60_000;
        console.warn('Assessment inquiry delivery failed; no inquiry content was logged.');
        return res.status(503).json({ error: 'We could not confirm delivery acceptance. Please retry later with the same details, or use the email link.' });
      }
    },
  );
  router.use((error: { type?: string }, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    const tooLarge = error.type === 'entity.too.large';
    res.status(tooLarge ? 413 : 400).json({ error: tooLarge ? 'The inquiry is too large.' : 'The inquiry could not be read. Please check the form.' });
  });
  return router;
}
