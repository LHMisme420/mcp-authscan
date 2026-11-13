import type { RequestHandler } from 'express';
import { LEGACY_SITE_ORIGIN } from '../shared/siteMetadata';

/** Canonical origin for generated links, independent of the incoming Host. */
export function appOrigin() {
  const origin = process.env.NODE_ENV === 'production'
    ? process.env.PUBLIC_APP_URL
    : process.env.REPLIT_DEV_DOMAIN ? `https://${process.env.REPLIT_DEV_DOMAIN}` : process.env.PUBLIC_APP_URL;
  if (!origin) throw new Error('PUBLIC_APP_URL_MISSING');
  return new URL(origin).origin;
}

/** Exact deployment origins only: never derive trust from Host or forwarded headers. */
export function trustedAppOrigins() {
  const canonical = appOrigin();
  return process.env.NODE_ENV === 'production'
    ? [...new Set([canonical, LEGACY_SITE_ORIGIN])]
    : [canonical];
}

// Mounted after authentication. Missing Origin remains supported for non-browser
// API clients; supplied origins must match exactly, including scheme and port.
export const accountOriginGuard: RequestHandler = (req, res, next) => {
  if (req.method !== 'GET' &&
      req.get('origin') && !trustedAppOrigins().includes(req.get('origin')!)) {
    res.status(403).json({ error: 'Cross-origin account changes are not allowed.' });
    return;
  }
  next();
};
