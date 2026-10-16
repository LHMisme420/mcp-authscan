/** Canonical origin for same-origin account changes, independent of billing. */
export function appOrigin() {
  const origin = process.env.NODE_ENV === 'production'
    ? process.env.PUBLIC_APP_URL
    : process.env.REPLIT_DEV_DOMAIN ? `https://${process.env.REPLIT_DEV_DOMAIN}` : process.env.PUBLIC_APP_URL;
  if (!origin) throw new Error('PUBLIC_APP_URL_MISSING');
  return new URL(origin).origin;
}
