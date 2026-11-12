import { readFile } from 'node:fs/promises';
import path from 'node:path';
import type { Request, Response, NextFunction } from 'express';
import { PUBLIC_SITE_ORIGIN, renderPageMetadata } from '../shared/siteMetadata';

// Serve only public documents here. This does not bypass any /api auth or
// writer-readiness middleware, and never returns private workspace content.
export function publicDocuments(req: Request, res: Response, next: NextFunction) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return next();
  if (req.path === '/robots.txt') {
    return res.type('text/plain').send(
      `User-agent: *\nAllow: /\nDisallow: /api/\nSitemap: ${PUBLIC_SITE_ORIGIN}/sitemap.xml\n`,
    );
  }
  if (req.path === '/sitemap.xml') {
    return res.type('application/xml').send(
      `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>${PUBLIC_SITE_ORIGIN}/</loc></url><url><loc>${PUBLIC_SITE_ORIGIN}/sample-assessment</loc></url></urlset>`,
    );
  }
  return next();
}

export async function sendFrontendPage(req: Request, res: Response, next: NextFunction) {
  try {
    const html = await readFile(path.resolve('build/client/index.html'), 'utf8');
    res.setHeader('Cache-Control', 'no-cache');
    res.type('html').send(renderPageMetadata(html, req.path));
  } catch (error) {
    next(error);
  }
}
