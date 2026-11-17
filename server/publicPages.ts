import { readFile } from 'node:fs/promises';
import path from 'node:path';
import type { Request, Response, NextFunction } from 'express';
import { renderPageMetadata } from '../shared/siteMetadata';

// Serve only public documents here. This does not bypass any /api auth or
// writer-readiness middleware, and never returns private workspace content.
export function publicDocuments(req: Request, res: Response, next: NextFunction) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return next();
  if (req.path === '/robots.txt' || req.path === '/sitemap.xml') {
    const root = process.env.NODE_ENV === 'production' ? 'build/client' : 'client/public';
    return res.sendFile(path.resolve(root, req.path.slice(1)), error => {
      if (error) next(error);
    });
  }
  return next();
}

export async function sendFrontendPage(req: Request, res: Response, next: NextFunction) {
  try {
    const templatePath = req.path === '/' ? 'build/server/home.html' : 'build/client/index.html';
    const html = await readFile(path.resolve(templatePath), 'utf8');
    res.setHeader('Cache-Control', 'no-cache');
    res.type('html').send(renderPageMetadata(html, req.path));
  } catch (error) {
    next(error);
  }
}
