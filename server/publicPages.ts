import { readFile } from 'node:fs/promises';
import path from 'node:path';
import type { Request, Response, NextFunction } from 'express';
import { renderPageMetadata } from '../shared/siteMetadata';

// Serve only public documents here. This does not bypass any /api auth or
// writer-readiness middleware, and never returns private workspace content.
export function publicDocuments(req: Request, res: Response, next: NextFunction) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return next();
  const verificationFile = 'google4d11d51a142646af.html';
  const nestedVerification = req.path === `/sitemap.xml/${verificationFile}`;
  if (req.path === '/robots.txt' || req.path === '/sitemap.xml' ||
      req.path === `/${verificationFile}` || nestedVerification) {
    const root = process.env.NODE_ENV === 'production' ? 'build/client' : 'client/public';
    const filename = nestedVerification ? verificationFile : req.path.slice(1);
    return res.sendFile(path.resolve(root, filename), error => {
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
