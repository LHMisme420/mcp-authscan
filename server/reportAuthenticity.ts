import type { Request, Response } from 'express';
import registry from '../client/public/keys.json';

export type PublishedKey = { key_id: string; alg: 'ed25519'; public_key: string };
const keyId = /^[A-Za-z0-9._-]{1,64}$/;

function decode(value: unknown, size: number) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.length === size && bytes.toString('base64url') === value ? bytes : null;
}

export async function publishedKeys(): Promise<PublishedKey[]> {
  // esbuild embeds this public registry in the server artifact. Do not depend
  // on the process CWD or a separately deployed runtime file.
  const document: { keys: unknown } = registry;
  if (!Array.isArray(document.keys)) throw new Error('Invalid public key configuration');
  const ids = new Set<string>();
  for (const entry of document.keys) {
    if (!entry || typeof entry.key_id !== 'string' || !keyId.test(entry.key_id) ||
        entry.alg !== 'ed25519' || !decode(entry.public_key, 32) || ids.has(entry.key_id) ||
        Object.keys(entry).sort().join(',') !== 'alg,key_id,public_key') {
      throw new Error('Invalid public key configuration');
    }
    ids.add(entry.key_id);
  }
  return document.keys as PublishedKey[];
}

export async function reportPublicKeys(_req: Request, res: Response) {
  res.setHeader('Cache-Control', 'no-store');
  try {
    res.json({ keys: await publishedKeys() });
  } catch {
    res.status(503).json({ error: 'Public verification keys are unavailable.' });
  }
}

// Signature verdicts are decided only by the Python engine (mcp_authscan.verification),
// against the pinned key history; tests check that this registry equals its active keys.
