import { createPublicKey, verify } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import type { Request, Response } from 'express';

export type PublishedKey = { key_id: string; alg: 'ed25519'; public_key: string };
export type Authenticity = {
  verdict: 'SIGNED BY' | 'NOT SIGNED' | 'SIGNATURE INVALID' | 'DIVERGENCE' | 'UNKNOWN KEY' | 'UNREADABLE';
  key_id: string | null;
  reason: string;
};
const keyId = /^[A-Za-z0-9._-]{1,64}$/;
const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');

function decode(value: unknown, size: number) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.length === size && bytes.toString('base64url') === value ? bytes : null;
}

export async function publishedKeys(): Promise<PublishedKey[]> {
  const root = process.env.NODE_ENV === 'production' ? 'build/client' : 'client/public';
  const document = JSON.parse(await readFile(path.resolve(root, 'keys.json'), 'utf8'));
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
  return document.keys;
}

export async function reportPublicKeys(_req: Request, res: Response) {
  res.setHeader('Cache-Control', 'no-store');
  try {
    res.json({ keys: await publishedKeys() });
  } catch {
    res.status(503).json({ error: 'Public verification keys are unavailable.' });
  }
}

export function verifyAuthenticity(
  signaturePresent: boolean | null, signature: unknown, bytes: Buffer | null, keys: PublishedKey[],
  divergence: string | null = null,
): Authenticity {
  const result = (verdict: Authenticity['verdict'], reason: string, key_id: string | null = null) =>
    ({ verdict, reason, key_id });
  if (signaturePresent === null) return result('UNREADABLE', 'The report could not be parsed.');
  if (!signaturePresent) return result('NOT SIGNED', 'No signature field is present.');
  const sig = signature as Record<string, unknown> | null;
  const id = sig && typeof sig.key_id === 'string' && keyId.test(sig.key_id) ? sig.key_id : null;
  if (!sig || typeof sig !== 'object' || Array.isArray(sig) || !id ||
      sig.alg !== 'ed25519' || Object.keys(sig).sort().join(',') !== 'alg,key_id,value') {
    return result('UNREADABLE', 'Signature must contain ed25519 alg, a short key_id and a base64url value.', id);
  }
  const detached = decode(sig.value, 64);
  if (!detached) return result('UNREADABLE', 'Signature value must encode exactly 64 bytes as unpadded base64url.', id);
  const key = keys.find(entry => entry.key_id === id);
  if (!key) return result('UNKNOWN KEY', 'This key_id is not published in /keys.json.', id);
  if (divergence && !bytes) return result('DIVERGENCE', `Signed-content component differs or cannot be reconstructed: ${divergence}.`, id);
  if (!bytes) return result('UNREADABLE', 'Canonical graded content could not be recomputed.', id);
  try {
    const raw = decode(key.public_key, 32);
    if (!raw || key.alg !== 'ed25519') throw new Error();
    const publicKey = createPublicKey({
      key: Buffer.concat([spkiPrefix, raw]), format: 'der', type: 'spki',
    });
    const valid = verify(null, bytes, publicKey, detached);
    if (!valid && divergence) return result('DIVERGENCE', `Signed-content component differs or cannot be reconstructed: ${divergence}.`, id);
    return valid
      ? result('SIGNED BY', 'Ed25519 signature verifies over the reference canonical signed content.', id)
      : result('SIGNATURE INVALID', 'Ed25519 verification failed over reference-reconstructed bytes. A signature alone cannot distinguish altered evidence/provenance from an invalid signature.', id);
  } catch {
    return result('UNREADABLE', 'Ed25519 verification is unavailable or the published key is invalid.', id);
  }
}
