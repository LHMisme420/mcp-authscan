// FIXTURE (synthetic) — webrix-shape auth-code replay. B2 MUST fire.
// Redeem path present; code looked up and token issued, but code is NEVER
// invalidated (no delete, no used-flag, no usedAt). Models webrix-ai finding.
import { prisma } from './prisma';
export async function POST(request) {
  const form = await request.formData();
  if (form.get('grant_type') !== 'authorization_code') return err('unsupported_grant_type');
  const code = form.get('code');
  const authCode = await findAuthorizationCode(code);  // lookup/redeem
  if (!authCode) return err('invalid_grant', 'code not found');
  // BUG: no usedAt check, no invalidation anywhere — code is replayable.
  const issued = await issueToken({ userId: authCode.userId, scopes: authCode.scopes });
  return json({ access_token: issued.accessToken, token_type: 'Bearer' });
}
