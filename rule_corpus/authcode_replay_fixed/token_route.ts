// FIXTURE (synthetic) — cortex-shape correct single-use. B2 must STAY SILENT.
// Redeem path present AND code invalidated via timestamp column: usedAt read-guard
// rejects replay, usedAt set to a Date before issuing.
import { prisma } from './prisma';
export async function POST(request) {
  const form = await request.formData();
  if (form.get('grant_type') !== 'authorization_code') return err('unsupported_grant_type');
  const code = form.get('code');
  const authCode = await prisma.oauthAuthorizationCode.findUnique({ where: { codeHash: sha256Hex(code) } });
  if (!authCode) return err('invalid_grant', 'code not found');
  if (authCode.usedAt) return err('invalid_grant', 'Authorization code already used');  // replay guard
  if (authCode.expiresAt < new Date()) return err('invalid_grant', 'expired');
  await prisma.oauthAuthorizationCode.update({ where: { id: authCode.id }, data: { usedAt: new Date() } });
  const issued = await issueToken({ userId: authCode.userId, scopes: authCode.scopes });
  return json({ access_token: issued.accessToken, token_type: 'Bearer' });
}
