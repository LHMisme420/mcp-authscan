import { randomUUID } from 'node:crypto';
import { pool } from '../server/db';
import { getTestStripeClient } from '../server/stripeSandbox';
import { TestCheckoutService } from '../server/testCheckoutService';

const service = new TestCheckoutService();
const account = { id: `sandbox_fixture_${randomUUID()}`, clerk_user_id: `sandbox_owner_${randomUUID()}` };
let sessionId: string | undefined;
try {
  const status = await service.status();
  if (status.mode !== 'test') throw new Error('Unexpected payment mode');
  const created = await service.create(account, randomUUID());
  sessionId = created.sessionId;
  const verified = await service.verify(account, sessionId);
  if (verified.confirmed || verified.accessChanged) throw new Error('An unpaid checkout was incorrectly confirmed.');
  console.log('Real Stripe TEST session created and independently verified as unpaid. No account access changed.');
} finally {
  if (sessionId) {
    const stripe = await getTestStripeClient();
    await stripe.checkout.sessions.expire(sessionId);
    console.log('Synthetic test checkout expired and cleaned up.');
  }
  await pool.end();
}
