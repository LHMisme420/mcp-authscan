import { Router } from 'express';
import { scanUsage } from './tiers';
import { advancedBillingEnabled, billingStatus } from './billing';

export const accountRoutes = Router();
accountRoutes.get('/account', async (req: any, res) => {
  const billing = await billingStatus(req.account);
  const pro = !advancedBillingEnabled() || billing.plan === 'pro';
  res.json({
    organization: { id: -req.account.id, name: req.account.display_name },
    actorUserId: req.userId,
    role: req.account.role,
    usage: await scanUsage(req.account.id),
    billing,
    capabilities: { programmaticApi: pro, scheduling: pro, teamSeats: pro ? 5 : 1, historyDays: null },
  });
});
