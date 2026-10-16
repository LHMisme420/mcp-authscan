import { Router } from 'express';
import { requireOwner, TierError } from './tiers';
import { assertSandboxContext } from './stripeSandbox';
import { TestCheckoutService } from './testCheckoutService';

export function createTestCheckoutRoutes(service = new TestCheckoutService()) {
  const routes = Router();
  routes.use(['/test-checkout', '/checkout'], (req: any, _res, next) => {
    assertSandboxContext();
    requireOwner(req.account);
    if (req.authMethod !== 'session') throw new TierError(403, 'Use the owner’s signed-in browser for test checkout.');
    next();
  });
  routes.get('/test-checkout', async (_req, res) => res.json(await service.status()));
  const create = async (req: any, res: any) => {
    const requestId = req.body?.requestId;
    if (typeof requestId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(requestId)) {
      throw new TierError(400, 'A valid checkout request ID is required.');
    }
    res.status(201).json(await service.create(req.account, requestId));
  };
  routes.post('/test-checkout', create);
  routes.post('/checkout', create);
  routes.get('/test-checkout/:sessionId', async (req: any, res) => {
    if (!/^cs_test_[A-Za-z0-9]+$/.test(req.params.sessionId)) throw new TierError(400, 'Invalid test checkout ID.');
    res.json(await service.verify(req.account, req.params.sessionId));
  });
  return routes;
}
