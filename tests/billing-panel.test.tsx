import test, { beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import BillingPanel from '../client/src/BillingPanel';
import { api } from '../client/src/api';

const originalApi = { ...api };
let dom: JSDOM;
let root: Root;
let status: any;
let portalCalls: number;
let checkoutCalls: number;
let refreshCalls: number;
const globals = globalThis as any;

beforeEach(() => {
  dom = new JSDOM('<div id="root"></div>', { url: 'https://vata.example.test/user-portal' });
  globals.window = dom.window;
  globals.document = dom.window.document;
  globals.IS_REACT_ACT_ENVIRONMENT = true;
  root = createRoot(document.getElementById('root')!);
  status = {
    plan: 'free', status: 'none', available: true, mode: 'test', testMode: true,
    checkoutReady: true, hasSubscription: false, cancelAtPeriodEnd: false, price: null,
  };
  portalCalls = checkoutCalls = refreshCalls = 0;
  api.getBillingStatus = async () => ({ ...status });
  api.refreshBilling = async () => { refreshCalls++; return {}; };
  api.createBillingPortal = async () => { portalCalls++; throw new Error('Synthetic portal failure'); };
  api.createCheckout = async () => { checkoutCalls++; throw new Error('Synthetic checkout failure'); };
});

afterEach(async () => {
  await act(async () => root.unmount());
  dom.window.close();
  Object.assign(api, originalApi);
  delete globals.window;
  delete globals.document;
  delete globals.IS_REACT_ACT_ENVIRONMENT;
});

async function render(isOwner = true, onRefresh?: () => void) {
  await act(async () => root.render(<BillingPanel isOwner={isOwner} onRefresh={onRefresh} />));
}
function text() { return document.body.textContent!; }
function button(label: string) {
  const result = [...document.querySelectorAll('button')].find(node => node.textContent === label);
  assert.ok(result, `Expected button: ${label}`);
  return result;
}
async function click(label: string) { await act(async () => button(label).click()); }

for (const [state, title] of [
  ['past_due', 'Subscription payment overdue'],
  ['unpaid', 'Subscription unpaid'],
  ['incomplete', 'Initial payment incomplete'],
]) {
  test(`${state}: owner sees recovery guidance, portal action, free history and no duplicate checkout`, async () => {
    Object.assign(status, { status: state, hasSubscription: true });
    await render();
    assert.ok(text().includes(title));
    assert.match(text(), /Unlimited manual scans and full scan history remain free/);
    assert.match(text(), /update your payment method/);
    assert.match(text(), /outstanding invoices/);
    assert.match(text(), /Do not start another checkout/);
    assert.doesNotMatch(text(), /Upgrade ·/);
    assert.equal(button('Fix payment in Stripe').disabled, false);
    await click('Fix payment in Stripe');
    assert.equal(portalCalls, 1);
    assert.equal(checkoutCalls, 0);
    assert.match(text(), /Unable to open the billing portal: Synthetic portal failure/);
    assert.equal(button('Fix payment in Stripe').disabled, false, 'portal failures can be retried');
    await click('Refresh billing');
    assert.equal(refreshCalls, 1);
    assert.doesNotMatch(text(), /You remain on Free/);
    assert.ok(text().includes(title));
  });

  test(`${state}: members see owner guidance and cannot manage payments`, async () => {
    Object.assign(status, { status: state, hasSubscription: true });
    await render(false);
    assert.match(text(), /Ask your workspace owner to update the payment method/);
    assert.match(text(), /Only the workspace owner can manage billing/);
    assert.equal(document.querySelectorAll('button').length, 0);
    assert.equal(portalCalls + checkoutCalls + refreshCalls, 0);
  });
}

test('refresh confirms actual recovery and removes payment-failure guidance', async () => {
  Object.assign(status, { status: 'past_due', hasSubscription: true });
  let changed = 0;
  await render(true, () => { changed++; });
  Object.assign(status, { plan: 'pro', status: 'active' });
  await click('Refresh billing');
  assert.equal(changed, 1);
  assert.match(text(), /Stripe confirms Pro is active/);
  assert.match(text(), /Pro plan/);
  assert.doesNotMatch(text(), /payment overdue|Fix payment|Upgrade ·/);
  assert.equal(button('Manage subscription').disabled, false);
});

for (const state of ['none', 'canceled', 'incomplete_expired']) {
  test(`${state}: a new or ended subscription permits checkout without renewal-failure messaging`, async () => {
    status.status = state;
    await render();
    assert.equal(button('Upgrade · $99 USD/month').disabled, false);
    assert.doesNotMatch(text(), /Fix payment in Stripe|Subscription payment overdue|Subscription unpaid/);
    assert.equal(button('Manage subscription').disabled, state === 'none');
    if (state === 'none') assert.match(text(), /No subscription yet/);
    if (state === 'canceled') assert.match(text(), /Subscription canceled/);
    if (state === 'incomplete_expired') assert.match(text(), /Initial payment expired/);
  });
}

test('scheduled cancellation remains active and is not presented as a failed renewal', async () => {
  Object.assign(status, { plan: 'pro', status: 'active', hasSubscription: true, cancelAtPeriodEnd: true });
  await render();
  assert.match(text(), /Cancellation scheduled/);
  assert.match(text(), /not a failed payment/);
  assert.doesNotMatch(text(), /Upgrade ·|Fix payment in Stripe/);
});

test('billing outage is not called a new Free workspace or a payment failure', async () => {
  Object.assign(status, { available: false, status: 'unavailable', checkoutReady: false });
  await render();
  assert.match(text(), /Billing status unavailable/);
  assert.match(text(), /Your scans and history remain available/);
  assert.doesNotMatch(text(), /No subscription yet|payment overdue|Upgrade ·/);
  assert.equal(button('Manage subscription').disabled, true);
  await click('Refresh billing');
  assert.match(text(), /Billing could not be verified/);
});

test('portal stays available while new live checkout is paused', async () => {
  Object.assign(status, { mode: 'live', testMode: false, status: 'unpaid', hasSubscription: true, checkoutReady: false });
  await render();
  assert.match(text(), /Live billing/);
  assert.equal(button('Fix payment in Stripe').disabled, false);
  assert.doesNotMatch(text(), /Upgrade ·/);
});

test('failed refresh preserves recovery state without claiming success', async () => {
  Object.assign(status, { status: 'incomplete', hasSubscription: true });
  await render();
  api.refreshBilling = async () => { throw new Error('Synthetic refresh failure'); };
  await click('Refresh billing');
  assert.match(text(), /Unable to refresh billing/);
  assert.match(text(), /Initial payment incomplete/);
  assert.doesNotMatch(text(), /Stripe confirms Pro is active/);
});

test('untrusted portal redirects are rejected', async () => {
  Object.assign(status, { status: 'past_due', hasSubscription: true });
  api.createBillingPortal = async () => ({ url: 'https://evil.invalid/portal' });
  await render();
  await click('Fix payment in Stripe');
  assert.match(text(), /not a trusted Stripe URL/);
});

test('unknown subscription states never offer checkout', async () => {
  Object.assign(status, { status: 'future_provider_state', hasSubscription: true });
  await render();
  assert.match(text(), /Existing subscription needs review/);
  assert.doesNotMatch(text(), /Upgrade ·/);
});
