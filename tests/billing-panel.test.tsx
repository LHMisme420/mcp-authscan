import { test } from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { PlanAndUsage } from '../client/src/PlanFeatures';

for (const mode of ['disabled', 'test', 'live'] as const) {
  test(`workspace has no payment controls even with stale ${mode} metadata`, () => {
    const markup = renderToStaticMarkup(
      <PlanAndUsage account={{ actorUserId: 'synthetic-owner', role: 'owner', billing: { mode } }} />,
    );
    assert.match(markup, /No subscription required/);
    assert.doesNotMatch(markup, /Stripe|checkout|upgrade|\$99|billing-panel/i);
  });
}
