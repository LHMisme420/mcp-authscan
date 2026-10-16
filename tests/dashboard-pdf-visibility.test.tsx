import assert from 'node:assert/strict';
import { test } from 'node:test';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { Router } from 'wouter';
import Dashboard from '../client/src/Dashboard';

test('signed-in dashboard shows the PDF control before account data is available', () => {
  const markup = renderToStaticMarkup(
    <Router ssrPath="/user-portal">
      <Dashboard
        account={null}
        setAccount={() => {}}
        userId="synthetic-report-user"
        onSignOut={() => {}}
      />
    </Router>,
  );
  assert.match(markup, /id="compliance-export-title"/);
  assert.match(markup, />Download PDF<\/button>/);
  assert.ok(markup.indexOf('compliance-export-title') < markup.indexOf('aria-label="Account loading"'));
  assert.ok(markup.indexOf('compliance-export-title') < markup.indexOf('aria-label="Security overview"'));
});
