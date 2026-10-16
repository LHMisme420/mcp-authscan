const assert = require('node:assert/strict');
const { harness, response, successResponse } = require('./dashboard_analytics.cjs');

const fixture = [{
    id: 1, server: 'test.com', server_name: 'test.com', vector_type: 'Test Rule',
    rule: 'Test Rule', severity: 'critical', description: 'Test finding',
    remediation: 'Test remediation', created_at: '2026-10-14 12:00:00', scan_id: null
}];

async function main() {
    for (const failedPath of ['/api/scans/mcp', '/api/reports/compliance', '/api/threat-intelligence']) {
        const { context, state } = harness();
        context.fetch = async url => url === failedPath
            ? response(failedPath.includes('scans') ? 404 : 503, {})
            : successResponse(url, fixture);
        await context.loadData();
        assert.equal(state.findings.length, 1, `${failedPath} must not block findings`);
        assert.equal(state.findings[0].description, 'Test finding');
        assert.match(state.error, /Unable to load/);
        assert.equal(state.consoleErrors.length, 1);
        assert(!JSON.stringify(state.consoleErrors).includes('test-token'));
        if (failedPath.endsWith('threat-intelligence')) {
            for (const key of ['critical', 'high', 'medium', 'low', 'total_findings']) {
                assert.equal(state.stats[key], 0);
            }
        }
    }
    {
        const { context, state } = harness();
        const completeRequests = [];
        context.fetch = url => url.endsWith('/api/findings')
            ? Promise.resolve(successResponse(url, fixture))
            : new Promise(resolve => { completeRequests.push(() => resolve(successResponse(url, fixture))); });
        const pendingLoad = context.loadData();
        await new Promise(resolve => setImmediate(resolve));
        assert.equal(state.findings.length, 1, 'findings must display before stats, compliance, and scan history finish');
        completeRequests.forEach(complete => complete());
        await pendingLoad;
        assert.equal(state.error, '');
    }
    for (const malformed of [{}, { findings: null }, { findings: [null] }]) {
        const { context, state } = harness();
        context.fetch = async url => url.endsWith('/api/findings')
            ? response(200, malformed) : successResponse(url);
        await context.loadData();
        assert.equal(state.findings, undefined, 'malformed responses must not masquerade as empty findings');
        assert.match(state.error, /expected a findings array of objects/);
    }
    {
        const { context, state } = harness();
        context.fetch = async url => url.endsWith('/api/findings')
            ? { status: 200, ok: true, json: async () => { throw new SyntaxError('Invalid JSON'); } }
            : successResponse(url);
        await context.loadData();
        assert.match(state.error, /Invalid JSON/);
        assert.equal(state.findings, undefined);
    }
    {
        const { context, events, state } = harness();
        context.fetch = async url => url.endsWith('/api/findings')
            ? response(401, {}) : successResponse(url, fixture);
        await context.loadData();
        assert.equal(context.token, null);
        assert.equal(state.findings, null);
        assert.equal(state.stats, null);
        assert.equal(state.signedIn, false);
        assert.deepEqual(events.map(event => event.name), ['session_expired']);
    }
    {
        const { context, state } = harness();
        context.fetch = async url => successResponse(url, []);
        await context.loadData();
        assert.equal(state.findings.length, 0);
        assert.equal(state.error, '');
        assert.equal(context.formatSeverity(null), 'MEDIUM');
        assert.equal(context.formatSeverity(undefined), 'MEDIUM');
        assert.equal(context.formatSeverity(''), 'MEDIUM');
        assert.equal(context.formatSeverity('  '), 'MEDIUM');
        assert.equal(context.formatSeverity(' critical '), 'CRITICAL');
    }
    console.log('Dashboard loading checks passed: independent endpoint updates, delayed requests, malformed JSON/data, auth expiry, empty results, and severity rendering.');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
