const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const html = fs.readFileSync('dashboard.html', 'utf8');
const wrapper = html.match(/<script>\s*(function trackEvent[\s\S]*?)<\/script>/)[1];
const login = html.slice(html.indexOf('async function loginUser(org)'), html.indexOf('async function loadData()'));
const load = html.slice(html.indexOf('async function loadData()'), html.indexOf('if (!signedIn) return ('));

function harness(tracker) {
    const events = [];
    const state = { consoleErrors: [] };
    const context = {
        window: { umami: tracker === undefined ? { track: (name, data) => events.push({ name, data }) } : tracker },
        API_URL: '', token: 'test-token',
        hasTrackedDashboard: { current: false }, lastLoadError: { current: null },
        localStorage: { setItem() {}, removeItem() {} },
        setBusy: value => state.busy = value,
        setError: value => state.error = value,
        setSignedIn: value => state.signedIn = value,
        setStats: value => state.stats = value,
        setFindings: value => state.findings = value,
        setCompliance: value => state.compliance = value,
        setScans: value => state.scans = value,
        console: { error: (...args) => state.consoleErrors.push(args) },
    };
    vm.createContext(context);
    vm.runInContext(`${wrapper}\n${login}\n${load}`, context);
    return { context, events, state };
}

function response(status, data) {
    return { status, ok: status >= 200 && status < 300, json: async () => data };
}

function successResponse(url, findings = []) {
    if (url.endsWith('/api/findings')) return response(200, { findings });
    if (url.endsWith('/api/scans/mcp')) return response(200, { scans: [] });
    if (url.endsWith('/api/reports/compliance')) return response(200, { compliance_score: 100 });
    return response(200, { critical: 0, high: 0, total_findings: findings.length });
}

async function main() {
    for (const tracker of [
        null,
        { track() { throw new Error('tracker failed'); } },
        { track() { return Promise.reject(new Error('tracker failed')); } },
    ]) {
        const { context, state } = harness(tracker);
        context.fetch = async () => response(200, { access_token: 'test-token' });
        await context.loginUser('private-organization');
        assert.equal(state.signedIn, true);
        assert.equal(state.busy, false);
    }

    {
        const { context, events } = harness();
        context.fetch = async () => response(200, { access_token: 'test-token' });
        await context.loginUser('private-organization');
        assert.deepEqual(events.map(e => e.name), ['organization_access_started', 'organization_access_completed']);
        assert(!JSON.stringify(events).includes('private-organization'));
        assert(!JSON.stringify(events).includes('test-token'));
    }
    {
        const { context, events } = harness();
        context.fetch = async () => response(500, { error: 'private failure content' });
        await context.loginUser('private-organization');
        assert.equal(events.at(-1).name, 'organization_access_failed');
        assert.equal(events.at(-1).data.status, 500);
        assert(!JSON.stringify(events).includes('private failure content'));
    }
    {
        const { context, events } = harness();
        context.fetch = async url => successResponse(url, [{ description: 'private finding' }]);
        await context.loadData();
        await context.loadData();
        assert.deepEqual(events.map(e => e.name), ['dashboard_loaded']);
        assert.equal(events[0].data.has_findings, true);
        assert(!JSON.stringify(events).includes('private finding'));
    }
    {
        const { context, events } = harness();
        context.fetch = async () => response(503, {});
        await context.loadData();
        await context.loadData();
        assert.equal(events.length, 1);
        assert.equal(events[0].name, 'dashboard_load_failed');
        assert.equal(events[0].data.stage, 'threat_intelligence');
        context.fetch = async url => successResponse(url);
        await context.loadData();
        context.fetch = async () => response(503, {});
        await context.loadData();
        assert.equal(events.filter(e => e.name === 'dashboard_load_failed').length, 2);
    }
    {
        const { context, events } = harness();
        context.fetch = async url => url.includes('findings') ? response(500, {}) : successResponse(url);
        await context.loadData();
        assert.equal(events[0].data.stage, 'findings');
    }
    {
        const { context, events, state } = harness();
        context.fetch = async () => response(401, {});
        await context.loadData();
        await context.loadData();
        assert.deepEqual(events.map(e => e.name), ['session_expired']);
        assert.equal(state.signedIn, false);
    }
    {
        const { context, events } = harness();
        context.fetch = async () => { throw new Error('network unavailable'); };
        await context.loadData();
        assert.equal(events[0].data.status, 0);
    }
    console.log('Dashboard analytics checks passed: events, polling deduplication, privacy, and tracker failure isolation.');
}

module.exports = { harness, response, successResponse };
if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
