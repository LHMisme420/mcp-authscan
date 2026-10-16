import { useCallback, useEffect, useRef, useState, type Dispatch, type FormEvent, type SetStateAction } from 'react';
import { Link, useLocation } from 'wouter';
import { api } from './api';
import { AcceptTeamInvite, ApiTokensPanel, PlanAndUsage, SchedulingPanel, TeamPanel } from './PlanFeatures';

type Account = {
  organization: { id: number | string; name: string };
  actorUserId: string;
  role?: 'owner' | 'member';
  billing?: { mode?: 'disabled' | 'test' | 'live' };
  usage?: { used: number; limit: 5 | null; remaining: number | null; month: string; resetsAt: string };
  capabilities?: { programmaticApi: boolean; scheduling: boolean; teamSeats: number; historyDays: 7 | null };
};
type Finding = {
  id: string | number;
  vector_type?: string;
  severity?: string | null;
  description?: string;
  remediation?: string;
  server?: string;
  server_name?: string;
  rule?: string;
};
type Scan = {
  id: string | number;
  target: string;
  status: string;
  findings_count: number;
  critical_count: number;
  high_count: number;
  compliance_score: number | null;
  error?: string | null;
  started_at?: string;
  completed_at?: string | null;
};
type ThreatStats = {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total_findings: number;
  week_trend: number;
  month_trend: number;
  trend_direction: string | null;
};
type Compliance = {
  compliance_score: number;
  critical_findings: number;
  high_findings: number;
  total_findings: number;
};
type Resource<T> = { value: T | null; loading: boolean; error: string };

declare global {
  interface Window {
    umami?: { track: (name: string, data?: Record<string, unknown>) => unknown };
  }
}

function trackEvent(name: string, data?: Record<string, unknown>) {
  try {
    const result = window.umami?.track(name, data);
    if (result && typeof (result as Promise<unknown>).catch === 'function') {
      (result as Promise<unknown>).catch(() => {});
    }
  } catch {
    // Analytics must never interrupt dashboard use.
  }
}

function formatSeverity(value: string | null | undefined) {
  return typeof value === 'string' && value.trim() ? value.trim().toUpperCase() : 'MEDIUM';
}

function formatDate(value?: string | null) {
  if (!value) return 'Time not recorded';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  });
}

function getErrorMessage(error: unknown) {
  return error instanceof Error ? error.message : 'Something went wrong. Please try again.';
}

function getHttpStatus(message: string) {
  const match = message.match(/\((\d{3})\)/);
  if (match) return Number(match[1]);
  if (/unauthorized/i.test(message)) return 401;
  return 0;
}

function retryableAuthError(message: string) {
  return /\((401|422)\)/.test(message) || /unauthorized|session expired/i.test(message);
}

function retryButton(onClick: () => void, label = 'Retry') {
  return <button className="button quiet small" type="button" onClick={onClick}>{label}</button>;
}

function Metric({ label, value, caption, tone = '', trend }: {
  label: string;
  value: string | number;
  caption?: string;
  tone?: string;
  trend?: string;
}) {
  return (
    <div className={`metric-card ${tone}`}>
      <span className="metric-label">{label}</span>
      <strong className="metric-value">{value}</strong>
      <span className="metric-foot">{caption}{trend && <span className="trend-arrow" aria-label={trend === 'increasing' ? 'Increasing' : 'Decreasing'}>{trend === 'increasing' ? '↗' : '↘'} {trend}</span>}</span>
    </div>
  );
}

function MetricLoading({ label }: { label: string }) {
  return (
    <div className="metric-card">
      <span className="metric-label">{label}</span>
      <strong className="metric-value" aria-label="Loading">–</strong>
      <span className="metric-foot">Loading data</span>
    </div>
  );
}

function StatusPill({ status }: { status: string }) {
  const normalized = status.toLowerCase();
  return <span className={`status-pill ${normalized}`}><span className="signal" />{normalized || 'unknown'}</span>;
}


function ResourceError({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div className="panel-error" role="alert">
      <span>{message}</span>
      {retryButton(onRetry)}
    </div>
  );
}

export default function Dashboard({ account, setAccount, userEmail, userId, onSignOut }: {
  account: Account | null;
  setAccount: (account: Account) => void;
  userEmail?: string;
  userId?: string;
  onSignOut: () => void;
}) {
  const [, setLocation] = useLocation();
  const [accountResource, setAccountResource] = useState<Resource<Account>>({ value: null, loading: true, error: '' });
  const [stats, setStats] = useState<Resource<ThreatStats>>({ value: null, loading: true, error: '' });
  const [findings, setFindings] = useState<Resource<Finding[]>>({ value: null, loading: true, error: '' });
  const [compliance, setCompliance] = useState<Resource<Compliance>>({ value: null, loading: true, error: '' });
  const [scans, setScans] = useState<Resource<Scan[]>>({ value: null, loading: true, error: '' });
  const [targetUrl, setTargetUrl] = useState('');
  const [scanBusy, setScanBusy] = useState(false);
  const [scanNotice, setScanNotice] = useState<{ text: string; critical: boolean } | null>(null);
  const [scanError, setScanError] = useState('');
  const [reportBusy, setReportBusy] = useState(false);
  const [reportMessage, setReportMessage] = useState('');
  const [reportError, setReportError] = useState(false);
  const hasTrackedDashboard = useRef(false);
  const lastLoadError = useRef<string | null>(null);
  const scanInFlight = useRef(false);

  const loadOne = useCallback(async <T,>(
    stage: string,
    request: () => Promise<T>,
    validate: (value: T) => boolean,
    setResource: Dispatch<SetStateAction<Resource<T>>>,
    label: string,
  ) => {
    setResource(old => ({ ...old, loading: old.value === null, error: '' }));
    try {
      const value = await request();
      if (!validate(value)) throw new Error('The response was not in the expected format.');
      setResource({ value, loading: false, error: '' });
      return null;
    } catch (error) {
      const message = getErrorMessage(error);
      setResource(old => ({ ...old, loading: false, error: `Unable to load ${label}: ${message}` }));
      if (retryableAuthError(message) && lastLoadError.current !== 'session_expired') {
        trackEvent('session_expired');
        lastLoadError.current = 'session_expired';
      }
      return { stage, message, status: getHttpStatus(message) };
    }
  }, []);

  const loadAll = useCallback(async () => {
    const outcomes = await Promise.all([
      loadOne('account', api.getAccount, value => !!value?.organization && !!value?.capabilities, setAccountResource, 'account'),
      loadOne('threat_intelligence', api.getThreatIntelligence, value => Number.isFinite(value?.total_findings), setStats, 'threat intelligence'),
      loadOne('findings', async () => (await api.getFindings()).findings, value => Array.isArray(value) && value.every((item: unknown) => !!item && typeof item === 'object' && !Array.isArray(item)), setFindings, 'findings'),
      loadOne('compliance', api.getCompliance, value => Number.isFinite(value?.compliance_score), setCompliance, 'compliance results'),
      loadOne('scan_history', async () => (await api.getScans()).scans, value => Array.isArray(value), setScans, 'scan history'),
    ]);
    const failures = outcomes.filter(Boolean) as { stage: string; message: string; status: number }[];
    if (!failures.length) {
      lastLoadError.current = null;
      return;
    }
    const errorKey = failures.map(({ stage, status }) => `${stage}:${status}`).join('|');
    if (lastLoadError.current !== errorKey && lastLoadError.current !== 'session_expired') {
      trackEvent('dashboard_load_failed', { stage: failures[0].stage, status: failures[0].status });
      console.error('Dashboard API load failed', failures.map(({ stage, status }) => ({ stage, status })));
      lastLoadError.current = errorKey;
    }
  }, [loadOne]);

  useEffect(() => {
    if (accountResource.value) setAccount(accountResource.value);
  }, [accountResource.value, setAccount]);

  useEffect(() => {
    let active = true;
    let running = false;
    const run = async () => {
      if (!active || running) return;
      running = true;
      try {
        await loadAll();
      } finally {
        running = false;
      }
    };
    void run();
    const interval = window.setInterval(() => void run(), 5000);
    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, [loadAll]);

  useEffect(() => {
    if (findings.value === null || hasTrackedDashboard.current) return;
    trackEvent('dashboard_loaded', { has_findings: findings.value.length > 0 });
    hasTrackedDashboard.current = true;
  }, [findings.value]);

  async function submitScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!targetUrl.trim() || scanInFlight.current) return;
    scanInFlight.current = true;
    trackEvent('mcp_scan_started');
    setScanBusy(true);
    setScanError('');
    setScanNotice(null);
    try {
      const data = await api.scanTarget(targetUrl.trim());
      trackEvent('mcp_scan_completed', {
        findings: data.scan?.findings_count,
        critical_findings: data.scan?.critical_count,
      });
      setScanNotice({ text: data.message || 'Scan completed.', critical: Boolean(data.scan?.has_critical) });
      setTargetUrl('');
      await loadAll();
    } catch (error) {
      const message = getErrorMessage(error);
      if (retryableAuthError(message) && lastLoadError.current !== 'session_expired') {
        trackEvent('session_expired');
        lastLoadError.current = 'session_expired';
      }
      trackEvent('mcp_scan_failed', { status: getHttpStatus(message) });
      setScanError(message);
    } finally {
      scanInFlight.current = false;
      setScanBusy(false);
    }
  }

  async function downloadComplianceReport() {
    if (reportBusy) return;
    setReportBusy(true);
    setReportMessage('');
    setReportError(false);
    trackEvent('compliance_pdf_download_started');
    try {
      const blob = await api.getCompliancePdf();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'vata-compliance-summary.pdf';
      link.hidden = true;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setReportMessage('Your compliance PDF is ready.');
      trackEvent('compliance_pdf_download_completed');
    } catch (error) {
      const message = getErrorMessage(error);
      setReportError(true);
      setReportMessage(message);
      trackEvent('compliance_pdf_download_failed', { status: getHttpStatus(message) });
    } finally {
      setReportBusy(false);
    }
  }

  const trend = stats.value?.trend_direction === 'increasing' || stats.value?.trend_direction === 'decreasing'
    ? stats.value.trend_direction : undefined;
  const historyDays = account?.capabilities?.historyDays ?? null;
  const visibleScans = scans.value?.filter(scan => {
    if (historyDays === null || historyDays === undefined) return true;
    const date = new Date(scan.completed_at || scan.started_at || '');
    return Number.isFinite(date.getTime()) && date.getTime() >= Date.now() - historyDays * 24 * 60 * 60 * 1000;
  });

  return (
    <div className="portal app-shell">
      <header className="portal-topbar">
        <div className="wrap portal-topbar-inner">
          <div className="workspace-label">
            <Link className="brand" href="/user-portal" aria-label="VATA workspace">
              <img src="/logo.svg" alt="" /><span className="brand-word">VATA</span>
            </Link>
            <span className="workspace-divider" />
            <span className="org-name">{account?.organization?.name || 'Security workspace'}</span>
          </div>
          <div className="profile-actions">
            <span className="profile-email">{userEmail || 'Authenticated workspace'}</span>
            <button className="button secondary small" type="button" onClick={() => setLocation('/')}>Overview</button>
            <button className="button quiet small" type="button" onClick={onSignOut}>Sign out</button>
          </div>
        </div>
      </header>

      <main className="wrap portal-main">
        <div className="page-heading">
          <div>
            <span className="eyebrow">MCP authorization review</span>
            <h1>Security workspace</h1>
            <p>Run an authorized server scan, then review its findings and organization-level signals.</p>
          </div>
          {account && <div className="account-chip">Workspace · {account.role || 'owner'}</div>}
        </div>

        <section className="panel report-export" aria-labelledby="compliance-export-title">
          <div className="report-copy">
            <span className="eyebrow">Printable report</span>
            <h2 className="panel-title" id="compliance-export-title">Compliance summary</h2>
            <p>Download this organization’s VATA score, severity counts, and recent findings.</p>
            <p className="field-note">The VATA score is an indicator—not a SOC 2 certification or audit opinion.</p>
          </div>
          <div className="report-actions">
            <button className="button secondary" type="button" onClick={() => void downloadComplianceReport()} disabled={reportBusy}>
              {reportBusy ? 'Preparing PDF…' : 'Download PDF'}
            </button>
            {reportMessage && <p className={`report-status${reportError ? ' error' : ''}`} role={reportError ? 'alert' : 'status'}>{reportMessage}</p>}
          </div>
        </section>

        {!account && <section className="panel" aria-label="Account loading">
          {accountResource.error
            ? <ResourceError message={accountResource.error} onRetry={() => void loadAll()} />
            : <div className="panel-body"><div className="skeleton" /><div className="skeleton" /></div>}
        </section>}
        {account && <PlanAndUsage account={account} />}
        {scanError && <div className="scan-status error" role="alert">{scanError}</div>}
        {account && <AcceptTeamInvite onDone={() => { void loadAll(); setLocation('/user-portal'); }} />}

        <section className="metric-grid" aria-label="Security overview">
          {stats.loading && !stats.value ? <>
            <MetricLoading label="Critical findings" /><MetricLoading label="High severity" /><MetricLoading label="Total findings" /><MetricLoading label="30-day trend" />
          </> : <>
            <Metric label="Critical findings" value={stats.value?.critical ?? '—'} caption="Current organization" tone="critical" />
            <Metric label="High severity" value={stats.value?.high ?? '—'} caption="Current organization" tone="high" />
            <Metric label="Total findings" value={stats.value?.total_findings ?? '—'} caption={`7 days: ${stats.value?.week_trend ?? '—'} · 30 days: ${stats.value?.month_trend ?? '—'}`} />
            <Metric label="30-day trend" value={trend ? (trend === 'increasing' ? 'Rising' : 'Falling') : '—'} caption="Compared with weekly average" trend={trend} />
          </>}
          {compliance.loading && !compliance.value
            ? <MetricLoading label="Compliance score" />
            : <Metric label="Compliance score" value={compliance.value ? `${compliance.value.compliance_score}%` : '—'} caption={compliance.value ? `${compliance.value.total_findings} findings included` : 'Not available'} tone="compliance" />}
        </section>

        <div className="dashboard-grid">
          <section className="panel">
            <header className="panel-head">
              <div><h2 className="panel-title">Scan a server or repository</h2><p className="panel-subtitle">Test a live MCP server or a public GitHub repository you are authorized to scan.</p></div>
            </header>
            <div className="panel-body">
              <form className="scan-form" onSubmit={submitScan}>
                <div className="field">
                  <label htmlFor="target-url">MCP server or GitHub repository URL</label>
                  <input id="target-url" type="url" required maxLength={2048} placeholder="https://github.com/owner/repository" value={targetUrl} onChange={event => setTargetUrl(event.target.value)} disabled={scanBusy} />
                </div>
                <button className="button" type="submit" disabled={scanBusy || !targetUrl.trim()}>{scanBusy ? 'Scanning…' : 'Run scan'}</button>
              </form>
              <p className="field-note">Only scan systems you are authorized to test. A scan may take a short time to complete.</p>
              {scanNotice && <p className={`scan-status ${scanNotice.critical ? 'warning' : 'success'}`} role="status">{scanNotice.critical ? `Critical findings detected. ${scanNotice.text}` : scanNotice.text}</p>}
            </div>
          </section>

          <section className="panel">
            <header className="panel-head">
              <div><h2 className="panel-title">Recent scans</h2><p className="panel-subtitle">Most recent scan runs for this organization.</p></div>
              {scans.error && retryButton(() => void loadAll(), 'Refresh')}
            </header>
            {scans.error && <ResourceError message={scans.error} onRetry={() => void loadAll()} />}
            {scans.loading && !scans.value
              ? <div className="scan-list" aria-label="Loading scan history"><div className="skeleton" /><div className="skeleton" /><div className="skeleton" /></div>
              : visibleScans?.length
                ? <div className="scan-list">{visibleScans.map(scan => (
                  <article className="scan-row" key={scan.id}>
                    <div className="scan-row-top"><strong className="scan-target" title={scan.target}>{scan.target}</strong><StatusPill status={scan.status || 'unknown'} /></div>
                    {scan.status === 'failed'
                      ? <p className="failure-text">{scan.error || 'The scan failed.'}</p>
                      : <>
                        {scan.critical_count > 0 && <p className="failure-text" role="alert">Critical findings detected in this scan.</p>}
                        <p className="scan-meta">{scan.findings_count} finding(s) · {scan.critical_count} critical · {scan.high_count} high{scan.compliance_score !== null && scan.compliance_score !== undefined ? ` · compliance ${scan.compliance_score}%` : ''}</p>
                      </>}
                    <time className="scan-date">{formatDate(scan.completed_at || scan.started_at)}</time>
                  </article>
                ))}</div>
                : !scans.error && <div className="empty-state"><strong>No scans have been run yet.</strong><span>Use the scan form to review an authorized MCP server. Results will appear here.</span></div>}
          </section>
        </div>

        <section className="panel findings-panel">
          <header className="panel-head">
            <div><h2 className="panel-title">Recent findings</h2><p className="panel-subtitle">Latest results for the signed-in organization · showing up to 20 · read-only records.</p></div>
            {findings.error && retryButton(() => void loadAll(), 'Refresh')}
          </header>
          {findings.error && <ResourceError message={findings.error} onRetry={() => void loadAll()} />}
          {findings.loading && !findings.value
            ? <div aria-label="Loading findings"><div className="skeleton" /><div className="skeleton" /><div className="skeleton" /></div>
            : findings.value?.length
              ? <div className="finding-list">{findings.value.slice(0, 20).map(finding => {
                const severity = formatSeverity(finding.severity);
                const rule = finding.rule || finding.vector_type || 'Finding';
                return <article className="finding-row" key={finding.id}>
                  <div>
                    <h3 className="finding-title">{finding.server || finding.server_name || finding.vector_type || 'MCP server'}</h3>
                    <p className="finding-description">{rule}: {finding.description || 'No description provided.'}</p>
                    {finding.remediation && <p className="finding-remediation">Recommended fix: {finding.remediation}</p>}
                  </div>
                  <span className={`severity ${severity.toLowerCase()}`}>{severity}</span>
                </article>;
              })}</div>
              : !findings.error && <div className="empty-state"><strong>No findings returned for this signed-in organization.</strong><span>Findings from another organization or environment will not appear here.</span></div>}
        </section>
        {account && <div className="feature-layout">
          <SchedulingPanel account={account} />
          <ApiTokensPanel account={account} />
        </div>}
        {account && <div style={{ marginBottom: 18 }}><TeamPanel account={account} userId={userId} onMembershipChange={() => void loadAll()} /></div>}
        {(stats.error || compliance.error) && <div className="dashboard-grid" style={{ marginTop: 17 }}>
          {stats.error && <section className="panel"><ResourceError message={stats.error} onRetry={() => void loadAll()} /></section>}
          {compliance.error && <section className="panel"><ResourceError message={compliance.error} onRetry={() => void loadAll()} /></section>}
        </div>}
      </main>
    </div>
  );
}
