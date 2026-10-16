import { useEffect, useState, type FormEvent } from 'react';
import { Link } from 'wouter';
import { api } from './api';

type PortalAccount = {
  actorUserId: string;
  role?: 'owner' | 'member';
  usage?: { used: number; limit: 5 | null; remaining: number | null; month: string; resetsAt: string };
  capabilities?: { programmaticApi: boolean; scheduling: boolean; teamSeats: number; historyDays: 7 | null };
  billing?: { mode?: 'disabled' | 'test' | 'live' };
};
type Schedule = { id: number; target_url: string; frequency: 'once' | 'hourly' | 'daily' | 'weekly'; next_run_at: string | null; enabled: boolean; last_run_at: string | null; last_error: string | null; created_by: string };
type Team = { role: 'owner' | 'member'; organization: { id: number | string; name: string }; seatsUsed: number; maxSeats: 5; members: { userId: string; role: string; label: string }[]; invites: { id: number; expires_at: string }[] };
type ApiToken = { id: number; name: string; created_at: string; last_used_at: string | null };

function messageOf(error: unknown) {
  return error instanceof Error ? error.message : 'Something went wrong. Please try again.';
}
function utc(value?: string | null) {
  if (!value) return 'Not scheduled';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : `${date.toISOString().replace('T', ' ').slice(0, 16)} UTC`;
}
function initials(value: string) {
  const parts = value.trim().split(/[\s@._-]+/).filter(Boolean);
  return (parts.slice(0, 2).map(part => part[0]).join('') || 'V').toUpperCase();
}
function Retry({ onClick }: { onClick: () => void }) {
  return <button className="button quiet small" type="button" onClick={onClick}>Retry</button>;
}
function Alert({ children, success = false }: { children: string; success?: boolean }) {
  return <div className={`feature-alert${success ? ' success' : ''}`} role={success ? 'status' : 'alert'}>{children}</div>;
}
function LockedFeature() {
  return <div className="feature-lock"><p>This feature is not available for this account. Ask your workspace owner to review your access.</p></div>;
}
function ApiExamples({ scan, schedule }: { scan: string; schedule: string }) {
  return <>
    <div className="feature-code"><strong className="feature-meta">Scan request · use your browser origin</strong><pre>{scan}</pre></div>
    <div className="feature-code"><strong className="feature-meta">Schedule request · same token authorization</strong><pre>{schedule}</pre></div>
  </>;
}

export function PlanAndUsage({ account }: { account: PortalAccount }) {
  const usage = account.usage;
  const used = usage?.used ?? 0;
  return (
    <>
      <section className="plan-summary" aria-label="Workspace and scan usage">
        <div className="plan-summary-copy">
          <span className={`plan-dot${account.capabilities?.programmaticApi ? ' pro' : ''}`} aria-hidden="true" />
          <div>
            <h2>VATA workspace</h2>
            <p>Scanning, full history, API access, scheduling, and up to 5 team members. No subscription required.</p>
          </div>
        </div>
        <div>
          <strong className="quota-number">{used} scans</strong>
          <span className="quota-caption">SCANS THIS UTC MONTH</span>
        </div>
      </section>
    </>
  );
}

export function SchedulingPanel({ account }: { account: PortalAccount }) {
  const enabled = account.capabilities?.scheduling ?? false;
  const canView = enabled || account.role === 'owner';
  const [schedules, setSchedules] = useState<Schedule[] | null>(null);
  const [loading, setLoading] = useState(canView);
  const [error, setError] = useState('');
  const [actionError, setActionError] = useState('');
  const [busy, setBusy] = useState(false);
  const [target, setTarget] = useState('');
  const [frequency, setFrequency] = useState<Schedule['frequency']>('daily');
  const [runAt, setRunAt] = useState('');

  async function load() {
    setLoading(true); setError('');
    try {
      const result = await api.getSchedules();
      if (!Array.isArray(result?.schedules)) throw new Error('Schedule response was not in the expected format.');
      setSchedules(result.schedules);
    } catch (e) { setError(`Unable to load schedules: ${messageOf(e)}`); }
    finally { setLoading(false); }
  }
  useEffect(() => { if (canView) void load(); }, [canView]);

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!enabled || busy || !target.trim()) return;
    setBusy(true); setActionError('');
    try {
      await api.createSchedule({ target_url: target.trim(), frequency, ...(frequency === 'once' && runAt ? { run_at: new Date(`${runAt}Z`).toISOString() } : {}) });
      setTarget(''); setRunAt(''); await load();
    } catch (e) { setActionError(`Unable to create schedule: ${messageOf(e)}`); }
    finally { setBusy(false); }
  }
  async function toggle(schedule: Schedule) {
    if (!enabled && !schedule.enabled) return;
    setBusy(true); setActionError('');
    try { await api.updateSchedule(schedule.id, !schedule.enabled); await load(); }
    catch (e) { setActionError(`Unable to update schedule: ${messageOf(e)}`); }
    finally { setBusy(false); }
  }
  async function remove(schedule: Schedule) {
    if (!window.confirm(`Delete the schedule for ${schedule.target_url}?`)) return;
    setBusy(true); setActionError('');
    try { await api.deleteSchedule(schedule.id); await load(); }
    catch (e) { setActionError(`Unable to delete schedule: ${messageOf(e)}`); }
    finally { setBusy(false); }
  }

  return <section className="feature-panel">
    <header className="panel-head"><div><h2 className="panel-title">Automated scheduling</h2><p className="panel-subtitle">Runs on the VATA worker. All times are UTC.</p></div>{error && <Retry onClick={() => void load()} />}</header>
    {!canView ? <LockedFeature /> : <div className="feature-body">
      {!enabled && <LockedFeature />}
      {actionError && <Alert>{actionError}</Alert>}{error && <Alert>{error}</Alert>}
      {enabled && <form className="feature-form" onSubmit={create}>
        <div className="field"><label htmlFor="schedule-target">MCP server URL</label><input id="schedule-target" type="url" required maxLength={2048} placeholder="https://mcp.example.com" value={target} onChange={e => setTarget(e.target.value)} disabled={busy} /></div>
        <div className="field"><label htmlFor="schedule-frequency">Frequency</label><select id="schedule-frequency" value={frequency} onChange={e => setFrequency(e.target.value as Schedule['frequency'])} disabled={busy}><option value="once">Once</option><option value="hourly">Hourly</option><option value="daily">Daily</option><option value="weekly">Weekly</option></select></div>
        {frequency === 'once' && <div className="field"><label htmlFor="schedule-time">Run at (UTC)</label><input id="schedule-time" type="datetime-local" value={runAt} onChange={e => setRunAt(e.target.value)} disabled={busy} /></div>}
        <button className="button small" type="submit" disabled={busy || !target.trim()}>{busy ? 'Saving…' : 'Add schedule'}</button>
      </form>}
      {loading && !schedules ? <div aria-label="Loading schedules"><div className="skeleton" /><div className="skeleton" /></div>
        : schedules?.length ? <ul className="feature-list">{schedules.map(schedule => <li className="feature-row" key={schedule.id}>
          <div className="feature-row-main"><strong>{schedule.target_url}</strong><span>{schedule.frequency} · next run {utc(schedule.next_run_at)}{schedule.last_run_at ? ` · last run ${utc(schedule.last_run_at)}` : ''}</span>{schedule.last_error && <span className="quota-warning">Last error: {schedule.last_error}</span>}</div>
          {(account.role === 'owner' || schedule.created_by === account.actorUserId) && <div className="feature-controls"><button className="button secondary small" type="button" disabled={busy || (!enabled && !schedule.enabled)} onClick={() => void toggle(schedule)}>{schedule.enabled ? 'Pause' : 'Resume'}</button><button className="button quiet small" type="button" disabled={busy} onClick={() => void remove(schedule)}>Delete</button></div>}
        </li>)}</ul> : !error && <div className="empty-state"><strong>No schedules yet.</strong><span>{enabled ? 'Create a schedule for an authorized MCP server.' : 'There are no existing schedules to clean up.'}</span></div>}
    </div>}
  </section>;
}

export function TeamPanel({ account, userId, onMembershipChange }: { account: PortalAccount; userId?: string; onMembershipChange?: () => void }) {
  const enabled = true;
  const [team, setTeam] = useState<Team | null>(null);
  const [loading, setLoading] = useState(enabled);
  const [error, setError] = useState('');
  const [actionError, setActionError] = useState('');
  const [busy, setBusy] = useState(false);
  const [invite, setInvite] = useState<{ url: string; expiresAt: string } | null>(null);
  const [copied, setCopied] = useState(false);
  const canInvite = account.role === 'owner' && (account.capabilities?.teamSeats ?? 0) > 1;

  async function load() {
    setLoading(true); setError('');
    try {
      const result = await api.getTeam();
      if (!result?.organization || !Array.isArray(result.members) || !Array.isArray(result.invites)) throw new Error('Team response was not in the expected format.');
      setTeam(result);
    } catch (e) { setError(`Unable to load team: ${messageOf(e)}`); }
    finally { setLoading(false); }
  }
  useEffect(() => { if (enabled) void load(); }, [enabled]);
  async function inviteMember() {
    if (!team || busy || team.role !== 'owner' || !canInvite || team.seatsUsed >= team.maxSeats) return;
    setBusy(true); setActionError(''); setInvite(null); setCopied(false);
    try {
      const result = await api.inviteTeam();
      if (!result?.invite_url) throw new Error('The invitation link was not returned.');
      setInvite({ url: result.invite_url, expiresAt: result.expires_at }); await load();
    } catch (e) { setActionError(`Unable to create invitation: ${messageOf(e)}`); }
    finally { setBusy(false); }
  }
  async function copyInvite() {
    if (!invite) return;
    try { await navigator.clipboard.writeText(invite.url); setCopied(true); }
    catch { setActionError('Could not copy the invitation link. Select and copy it manually.'); }
  }
  async function revoke(id: number) {
    if (!window.confirm('Revoke this invitation?')) return;
    setBusy(true); setActionError('');
    try { await api.revokeInvite(id); await load(); }
    catch (e) { setActionError(`Unable to revoke invitation: ${messageOf(e)}`); }
    finally { setBusy(false); }
  }
  async function removeMember(member: Team['members'][number]) {
    if (!window.confirm(`Remove ${member.label || member.userId} from this team?`)) return;
    setBusy(true); setActionError('');
    try { await api.removeMember(member.userId); await load(); }
    catch (e) { setActionError(`Unable to remove member: ${messageOf(e)}`); }
    finally { setBusy(false); }
  }
  async function leave() {
    if (!window.confirm('Leave this team? Your personal workspace data will be retained.')) return;
    setBusy(true); setActionError('');
    try { await api.leaveTeam(); onMembershipChange?.(); await load(); }
    catch (e) { setActionError(`Unable to leave team: ${messageOf(e)}`); }
    finally { setBusy(false); }
  }

  return <section className="feature-panel">
    <header className="panel-head"><div><h2 className="panel-title">Team access</h2><p className="panel-subtitle">Seats include the owner. Personal workspace data remains separate.</p></div>{error && enabled && <Retry onClick={() => void load()} />}</header>
    {!enabled ? <LockedFeature /> : <>
      {actionError && <div className="feature-body"><Alert>{actionError}</Alert></div>}
      {error && <div className="feature-body"><Alert>{error}</Alert></div>}
      {loading && !team ? <div className="feature-body"><div className="skeleton" /><div className="skeleton" /></div> : team && <div className="feature-body">
        <div className="feature-row"><div className="feature-row-main"><strong>{team.organization.name}</strong><span>Your role: {team.role}</span></div><span className="seat-count">{team.seatsUsed} / {team.maxSeats} seats · pending reserved</span></div>
        {team.role === 'owner' && <div style={{ paddingBlock: 13 }}>
          <button className="button small" type="button" disabled={busy || !canInvite || team.seatsUsed >= team.maxSeats} onClick={() => void inviteMember()}>{busy ? 'Working…' : 'Invite a member'}</button>
          {!canInvite && <p className="feature-inline-note">Invitations are available on Pro. You can still manage existing members and invitations here.</p>}
          {team.seatsUsed >= team.maxSeats && <p className="feature-inline-note">All 5 seats, including the owner, are in use.</p>}
          {invite && <div className="token-secret"><strong>Invitation link · expires {utc(invite.expiresAt)}</strong><code>{invite.url}</code><button className="button secondary small" type="button" onClick={() => void copyInvite()}>{copied ? 'Copied' : 'Copy invitation link'}</button></div>}
        </div>}
        <div className="team-members">{team.members.map(member => <div className="team-member" key={member.userId}>
          <div className="member-identity"><span className="member-mark" aria-hidden="true">{initials(member.label || member.userId)}</span><div><strong>{member.label || member.userId}</strong><span>{member.role}{member.userId === userId ? ' · you' : ''}</span></div></div>
          {team.role === 'owner' && member.role !== 'owner' && <button className="button quiet small" type="button" disabled={busy} onClick={() => void removeMember(member)}>Remove</button>}
        </div>)}</div>
        {!!team.invites.length && <div className="team-members" aria-label="Pending invitations">{team.invites.map(item => <div className="team-member" key={item.id}><div className="member-identity"><span className="member-mark" aria-hidden="true">INV</span><div><strong>Pending invitation</strong><span>Expires {utc(item.expires_at)}</span></div></div>{team.role === 'owner' && <button className="button quiet small" type="button" disabled={busy} onClick={() => void revoke(item.id)}>Revoke</button>}</div>)}</div>}
        {team.role === 'member' && <button className="button secondary small" type="button" disabled={busy} onClick={() => void leave()}>Leave team</button>}
      </div>}
    </>}
  </section>;
}

export function ApiTokensPanel({ account }: { account: PortalAccount }) {
  const allowed = account.capabilities?.programmaticApi ?? false;
  const canManage = account.role === 'owner';
  const canCleanUp = canManage && !allowed;
  const [tokens, setTokens] = useState<ApiToken[] | null>(null);
  const [loading, setLoading] = useState(canManage);
  const [error, setError] = useState('');
  const [actionError, setActionError] = useState('');
  const [busy, setBusy] = useState(false);
  const [name, setName] = useState('');
  const [newSecret, setNewSecret] = useState<{ id: number; name: string; token: string } | null>(null);
  const [copied, setCopied] = useState(false);
  async function load() {
    setLoading(true); setError('');
    try {
      const result = await api.getApiTokens();
      if (!Array.isArray(result?.tokens)) throw new Error('Token response was not in the expected format.');
      setTokens(result.tokens);
    } catch (e) { setError(`Unable to load API tokens: ${messageOf(e)}`); }
    finally { setLoading(false); }
  }
  useEffect(() => { if (canManage) void load(); }, [canManage]);
  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || !name.trim()) return;
    setBusy(true); setActionError(''); setNewSecret(null); setCopied(false);
    try {
      const result = await api.createApiToken(name.trim());
      if (!result?.token || !Number.isFinite(result.id)) throw new Error('The new token was not returned.');
      setNewSecret({ id: result.id, name: result.name, token: result.token }); setName(''); await load();
    } catch (e) { setActionError(`Unable to create API token: ${messageOf(e)}`); }
    finally { setBusy(false); }
  }
  async function revoke(token: ApiToken) {
    if (!window.confirm(`Revoke API token “${token.name}”? Applications using it will lose access.`)) return;
    setBusy(true); setActionError('');
    try { await api.revokeApiToken(token.id); if (newSecret?.id === token.id) setNewSecret(null); await load(); }
    catch (e) { setActionError(`Unable to revoke API token: ${messageOf(e)}`); }
    finally { setBusy(false); }
  }
  async function copySecret() {
    if (!newSecret) return;
    try { await navigator.clipboard.writeText(newSecret.token); setCopied(true); }
    catch { setActionError('Could not copy the token. Select and copy it manually.'); }
  }
  const scanExample = [
    `curl -X POST '${window.location.origin}/api/scan' \\`,
    "  -H 'Authorization: Bearer $VATA_API_TOKEN' \\",
    "  -H 'Content-Type: application/json' \\",
    `  -d '{"target_url":"https://mcp.example.com"}'`,
  ].join('\n');
  const scheduleExample = [
    `curl -X POST '${window.location.origin}/api/schedule-scan' \\`,
    "  -H 'Authorization: Bearer $VATA_API_TOKEN' \\",
    "  -H 'Content-Type: application/json' \\",
    `  -d '{"target_url":"https://mcp.example.com","frequency":"daily"}'`,
  ].join('\n');
  return <section className="feature-panel">
    <header className="panel-head"><div><h2 className="panel-title">Programmatic scan API</h2><p className="panel-subtitle">Use a token with the scan and schedule endpoints.</p></div>{error && canManage && <Retry onClick={() => void load()} />}</header>
    {!allowed && !canCleanUp ? <LockedFeature />
      : !canManage ? <div className="feature-body"><p className="feature-inline-note">Your workspace has Pro access. Use a token provided by the owner; only the owner can create or revoke tokens.</p><ApiExamples scan={scanExample} schedule={scheduleExample} /></div>
      : <div className="feature-body">
        {canCleanUp && <LockedFeature />}
        {actionError && <Alert>{actionError}</Alert>}{error && <Alert>{error}</Alert>}
        {allowed && <form className="feature-form" onSubmit={create}><div className="field"><label htmlFor="token-name">Token name</label><input id="token-name" required maxLength={80} value={name} onChange={e => setName(e.target.value)} placeholder="CI scanner" disabled={busy} /></div><button className="button small" type="submit" disabled={busy || !name.trim()}>{busy ? 'Creating…' : 'Create token'}</button></form>}
        {newSecret && <div className="token-secret"><strong>{newSecret.name} · shown only once</strong><code>{newSecret.token}</code><button className="button secondary small" type="button" onClick={() => void copySecret()}>{copied ? 'Copied' : 'Copy token'}</button></div>}
        {loading && !tokens ? <div aria-label="Loading API tokens"><div className="skeleton" /><div className="skeleton" /></div>
          : tokens?.length ? <ul className="feature-list">{tokens.map(token => <li className="feature-row" key={token.id}><div className="feature-row-main"><strong>{token.name}</strong><span>Created {utc(token.created_at)} · last used {token.last_used_at ? utc(token.last_used_at) : 'never'}</span></div><button className="button quiet small" type="button" disabled={busy} onClick={() => void revoke(token)}>Revoke</button></li>)}</ul>
            : !error && <div className="empty-state"><strong>No API tokens.</strong><span>Create one to authorize programmatic scans.</span></div>}
        <ApiExamples scan={scanExample} schedule={scheduleExample} />
      </div>}
  </section>;
}

export function JoinTeamPage() {
  const params = new URLSearchParams(window.location.search);
  const token = params.get('token') || '';
  return <main className="join-shell app-shell"><section className="join-card">
    <Link href="/" className="brand"><img src="/logo.svg" alt="" /><span className="brand-word">VATA</span></Link>
    <span className="eyebrow" style={{ display: 'block', marginTop: 24 }}>Team invitation</span>
    <h1>Join a VATA workspace</h1>
    <p>Accepting this one-use invitation connects your account to the inviting team. Your personal workspace data is retained.</p>
    {!token ? <Alert>Invitation token is missing. Open the full invitation link again.</Alert> : <p className="feature-inline-note">Sign in or create an account to accept. The invitation token stays in this URL through authentication.</p>}
    <div className="join-actions">
      {token && <Link className="button" href={`/sign-in?redirect_url=${encodeURIComponent(`${window.location.pathname}${window.location.search}`)}`}>Sign in to accept</Link>}
      {token && <Link className="button secondary" href={`/sign-up?redirect_url=${encodeURIComponent(`${window.location.pathname}${window.location.search}`)}`}>Create account</Link>}
      <Link className="button quiet" href="/">Return to VATA</Link>
    </div>
  </section></main>;
}

export function AcceptTeamInvite({ onDone }: { onDone: () => void }) {
  const token = new URLSearchParams(window.location.search).get('token') || '';
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [done, setDone] = useState(false);
  async function accept() {
    if (busy || done || !token) return;
    setBusy(true); setError('');
    try {
      await api.joinTeam(token);
      setDone(true);
      onDone();
    } catch (e) { setError(`Unable to accept invitation: ${messageOf(e)}`); }
    finally { setBusy(false); }
  }
  if (!token) return null;
  return <section className="panel" style={{ marginBottom: 18 }}>
    <div className="panel-body">
      <div className="feature-row" style={{ paddingTop: 0 }}>
        <div className="feature-row-main"><strong>Invitation ready</strong><span>Accept to join the team. Your personal workspace data is retained.</span></div>
        <button className="button small" type="button" onClick={() => void accept()} disabled={busy || done}>{done ? 'Accepted' : busy ? 'Accepting…' : 'Accept invitation'}</button>
      </div>
      {error && <Alert>{error}</Alert>}
    </div>
  </section>;
}
