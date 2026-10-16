async function request<T = any>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    credentials: 'include',
    ...init,
    headers: { 'Content-Type': 'application/json', ...init.headers },
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || `Request failed (${response.status})`);
  }
  return data;
}

export const api = {
  getAccount: () => request('/api/account'),
  getFindings: () => request('/api/findings'),
  getThreatIntelligence: () => request('/api/threat-intelligence'),
  getCompliance: () => request('/api/reports/compliance'),
  getScans: () => request('/api/scans/mcp'),
  scanTarget: (target_url: string) => request('/api/scans/mcp', {
    method: 'POST', body: JSON.stringify({ target_url }),
  }),
  getSchedules: () => request('/api/schedule-scan'),
  createSchedule: (data: { target_url: string; frequency: string; run_at?: string }) =>
    request('/api/schedule-scan', { method: 'POST', body: JSON.stringify(data) }),
  updateSchedule: (id: number, enabled: boolean) =>
    request(`/api/schedule-scan/${id}`, { method: 'PATCH', body: JSON.stringify({ enabled }) }),
  deleteSchedule: (id: number) => request(`/api/schedule-scan/${id}`, { method: 'DELETE' }),
  getTeam: () => request('/api/team'),
  inviteTeam: () => request('/api/team/invites', { method: 'POST', body: '{}' }),
  revokeInvite: (id: number) => request(`/api/team/invites/${id}`, { method: 'DELETE' }),
  removeMember: (userId: string) => request(`/api/team/members/${encodeURIComponent(userId)}`, { method: 'DELETE' }),
  leaveTeam: () => request('/api/team/leave', { method: 'POST', body: '{}' }),
  joinTeam: (token: string) => request('/api/team/join', { method: 'POST', body: JSON.stringify({ token }) }),
  getApiTokens: () => request('/api/api-tokens'),
  createApiToken: (name: string) => request('/api/api-tokens', { method: 'POST', body: JSON.stringify({ name }) }),
  revokeApiToken: (id: number) => request(`/api/api-tokens/${id}`, { method: 'DELETE' }),
};
