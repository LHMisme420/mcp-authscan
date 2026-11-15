export type AuthReadinessResult = { request: string; status: string };

/** Diagnostic only: never authenticates a user or grants workspace access. */
export async function checkAuthReadiness(
  signal: AbortSignal,
  request = '/api/__clerk/v1/environment',
  fetcher: typeof fetch = fetch,
  timeoutMs = 5000,
): Promise<AuthReadinessResult> {
  const controller = new AbortController();
  const cancel = () => controller.abort();
  signal.addEventListener('abort', cancel, { once: true });
  if (signal.aborted) controller.abort();
  const timer = setTimeout(cancel, timeoutMs);
  try {
    const response = await fetcher(request, {
      credentials: 'include', cache: 'no-store', signal: controller.signal,
    });
    const json = response.headers.get('content-type')?.includes('application/json');
    return {
      request,
      status: `HTTP ${response.status}${response.ok && !json ? ' — unexpected non-JSON response' : ''}`,
    };
  } catch {
    return {
      request,
      status: controller.signal.aborted
        ? 'Timed out — no HTTP status received'
        : 'Network error — no HTTP status received',
    };
  } finally {
    clearTimeout(timer);
    signal.removeEventListener('abort', cancel);
  }
}
