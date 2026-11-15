import { useEffect, useState } from 'react';
import { checkAuthReadiness, type AuthReadinessResult } from './authReadiness';

const basePath = (import.meta.env?.BASE_URL ?? '/').replace(/\/$/, '');

export function AuthLoading({
  timeoutMs = 2000,
  check = checkAuthReadiness,
}: {
  timeoutMs?: number;
  check?: (signal: AbortSignal) => Promise<AuthReadinessResult>;
}) {
  const [expired, setExpired] = useState(false);
  const [diagnostic, setDiagnostic] = useState<AuthReadinessResult | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    const timer = setTimeout(() => {
      setExpired(true);
      void check(controller.signal).then(result => {
        if (!controller.signal.aborted) setDiagnostic(result);
      }).catch(() => {
        if (!controller.signal.aborted) {
          setDiagnostic({ request: '/api/__clerk/v1/environment', status: 'Network error — no HTTP status received' });
        }
      });
    }, timeoutMs);
    return () => { clearTimeout(timer); controller.abort(); };
  }, [check, timeoutMs]);

  if (!expired) return <main className="auth-loading" role="status">Loading secure workspace…</main>;
  return (
    <main className="auth-loading">
      <section className="auth-load-error" role="alert" aria-labelledby="auth-load-error-title">
        <h1 id="auth-load-error-title">Unable to load secure workspace</h1>
        <p>The sign-in service did not finish initializing within {Math.round(timeoutMs / 1000)} seconds.
          Your sign-in status could not be confirmed. Workspace access remains protected.</p>
        <p><strong>Waiting on:</strong> authentication initialization (Clerk useAuth().isLoaded).</p>
        {diagnostic ? (
          <>
            <p><strong>Authentication service check:</strong> <code>GET {diagnostic.request}</code></p>
            <p><strong>Status:</strong> {diagnostic.status}</p>
            <p>A successful service response does not mean your browser has finished signing in.
              A blocked script, connection problem, or browser restriction may still prevent initialization.</p>
          </>
        ) : <p role="status">Checking the authentication service (up to 5 seconds)…</p>}
        <div className="auth-load-actions">
          <button type="button" onClick={() => window.location.reload()}>Retry workspace</button>
          <a href={`${basePath}/sign-in?redirect_url=${encodeURIComponent(`${basePath}/user-portal`)}`}>Go to sign in</a>
          <a href={basePath || '/'}>Back to public site</a>
        </div>
        <p>No scan or workspace change was performed.</p>
      </section>
    </main>
  );
}
