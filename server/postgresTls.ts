/**
 * Pin certificate and hostname verification instead of relying on pg's
 * version-dependent interpretation of require/prefer/verify-ca.
 * Do not log the returned URL: it contains database credentials.
 */
export function verifiedPostgresUrl(connectionString: string | undefined) {
  if (!connectionString) return connectionString;
  const url = new URL(connectionString);
  const mode = url.searchParams.get('sslmode');
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  // Plaintext is only supported for explicitly local test/development databases.
  if (mode === 'disable' && !local) {
    throw new Error('Remote PostgreSQL requires sslmode=verify-full.');
  }
  if (!(local && (!mode || mode === 'disable'))) {
    url.searchParams.set('sslmode', 'verify-full');
    url.searchParams.delete('uselibpqcompat');
  }
  return url.toString();
}
