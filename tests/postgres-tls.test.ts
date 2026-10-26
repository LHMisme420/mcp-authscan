import test from 'node:test';
import assert from 'node:assert/strict';
import { verifiedPostgresUrl } from '../server/postgresTls';

test('remote connections explicitly verify certificates and hostnames', () => {
  for (const mode of ['', 'require', 'prefer', 'verify-ca', 'verify-full']) {
    const url = new URL('postgresql://example:synthetic@db.example.test/vata');
    if (mode) url.searchParams.set('sslmode', mode);
    url.searchParams.set('sslrootcert', '/tmp/example-ca.pem');
    url.searchParams.set('uselibpqcompat', 'true');
    const result = new URL(verifiedPostgresUrl(url.toString())!);
    assert.equal(result.searchParams.get('sslmode'), 'verify-full');
    assert.equal(result.searchParams.has('uselibpqcompat'), false);
    assert.equal(result.searchParams.get('sslrootcert'), '/tmp/example-ca.pem');
    assert.equal(result.username, url.username);
    assert.equal(result.password, url.password);
  }
});

test('plaintext is permitted only for local databases', () => {
  assert.throws(() => verifiedPostgresUrl('postgresql://db.example.test/vata?sslmode=disable'),
    /requires sslmode=verify-full/);
  for (const host of ['localhost', '127.0.0.1', '[::1]']) {
    const result = new URL(verifiedPostgresUrl(`postgresql://${host}/test?sslmode=disable`)!);
    assert.equal(result.searchParams.get('sslmode'), 'disable');
  }
  assert.equal(verifiedPostgresUrl(undefined), undefined);
});
