import { spawn, type ChildProcess } from 'node:child_process';
import type { Server } from 'node:http';
import { pool, verifyDatabase } from './db';
import { configuredPort, SCANNER_PORT, scannerReady, waitForScanner } from './flaskBridge';
import { startScheduler } from './scheduler';
import type { Express } from 'express';
import { validateFindingsConfiguration, findingsReady, type FindingsStorage } from './findingsStorage';
import { findingsAlerts } from './findingsAlerts';
import { acquireFindingsWriter, writerStartupPolicy } from './findingsStartup';

export async function startApplication(app: Express) {
  let scanner: ChildProcess | undefined;
  let server: Server | undefined;
  let scannerStopped = true;
  let stopping = false;
  let stopScheduler = () => {};
  let findings: FindingsStorage | undefined;
  let pendingStorage: Promise<FindingsStorage | undefined> | undefined;
  let applicationReady = false;
  const shutdown = new AbortController();
  const readyForRequests = () => applicationReady && !stopping && !scannerStopped && findingsReady();

  async function stop(code = 0) {
    if (stopping) return;
    stopping = true;
    applicationReady = false;
    shutdown.abort();
    stopScheduler();
    // Also bound shutdown if a scan or a dependency never finishes.
    const forced = setTimeout(() => {
      scanner?.kill('SIGKILL');
      process.exit(code);
    }, 5000);
    forced.unref();
    const closed = server ? new Promise<void>(resolve => {
      server!.close(() => resolve());
      server!.closeIdleConnections();
    }) : Promise.resolve();
    const exited = scanner && !scannerStopped ? new Promise<void>(resolve => {
      scanner!.once('exit', () => resolve());
      scanner!.kill('SIGTERM');
    }) : Promise.resolve();
    await Promise.all([closed, exited, pool.end()]);
    // A SIGTERM while acquiring/restoring must not strand a new writer session.
    await (await pendingStorage?.catch(() => undefined))?.close();
    await findings?.close();
    clearTimeout(forced);
    process.exit(code);
  }
  process.once('SIGTERM', () => void stop());
  process.once('SIGINT', () => void stop());

  // Health is independent of Clerk and never exposes database configuration.
  app.get('/health', async (_req, res) => {
    let database = false;
    try { await verifyDatabase(); database = true; } catch {}
    const scanner = !scannerStopped && findingsReady() && await scannerReady();
    const ready = readyForRequests() && database && scanner;
    res.setHeader('Cache-Control', 'no-store');
    if (!ready) res.setHeader('Retry-After', '2');
    res.status(ready ? 200 : 503).json({
      status: ready ? 'ok' : 'unavailable', version: '3.0',
      dependencies: { database: database ? 'ready' : 'unavailable', scanner: scanner ? 'ready' : 'unavailable' },
      ...(!ready ? { error: 'Writer or scanner not ready. Please retry.' } : {}),
    });
  });

  // Install before authentication, provisioning, quota reservations and all API
  // routes: no request can touch SQLite or consume scan quota during handoff.
  app.use('/api', (_req, res, next) => {
    if (readyForRequests()) return next();
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Retry-After', '2');
    res.status(503).json({ error: 'Writer not ready. Please retry.', code: 'WRITER_NOT_READY' });
  });

  return async () => {
    try {
      const port = configuredPort(process.env.VATA_PORT, 5000);
      if (port === SCANNER_PORT) throw new Error('Public gateway and private scanner ports must differ.');
      if (!process.env.JWT_SECRET && !process.env.SESSION_SECRET) {
        throw new Error('Set JWT_SECRET or SESSION_SECRET before starting the private scanner.');
      }
      validateFindingsConfiguration();
      const policy = writerStartupPolicy();
      await verifyDatabase();
      if (stopping) return;
      // Replit probes /. Serve frontend liveness before waiting for the old
      // revision's writer lock; /health and /api remain honestly unavailable.
      await new Promise<void>((resolve, reject) => {
        server = app.listen(port, '0.0.0.0', () => resolve());
        server.once('error', reject);
      });
      console.log(`VATA frontend listening on port ${port}; scanner APIs are warming up.`);
      pendingStorage = acquireFindingsWriter(shutdown.signal, policy);
      findings = await pendingStorage;
      if (stopping) return;
      // Importing app.py initializes SQLite. Never spawn it before ownership and
      // snapshot restore, even though the public frontend is already listening.
      scannerStopped = false;
      scanner = spawn('gunicorn', [
        '--bind', `127.0.0.1:${SCANNER_PORT}`, '--workers', '1', '--threads', '4', '--timeout', '120', 'app:app',
      ], { stdio: 'inherit', env: { ...process.env, VATA_PORT: String(SCANNER_PORT), PORT: String(SCANNER_PORT), VATA_AUTH_BRIDGE_ENABLED: '1' } });
      scanner.once('error', () => {
        scannerStopped = true;
        console.error('Private scanner could not start. Check that Gunicorn and Python dependencies are installed.');
        void stop(1);
      });
      scanner.once('exit', () => {
        scannerStopped = true;
        if (!stopping) {
          console.error('Private scanner stopped unexpectedly. Check Python dependencies and DB_FILE access.');
          void stop(1);
        }
      });
      await waitForScanner(() => scannerStopped || stopping);
      // Persist any compatible SQLite schema additions before opening traffic.
      if (findings) await findings.run(async () => {});
      if (stopping) return;
      applicationReady = true;
      console.log(`VATA listening on port ${port}; PostgreSQL and private scanner are ready.`);
      stopScheduler = startScheduler();
    } catch (error) {
      if (stopping) return;
      // Database/schema failure can occur before the storage coordinator opens.
      const mode = process.env.VATA_SQLITE_DURABILITY ?? (process.env.NODE_ENV === 'production' ? 'postgres' : 'local');
      if (mode !== 'local' && !findings) findingsAlerts.fail('startup_failed');
      console.error(error instanceof Error ? error.message : 'Application startup failed.');
      await stop(1);
    }
  };
}
