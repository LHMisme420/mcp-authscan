import { spawn, type ChildProcess } from 'node:child_process';
import type { Server } from 'node:http';
import { pool, verifyDatabase } from './db';
import { configuredPort, SCANNER_PORT, scannerReady, waitForScanner } from './flaskBridge';
import { startScheduler } from './scheduler';
import type { Express } from 'express';
import { prepareFindingsStorage, findingsReady, type FindingsStorage } from './findingsStorage';
import { findingsAlerts } from './findingsAlerts';

export async function startApplication(app: Express) {
  let scanner: ChildProcess | undefined;
  let server: Server | undefined;
  let scannerStopped = true;
  let stopping = false;
  let stopScheduler = () => {};
  let findings: FindingsStorage | undefined;

  async function stop(code = 0) {
    if (stopping) return;
    stopping = true;
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
    const ready = !stopping && database && scanner;
    res.setHeader('Cache-Control', 'no-store');
    res.status(ready ? 200 : 503).json({
      status: ready ? 'ok' : 'unavailable', version: '3.0',
      dependencies: { database: database ? 'ready' : 'unavailable', scanner: scanner ? 'ready' : 'unavailable' },
    });
  });

  return async () => {
    try {
      const port = configuredPort(process.env.VATA_PORT, 5000);
      if (port === SCANNER_PORT) throw new Error('Public gateway and private scanner ports must differ.');
      if (!process.env.JWT_SECRET && !process.env.SESSION_SECRET) {
        throw new Error('Set JWT_SECRET or SESSION_SECRET before starting the private scanner.');
      }
      await verifyDatabase();
      findings = await prepareFindingsStorage();
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
      await new Promise<void>((resolve, reject) => {
        server = app.listen(port, '0.0.0.0', () => resolve());
        server.once('error', reject);
      });
      console.log(`VATA listening on port ${port}; PostgreSQL and private scanner are ready.`);
      stopScheduler = startScheduler();
    } catch (error) {
      // Database/schema failure can occur before the storage coordinator opens.
      const mode = process.env.VATA_SQLITE_DURABILITY ?? (process.env.NODE_ENV === 'production' ? 'postgres' : 'local');
      if (mode !== 'local' && !findings) findingsAlerts.fail('startup_failed');
      console.error(error instanceof Error ? error.message : 'Application startup failed.');
      await stop(1);
    }
  };
}
