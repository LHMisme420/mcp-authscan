import { spawn } from 'child_process';
import path from 'path';

export function startFlask() {
  const flaskApp = path.join(process.cwd(), 'app.py');
  
  console.log('[Flask] Starting Flask on port 5001...');
  
  const flask = spawn('gunicorn', [
    '--bind', '127.0.0.1:5001',
    '--workers', '1',
    '--timeout', '120',
    'app:app'
  ], {
    cwd: process.cwd(),
    stdio: 'inherit',
    env: { ...process.env, PYTHONUNBUFFERED: '1' }
  });
  
  flask.on('error', (err) => {
    console.error('[Flask] Failed to start:', err);
  });
  
  return flask;
}
