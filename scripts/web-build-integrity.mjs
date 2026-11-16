import { createHash } from 'node:crypto';
import { readdir, readFile, lstat } from 'node:fs/promises';
import path from 'node:path';

export const frontendModules = [
  'client/src/main.tsx', 'client/src/App.tsx',
  'client/src/Assessments.tsx', 'client/src/RequestAssessment.tsx',
];
export const serverModules = ['server/index.ts', 'server/assessmentInquiry.ts', 'shared/assessmentInquiry.ts'];
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const fail = message => { throw new Error(`WEB_BUILD_INTEGRITY: ${message}`); };

async function filesIn(root, directory) {
  const files = [];
  for (const entry of (await readdir(path.join(root, directory), { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name, 'en'))) {
    const name = `${directory}/${entry.name}`;
    if (entry.isSymbolicLink()) fail(`Symlink is not a supported release input: ${name}`);
    if (entry.isDirectory()) files.push(...await filesIn(root, name));
    else if (entry.isFile()) files.push(name);
  }
  return files;
}

async function fingerprints(root, files) {
  const result = {};
  for (const name of [...files].sort()) {
    if (!(await lstat(path.join(root, name))).isFile()) fail(`Expected a regular file: ${name}`);
    result[name] = hash(await readFile(path.join(root, name)));
  }
  return result;
}

/** Hash actual staged bytes, not a Git revision label or the old compiled output. */
export async function sourceSnapshot(root) {
  const files = [
    'package.json', 'package-lock.json', 'vite.config.ts', 'client/index.html',
    'app.py', 'requirements-runtime.txt', '.replitignore',
    'mcp_authscan/report_verify.py', 'mcp_authscan/scan_report.py',
    'mcp_authscan/findings_schema.py', 'mcp_authscan/monolith.py',
    'mcp_authscan/scanner.py', 'mcp_authscan/repository_scan.py',
    'scripts/deployment-build.sh', 'scripts/deployment-web.mjs',
    'scripts/build-web.mjs', 'scripts/web-build-integrity.mjs',
    ...await filesIn(root, 'client/src'),
    ...await filesIn(root, 'client/public'),
    ...await filesIn(root, 'server'),
    ...await filesIn(root, 'shared'),
  ];
  const inputs = await fingerprints(root, files);
  return { fingerprint: hash(JSON.stringify(inputs)), files: inputs };
}

export async function assertSource(root, expected) {
  const snapshot = await sourceSnapshot(root);
  if (expected && !/^[a-f0-9]{64}$/.test(expected)) fail('Expected source fingerprint must be a SHA-256 digest.');
  if (expected && expected !== snapshot.fingerprint) {
    // File hashes, not contents, allow a failed publish's actual staging inputs
    // to be compared with the approved workspace inventory.
    console.error(JSON.stringify({ event: 'web_build_source_mismatch', actual: snapshot }));
    fail(`Staged source differs from the approved publish fingerprint. Expected ${expected}; got ${snapshot.fingerprint}. No build or database operation was started.`);
  }
  const app = await readFile(path.join(root, 'client/src/App.tsx'), 'utf8');
  for (const [route, component] of [['/assessments', 'Assessments'], ['/request-assessment', 'RequestAssessment']]) {
    if (!app.includes(`path="${route}" component={${component}}`)) fail(`Missing actual route binding: ${route}`);
  }
  const server = await readFile(path.join(root, 'server/index.ts'), 'utf8');
  if (!server.includes("app.use('/contact', assessmentInquiryRoutes())")) fail('Inquiry router is not mounted.');
  const handler = await readFile(path.join(root, 'server/assessmentInquiry.ts'), 'utf8');
  if (!/router\.post\(\s*['"]\/assessment['"]/.test(handler)) fail('Inquiry POST handler is missing.');
  return snapshot;
}

export async function artifactSnapshot(root) {
  return fingerprints(root, [...await filesIn(root, 'build/client'), 'build/server/index.js']);
}

export async function assertArtifacts(root, graphs) {
  for (const [modules, actual] of [[frontendModules, graphs.frontend], [serverModules, graphs.server]]) {
    for (const name of modules) if (!actual?.includes(name)) fail(`Required module was not compiled: ${name}`);
  }
  const html = await readFile(path.join(root, 'build/client/index.html'), 'utf8');
  const scripts = [...html.matchAll(/<script\b[^>]*\bsrc="(\/assets\/[^"]+\.js)"/g)].map(match => match[1]);
  if (!scripts.length) fail('Built HTML has no local JavaScript entry.');
  let client = '';
  for (const name of scripts) {
    if (!/^\/assets\/[A-Za-z0-9_.-]+\.js$/.test(name)) fail('Unexpected script output path.');
    client += await readFile(path.join(root, 'build/client', name.slice(1)), 'utf8');
  }
  for (const marker of [
    '/assessments', '/request-assessment', '/sample-assessment',
    'Email us to request an assessment', 'mailto:lhmisme2011@gmail.com',
    '/assessment', '1750 dollars', '3500 dollars', '2500 dollars',
    'Independent MCP security assessments', 'Single-server assessment',
    'Expanded assessment', 'Single-server assessment with publication',
    'No mandatory call is part of any assessment.',
    'Synthetic Demonstration — Not a Real Client Assessment.',
    'MCP security assessment your buyer',
    'How the report stands up', 'MATCH', 'DIVERGENCE', 'NOT REPRODUCIBLE',
  ]) if (!client.includes(marker)) fail(`Generated frontend lacks required content: ${marker}`);
  if (client.includes('https://buy.stripe.com/')) fail('Generated frontend includes a retired recurring checkout link.');
  if (!html.includes('Independent MCP Security Assessments | MCP AuthScan')) fail('Generated HTML uses an old homepage template.');
  const server = await readFile(path.join(root, 'build/server/index.js'), 'utf8');
  if (!/app\.use\(["']\/contact["'],\s*assessmentInquiryRoutes\(\)\)/.test(server) ||
      !/router\.post\(\s*["']\/assessment["']/.test(server) ||
      !server.includes('/assessment/status') || !server.includes('INQUIRY_DELIVERY_UNAVAILABLE')) {
    fail('Generated server lacks the mounted inquiry delivery handler.');
  }
  return scripts;
}

export async function verifyRelease(root) {
  const release = JSON.parse(await readFile(path.join(root, 'build/release-manifest.json'), 'utf8'));
  if (release.schemaVersion !== 1) fail('Missing or unsupported release manifest.');
  const current = await assertSource(root, release.source.fingerprint);
  if (!same(current.files, release.source.files)) fail('Source inventory differs from the verified build.');
  await assertArtifacts(root, release.graphs);
  if (!same(await artifactSnapshot(root), release.artifacts)) fail('Built files changed after verification.');
  return release;
}
