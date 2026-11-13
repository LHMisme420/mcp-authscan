import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { assertSource, assertArtifacts, artifactSnapshot, verifyRelease } from './web-build-integrity.mjs';

export const root = fileURLToPath(new URL('../', import.meta.url));

export async function buildWeb(expected) {
  // Do not resolve inputs from the caller's CWD or accept an alternate Vite root.
  const source = await assertSource(root, expected);
  console.log(JSON.stringify({ event: 'web_build_source', fingerprint: source.fingerprint, files: Object.keys(source.files).length }));
  await rm(path.join(root, 'build'), { recursive: true, force: true });
  const { build: viteBuild } = await import('vite');
  const { build: esbuild } = await import('esbuild');
  const modules = new Set();
  await viteBuild({
    configFile: path.join(root, 'vite.config.ts'),
    root: path.join(root, 'client'),
    build: { outDir: path.join(root, 'build/client'), emptyOutDir: true },
    plugins: [{
      name: 'verify-release-module-graph',
      generateBundle(_options, bundle) {
        for (const chunk of Object.values(bundle)) {
          if (chunk.type !== 'chunk') continue;
          for (const [id, rendered] of Object.entries(chunk.modules)) {
            if (rendered.renderedLength > 0) modules.add(path.relative(root, id.split('?')[0]).replaceAll(path.sep, '/'));
          }
        }
      },
    }],
  });
  const result = await esbuild({
    absWorkingDir: root, entryPoints: ['server/index.ts'], bundle: true,
    packages: 'external', platform: 'node', format: 'esm',
    outfile: 'build/server/index.js', metafile: true, logLevel: 'info',
  });
  const graphs = { frontend: [...modules].sort(), server: Object.keys(result.metafile.inputs).sort() };
  const scripts = await assertArtifacts(root, graphs);
  // A mid-build edit invalidates the release, rather than mixing two snapshots.
  await assertSource(root, source.fingerprint);
  let gitCommit = null;
  try { gitCommit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch {}
  const release = {
    schemaVersion: 1, builtAt: new Date().toISOString(),
    gitCommit, source, graphs, artifacts: await artifactSnapshot(root),
  };
  await mkdir(path.join(root, 'build'), { recursive: true });
  await writeFile(path.join(root, 'build/release-manifest.json'), JSON.stringify(release, null, 2) + '\n');
  await verifyRelease(root);
  console.log(JSON.stringify({ event: 'web_build_verified', fingerprint: source.fingerprint, scripts, gitCommit }));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { await buildWeb(process.env.VATA_EXPECTED_WEB_SOURCE); }
  catch (error) {
    await rm(path.join(root, 'build/release-manifest.json'), { force: true });
    console.error(error instanceof Error ? error.message : 'Web build verification failed.');
    process.exitCode = 1;
  }
}
