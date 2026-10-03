import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import path from 'node:path';

function runtimeFiles(root, prefix = '') {
  if (!existsSync(root)) return [];
  return readdirSync(root, { withFileTypes: true }).flatMap(entry => {
    const relative = path.join(prefix, entry.name);
    return entry.isDirectory()
      ? runtimeFiles(path.join(root, entry.name), relative)
      : entry.name.endsWith('.js') ? [relative] : [];
  });
}

// Compare current files with compiler output, independently of Git staging,
// commits, or the checkout's CRLF settings. Do not rewrite either directory.
export function compareRuntimeOutputs(expectedRoot, actualRoot) {
  const files = new Set([...runtimeFiles(expectedRoot), ...runtimeFiles(actualRoot)]);
  return [...files].sort().filter(relative => {
    const expected = path.join(expectedRoot, relative);
    const actual = path.join(actualRoot, relative);
    if (!existsSync(expected) || !existsSync(actual)) return true;
    return readFileSync(expected, 'utf8').replace(/\r\n/g, '\n') !== readFileSync(actual, 'utf8').replace(/\r\n/g, '\n');
  }).map(relative => relative.split(path.sep).join('/'));
}

export function checkGeneratedAdminRuntime(root) {
  const workspace = path.resolve(root);
  const temporaryOutput = mkdtempSync(path.join(workspace, '.admin-runtime-check-'));
  try {
    execFileSync(process.execPath, [path.join(workspace, 'node_modules', 'typescript', 'bin', 'tsc'),
      '-p', path.join(workspace, 'config', 'tsconfig.admin.json'), '--outDir', temporaryOutput, '--noEmitOnError', 'true'],
    { cwd: workspace, stdio: 'inherit' });
    return compareRuntimeOutputs(temporaryOutput, path.join(workspace, 'web', 'admin', 'dist', 'js'));
  } finally {
    // Only the fresh directory produced by mkdtemp may be removed.
    if (path.dirname(temporaryOutput) !== workspace || !path.basename(temporaryOutput).startsWith('.admin-runtime-check-')) {
      throw new Error('Refusing to remove an unexpected compiler output directory.');
    }
    rmSync(temporaryOutput, { recursive: true, force: true });
  }
}
