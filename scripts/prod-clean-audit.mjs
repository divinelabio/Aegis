#!/usr/bin/env node
import { existsSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';

const root = process.cwd();

const ignoredDirs = new Set([
  '.agents',
  '.git',
  'node_modules',
  'pgdata',
  'rules',
  'data/rules',
  'web/admin/tests'
]);

const forbiddenExact = new Set([
  '.agent',
  '.env',
  '.vscode',
  'aegis',
  'aegis.exe',
  'aegis-server',
  'aegis-server.exe',
  'cookies.txt',
  'cmd/aegis-server/aegis',
  'cmd/aegis-server/aegis-server',
  'data/alerts-state.json',
  'data/license/identity.json',
  'data/routes.json',
  'server.crt',
  'server.key',
  'skills-lock.json',
  'test_output.txt'
]);

const forbiddenRootFile = [
  /^fix_.*\.(?:js|py)$/i,
  /^strip_glows\.py$/i,
  /^.*\.(?:png|jpe?g|webp|gif)$/i
];

const forbiddenAnyPath = [
  /^\.agent(?:\/|$)/,
  /^\.playwright-mcp(?:\/|$)/,
  /^\.vscode(?:\/|$)/,
  /^logs(?:\/|$)/,
  /(?:^|\/)test-results(?:\/|$)/,
  /(?:^|\/)playwright-report(?:\/|$)/,
  /(?:^|\/)coverage(?:\/|$)/,
  /^data\/[^/]+\.(?:jsonl|gz)$/i,
  /(?:^|\/)[^/]*\.test\.exe$/i,
  /(?:^|\/)[^/]*\.(?:pprof|prof|trace)$/i,
  /^\.tmp\/.+/,
  /(?:^|\/)[^/]+\.(?:log|out)$/i,
  /(?:^|\/)[^/]+\.(?:crt|key|pem|p12|pfx)$/i
];

function toPosix(file) {
  return file.split(path.sep).join('/');
}

function shouldSkipDir(relativePath) {
  const parts = relativePath.split('/');
  return parts.some((part) => ignoredDirs.has(part));
}

function walk(dir) {
  const files = [];
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    const relativePath = toPosix(path.relative(root, full));
    let stat;
    try {
      stat = statSync(full);
    } catch (error) {
      if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
        continue;
      }
      throw error;
    }
    if (stat.isDirectory()) {
      if (!shouldSkipDir(relativePath)) {
        files.push(...walk(full));
      } else if (relativePath === '.playwright-mcp') {
        files.push(relativePath);
      }
      continue;
    }
    files.push(relativePath);
  }
  return files;
}

function isForbidden(file) {
  if (forbiddenExact.has(file)) return true;
  if (!file.includes('/') && forbiddenRootFile.some((pattern) => pattern.test(file))) return true;
  return forbiddenAnyPath.some((pattern) => pattern.test(file));
}

if (!existsSync(root)) {
  console.error(`prod-clean-audit: root does not exist: ${root}`);
  process.exit(1);
}

const findings = walk(root).filter(isForbidden).sort();

if (findings.length > 0) {
  console.error('prod-clean-audit: remove local/non-production artifacts:');
  for (const file of findings) {
    console.error(` - ${file}`);
  }
  process.exit(1);
}

console.log('prod-clean-audit: OK');
