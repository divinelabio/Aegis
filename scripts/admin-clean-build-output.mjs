#!/usr/bin/env node
import { existsSync, mkdirSync, rmSync } from 'node:fs';
import path from 'node:path';

const generatedRoot = path.join(process.cwd(), 'web', 'admin', 'dist', 'js');

if (existsSync(generatedRoot)) {
  rmSync(generatedRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
mkdirSync(generatedRoot, { recursive: true });

