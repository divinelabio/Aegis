import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import { randomUUID } from 'node:crypto';

const destination = process.argv[2] || 'sbom.cdx.json';
const raw = execFileSync('go', ['list', '-m', '-json', 'all'], { encoding: 'utf8' });
const modules = [];
let depth = 0;
let current = '';
for (const line of raw.split(/\r?\n/)) {
  if (!line.trim()) continue;
  current += line + '\n';
  for (const ch of line) {
    if (ch === '{') depth++;
    else if (ch === '}') depth--;
  }
  if (depth === 0 && current.trim()) {
    try {
      modules.push(JSON.parse(current));
    } catch (_) {}
    current = '';
  }
}
const components = modules.map(module => ({
  type: 'library',
  name: module.Path,
  version: module.Version || 'local',
  'bom-ref': `pkg:golang/${module.Path}@${module.Version || 'local'}`,
  purl: `pkg:golang/${module.Path}@${module.Version || 'local'}`
}));
const sbom = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  serialNumber: `urn:uuid:${randomUUID()}`,
  version: 1,
  metadata: { timestamp: new Date().toISOString(), component: components[0] },
  components: components.slice(1)
};
fs.writeFileSync(destination, JSON.stringify(sbom, null, 2));
