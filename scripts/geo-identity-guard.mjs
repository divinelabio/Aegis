import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve('internal');
const violations = [];

function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full);
    else if (entry.name.endsWith('.go') && !entry.name.endsWith('_test.go')) {
      const normalized = full.split(path.sep).join('/');
      if (normalized.endsWith('telemetry/geoip.go') || normalized.endsWith('telemetry/mmdb.go')) continue;
      const source = fs.readFileSync(full, 'utf8');
      if (/MockCountryLookup|LookupCountryFromMMDB/.test(source)) violations.push(`${full}: production mock GeoIP lookup`);
      if (/Header\.Get\(["']X-Aegis-Country["']\)/.test(source)) violations.push(`${full}: country read from spoofable header`);
    }
  }
}

walk(root);
if (violations.length) {
  console.error(violations.join('\n'));
  process.exit(1);
}
