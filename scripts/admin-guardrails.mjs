#!/usr/bin/env node
import { execSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const adminRoot = path.join(root, 'web', 'admin');
const generatedJsRoot = path.join(adminRoot, 'dist', 'js');
const srcRoot = path.join(adminRoot, 'src');
const indexHtml = path.join(adminRoot, 'index.html');
const inlineHandlerPattern = /\bon(?:click|change|submit|keydown)\s*=/g;
const windowAssignmentPattern = /window\.[A-Za-z0-9_]+\s*=/g;
const directDomPattern = /document\.(?:getElementById|querySelector|querySelectorAll)\s*\(/g;
const legacySectionClassPrefixPattern = /class\s*=\s*["'][^"']*\b(?<!edge-)(?:access|antibot|waf|traffic)-[a-z0-9-]+/i;
const legacySectionSelectorPrefixPattern = /\.(?<!edge-)access-[a-z0-9-]+/i;
const malformedSharedClassPattern = /\bsection-section-[a-z0-9-]+\b/i;
const deprecatedSectionSelectorPattern = /\.(?:modal-list-item|geo-region-(?:grid|card|icon|info|name|code|check)|geo-items?|geo-code)\b/i;
const deprecatedSharedClassTokenPattern = /class\s*=\s*["'][^"']*(?<![A-Za-z0-9-])(?:settings-input|form-control|switch|slider|radio-card|mode-card|badge|status-badge|form-group|form-label|section-form-control|section-form-input|preset-row|preset-check|preset-main|preset-head|preset-title-row|preset-path|preset-new-badge|preset-strategy-badge|preset-desc|bot-toggle-group|bot-toggle-btn|bl-(?:primary|info|muted|warning)|switch-row|algo-card|blacklist-row|badge-primary|badge-warning|condition-row|cr-zone|cr-operator|cr-field|cr-pattern|cr-transform|cr-negate|edit-policy-method|dynamic-basic-settings|mode-grid|selection-card|selection-list|selection-row|region-checkbox|country-checkbox|range-primary|range-warning|input-stack|input-main|input-addon(?:-tight)?|select-addon|radio-accent|panel-soft|glass-hero|vip-card|vip-icon|alert-danger-soft|alert-success-soft|hero-pattern|icon-chip|code-tag|glass-card|provider-card|banner-primary|banner-icon|banner-title|banner-sub)(?![A-Za-z0-9-])[^"']*["']/i;

const directDomAllowlist = new Set([
  'about.ts',
  'alerts.ts',
  'auth/login.ts',
  'auth/reset-confirm.ts',
  'auth/reset-request.ts',
  'core/dom.ts',
  'dashboards/index.ts',
  'dashboards/system.ts',
  'dashboards/traffic.ts',
  'dashboards/waf.ts',
  'modules/captcha-config.ts',
  'modules/challenge-config.ts',
  'modules/reputation-config.ts',
  'sections/antibots-config-shared.ts',
  'sections/apisecurity-config.ts',
  'sections/apisecurity/config-runtime.ts',
  'sections/httpsecurity-config.ts',
  'sections/ui-components.ts',
  'setup-wizard.ts',
  'routes.ts',
  'settings.ts',
  'ssl.ts',
  'upstreams.ts'
]);

function walkFiles(dir) {
  if (!existsSync(dir)) return [];
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    let st;
    try {
      st = statSync(full);
    } catch (error) {
      if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
        continue;
      }
      throw error;
    }
    if (st.isDirectory()) {
      out.push(...walkFiles(full));
    } else {
      out.push(full);
    }
  }
  return out;
}

function rel(file) {
  return file.split(path.sep).join('/').replace(`${root}/`, '');
}

function fail(message) {
  console.error(`admin-guardrails: ${message}`);
  process.exit(1);
}

try {
  execSync('node scripts/prod-clean-audit.mjs', { stdio: 'inherit' });
} catch {
  process.exit(1);
}

if (existsSync(path.join(root, 'scripts', 'httpsecurity-ui-contract.mjs'))) {
  try {
    execSync('node scripts/httpsecurity-ui-contract.mjs', { stdio: 'inherit' });
  } catch {
    process.exit(1);
  }
}

const obsoleteArtifacts = walkFiles(adminRoot)
  .map((file) => path.relative(adminRoot, file).split(path.sep).join('/'))
  .filter((file) => /(^|\/)js\.zip$/i.test(file) || /\.(bak|old|orig|snapshot)$/i.test(file))
  .sort();
if (obsoleteArtifacts.length > 0) {
  fail(`Remove obsolete legacy artifacts under web/admin: ${obsoleteArtifacts.join(', ')}`);
}

const adminJsSources = walkFiles(adminRoot)
  .filter((file) => file.endsWith('.js'))
  .map((file) => path.relative(adminRoot, file).split(path.sep).join('/'));

const disallowedAdminJsSources = adminJsSources
  .filter((file) => !file.startsWith('dist/js/'))
  .filter((file) => !file.startsWith('tests/'))
  .sort();

if (disallowedAdminJsSources.length > 0) {
  fail(`Found disallowed JS sources under web/admin (only generated web/admin/dist/js/* and tests are allowed): ${disallowedAdminJsSources.join(', ')}`);
}

const jsFiles = walkFiles(generatedJsRoot)
  .filter((file) => file.endsWith('.js'))
  .map((file) => path.relative(generatedJsRoot, file).split(path.sep).join('/'))
  .filter((file) => !file.startsWith('types/') || !file.endsWith('.d.js'));

const tsSourceFiles = walkFiles(srcRoot)
  .filter((file) => file.endsWith('.ts'))
  .map((file) => path.relative(srcRoot, file).split(path.sep).join('/'));
const cssSourceFiles = walkFiles(path.join(adminRoot, 'css'))
  .filter((file) => file.endsWith('.css'))
  .map((file) => path.relative(adminRoot, file).split(path.sep).join('/'));

const tsRuntimeFiles = tsSourceFiles
  .filter((file) => !file.endsWith('.d.ts'))
  .map((file) => file.replace(/\.ts$/, '.js'));

const protectionModuleStateContracts = [
  {
    file: 'modules/captcha-config.ts',
    status: 'data-captcha-section-status',
    toggle: 'captcha-toggle-enabled'
  },
  {
    file: 'modules/reputation-config.ts',
    status: 'data-reputation-section-status',
    toggle: 'reputation-toggle-enabled'
  }
];

for (const contract of protectionModuleStateContracts) {
  const full = path.join(srcRoot, contract.file);
  const content = readFileSync(full, 'utf8');

  if (!/enabled:\s*false\b/.test(content)) {
    fail(`${rel(full)} must keep disabled as the default top-level protection state`);
  }
  if (/this\.config\.enabled\s*=\s*true\b/.test(content)) {
    fail(`${rel(full)} must not force-enable protection during load or save`);
  }
  if (!content.includes(contract.status) || !content.includes(contract.toggle)) {
    fail(`${rel(full)} must render a state-bound top-level status and switch`);
  }
  if (!content.includes("SectionUI.markSaveActionBarDirty('data-action')")) {
    fail(`${rel(full)} must stage top-level protection changes through the shared Save bar`);
  }
}

const reputationConfigSource = readFileSync(path.join(srcRoot, 'modules', 'reputation-config.ts'), 'utf8');
if (/<strong>Engine<\/strong>\s*Active/.test(reputationConfigSource)
  || !reputationConfigSource.includes('data-reputation-engine-status')) {
  fail('modules/reputation-config.ts must not present a disabled engine as active');
}

if (existsSync(path.join(srcRoot, 'sections', 'apisecurity', 'config-runtime.ts'))) {
  const apiSecurityConfigSource = readFileSync(path.join(srcRoot, 'sections', 'apisecurity', 'config-runtime.ts'), 'utf8');
  if (!apiSecurityConfigSource.includes('role="button" tabindex="0" data-api-security-action="open-policy-detail"')
    || !apiSecurityConfigSource.includes("'keydown', '[data-api-security-action=\"open-policy-detail\"]'")
    || !apiSecurityConfigSource.includes("APISecurityConfig.openPolicyDetail(target.dataset.apiPolicyId || '');")) {
    fail('API Security policy overview rows must remain keyboard-operable');
  }
}

const trafficConfigSource = readFileSync(path.join(srcRoot, 'sections', 'traffic-config.ts'), 'utf8');
if (!trafficConfigSource.includes('role="button" tabindex="0" data-traffic-action="switch-tab"')
  || !trafficConfigSource.includes("'keydown', '[data-traffic-action=\"switch-tab\"][role=\"button\"]'")
  || !trafficConfigSource.includes("event.key !== 'Enter' && event.key !== ' '")
  || !trafficConfigSource.includes('target.click();')) {
  fail('Traffic Control custom overview rows must remain keyboard-operable');
}

if (existsSync(path.join(srcRoot, 'sections', 'antibots-render-overview-tab.ts'))) {
  const antibotOverviewSource = readFileSync(path.join(srcRoot, 'sections', 'antibots-render-overview-tab.ts'), 'utf8');
  if (!antibotOverviewSource.includes('class="bot-event-toggle"')
    || !antibotOverviewSource.includes('aria-expanded="${expanded}"')
    || !antibotOverviewSource.includes('aria-controls="${escapeAttr(detailId)}"')
    || !antibotOverviewSource.includes('id="${escapeAttr(detailId)}" class="bot-event-detail compact"')) {
    fail('Bot Protection event details must remain keyboard-operable');
  }
}

if (existsSync(path.join(srcRoot, 'sections', 'antibots-render-basic-tabs.ts'))) {
  const antibotBasicTabsSource = readFileSync(path.join(srcRoot, 'sections', 'antibots-render-basic-tabs.ts'), 'utf8');
  if (!antibotBasicTabsSource.includes('<button type="button" class="section-fp-card')
    || !antibotBasicTabsSource.includes('aria-pressed="${mode === m.id}"')) {
    fail('Bot Protection fingerprint presets must remain native pressed buttons');
  }
}

const responseProtectionSource = readFileSync(path.join(srcRoot, 'sections', 'httpsecurity', 'render-response-protection.ts'), 'utf8');
if (!responseProtectionSource.includes('data-httpsec-action="save-securitytxt">Save Changes</button>')) {
  fail('Security.txt must use the canonical Save Changes action label');
}

const settingsBackupButtonContracts = [
  { marker: '<button type="button" class="btn btn-outline" data-settings-action="create-backup">Download</button>', label: 'backup download' },
  { marker: '<button type="button" class="btn btn-outline" data-settings-action="export-config">Export</button>', label: 'config export' },
  { marker: '<button type="button" class="btn btn-outline" data-import-target="import-file">Import</button>', label: 'config import' },
  { marker: '<button type="button" class="btn btn-danger" data-settings-action="factory-reset">Reset</button>', label: 'factory reset' }
];
const settingsSource = readFileSync(path.join(srcRoot, 'settings.ts'), 'utf8');
for (const contract of settingsBackupButtonContracts) {
  if ((settingsSource.split(contract.marker).length - 1) !== 1) {
    fail(`settings.ts must expose one native ${contract.label} action`);
  }
}

const ruleEditorTabContracts = [
  { marker: '<button type="button" class="editor-tab ${this.activeTab === \'visual\' ? \'active\' : \'\'}" data-rule-editor-action="switch-tab" data-rule-tab="visual">', label: 'Visual Builder' },
  { marker: '<button type="button" class="editor-tab ${this.activeTab === \'source\' ? \'active\' : \'\'}" data-rule-editor-action="switch-tab" data-rule-tab="source">', label: 'YAML Configuration' },
  { marker: '<button type="button" class="editor-tab ${this.activeTab === \'test\' ? \'active\' : \'\'}" data-rule-editor-action="switch-tab" data-rule-tab="test">', label: 'Request Tester' }
];
const ruleEditorSource = readFileSync(path.join(srcRoot, 'rule-editor.ts'), 'utf8');
for (const contract of ruleEditorTabContracts) {
  if ((ruleEditorSource.split(contract.marker).length - 1) !== 1) {
    fail(`rule-editor.ts must expose one native ${contract.label} tab`);
  }
}

const ruleEditorActionButtonContracts = [
  { marker: '<button type="button" class="btn btn-primary" data-rule-editor-action="save-file">', label: 'Save Policy' },
  { marker: '<button type="button" class="btn btn-xs btn-outline" data-rule-editor-action="add-rule" title="Add Rule">+ Add</button>', label: 'Add Rule' },
  { marker: '<button type="button" class="btn btn-sm btn-outline" data-rule-editor-action="duplicate-rule"', label: 'Duplicate Rule' },
  { marker: '<button type="button" class="btn btn-sm btn-outline text-danger" data-rule-editor-action="delete-rule"', label: 'Delete Rule' },
  { marker: '<button type="button" class="btn btn-sm btn-outline" data-rule-editor-action="add-pattern">', label: 'New Pattern' },
  { marker: '<button type="button" class="btn btn-sm btn-outline btn-danger-text" data-rule-editor-action="remove-pattern"', label: 'Remove Pattern' },
  { marker: '<button type="button" class="btn btn-primary" data-rule-editor-action="run-test">Run Test</button>', label: 'Run Test' }
];
for (const contract of ruleEditorActionButtonContracts) {
  if ((ruleEditorSource.split(contract.marker).length - 1) !== 1) {
    fail(`rule-editor.ts must expose one native ${contract.label} action`);
  }
}

const operationalButtonContracts = [
  { file: 'router.ts', marker: '<button type="button" class="btn btn-outline" data-action="refresh-threat-logs">Refresh</button>', label: 'Threat Logs refresh' }
];
for (const contract of operationalButtonContracts) {
  const source = readFileSync(path.join(srcRoot, contract.file), 'utf8').replace(/\r\n/g, '\n');
  if ((source.split(contract.marker).length - 1) !== 1) {
    fail(`${contract.file} must expose one native ${contract.label} control`);
  }
}

const alertAndSecurityEventButtonContracts = [
  { file: 'alerts.ts', marker: '<button type="button" class="btn btn-sm btn-outline btn-xs" data-action="alerts-mark-all-read">Mark all read</button>', label: 'Security Inbox mark all read' },
  { file: 'alerts.ts', marker: '<button type="button" class="btn btn-primary" data-action="alerts-open-route"', label: 'Security Inbox investigate' },
  { file: 'alerts.ts', marker: '<button type="button" class="btn btn-outline" data-action="alerts-close-detail">Close</button>', label: 'Security Inbox detail close' },
  { file: 'alerts.ts', marker: '<button type="button" class="alert-filter-pill ${active}" data-action="alerts-filter"', label: 'Security Inbox filter' },
  { file: 'alerts.ts', marker: '<button type="button" class="btn btn-outline btn-xs" data-action="alerts-open-route"', label: 'Security Inbox row open' },
  { file: 'alerts.ts', marker: '<button type="button" class="btn btn-ghost btn-xs" data-action="alerts-mark-one-read"', label: 'Security Inbox acknowledgement' },
  { file: 'security.ts', marker: '<button type="button" class="btn btn-sm btn-outline security-statistics-modal-close" data-security-analytics-action="close-statistics-modal">Close</button>', label: 'Security Events breakdown close' },
  { file: 'security.ts', marker: '<button type="button" class="btn btn-outline btn-sm" data-security-analytics-action="clear-filters">Clear filters</button>', label: 'Security Events empty-state clear filters' },
  { file: 'security.ts', marker: '<button type="button" class="btn btn-sm btn-outline" data-security-analytics-action="cancel-filter-builder">Cancel</button>', label: 'Security Events filter cancel' },
  { file: 'security.ts', marker: '<button type="button" class="btn btn-sm" data-security-analytics-action="apply-filter-builder">Apply</button>', label: 'Security Events filter apply' }
];
for (const contract of alertAndSecurityEventButtonContracts) {
  const source = readFileSync(path.join(srcRoot, contract.file), 'utf8');
  if ((source.split(contract.marker).length - 1) !== 1) {
    fail(`${contract.file} must expose one native ${contract.label} control`);
  }
}

const antibotOverviewButtonContracts = [
  { marker: '<button type="button" class="btn btn-sm" data-antibot-action="refresh-analytics">Try Again</button>', count: 1, label: 'analytics retry' },
  { marker: '<button type="button" class="btn btn-sm" data-antibot-action="show-add-rule-modal">Create Rule</button>', count: 2, label: 'create rule entry points' },
  { marker: '<button type="button" class="btn btn-outline btn-sm" data-antibot-action="switch-tab" data-antibot-value="rules">Manage Rules</button>', count: 1, label: 'manage rules' },
  { marker: '<button type="button" class="btn btn-outline btn-sm" data-nav-target="module_challenge">Open Smart Challenge</button>', count: 1, label: 'open Smart Challenge' },
  { marker: '<button type="button" class="btn btn-outline btn-sm"\n        data-antibot-action="create-rule-from-event"', count: 1, label: 'create rule recommendation' },
  { marker: '<button type="button" class="btn btn-outline btn-sm"\n        data-antibot-action="add-exception-value"', count: 1, label: 'exception recommendation' },
  { marker: '<button type="button" class="btn btn-outline btn-sm" data-antibot-action="switch-tab" data-antibot-value="${escapeAttr(tab)}">${escapeHtml(label)}</button>', count: 1, label: 'recommendation navigation' }
];
if (existsSync(path.join(srcRoot, 'sections/antibots-render-overview-tab.ts'))) {
  const antibotOverviewButtonsSource = readFileSync(path.join(srcRoot, 'sections/antibots-render-overview-tab.ts'), 'utf8');
  for (const contract of antibotOverviewButtonContracts) {
    if ((antibotOverviewButtonsSource.split(contract.marker).length - 1) !== contract.count) {
      fail(`antibots-render-overview-tab.ts must expose ${contract.count} native ${contract.label} control${contract.count === 1 ? '' : 's'}`);
    }
  }
}

const sectionUIComponentButtonContracts = [
  { marker: '<button type="button" class="operator-btn operator-btn-secondary" ${options.actionAttr}="${options.resetAction}"${resetAttrs}>', label: 'shared Reset action' },
  { marker: '<button type="button" class="operator-btn operator-btn-primary" ${options.actionAttr}="${options.saveAction}"${saveAttrs}>', label: 'shared Save Changes action' },
  { marker: '<button type="button" class="btn btn-outline" data-section-action="run-expression" data-section-expression="${retryExpression}">', label: 'shared Retry action' },
  { marker: '<button type="button" class="operator-line-tab ${tab.id === activeId ? \'is-active\' : \'\'}"', label: 'shared section tab' }
];
const sectionUIComponentSource = readFileSync(path.join(srcRoot, 'sections/ui-components.ts'), 'utf8');
for (const contract of sectionUIComponentButtonContracts) {
  if ((sectionUIComponentSource.split(contract.marker).length - 1) !== 1) {
    fail(`ui-components.ts must expose one native ${contract.label}`);
  }
}

const wafAndSecurityRuleButtonContracts = [
  { file: 'sections/waf-config.ts', marker: '<button type="button" class="btn btn-outline btn-sm section-btn-inline" data-waf-action="add-rule-condition">', count: 1, label: 'WAF add condition' },
  { file: 'sections/waf-config.ts', marker: '<button type="button" class="btn btn-ghost btn-sm text-danger" data-waf-action="delete-exclusion"', count: 1, label: 'WAF exclusion delete' },
  { file: 'sections/waf-config.ts', marker: '<button type="button" class="btn btn-primary btn-sm section-btn-inline" data-waf-action="show-exclusion-modal">', count: 2, label: 'WAF exclusion entry points' },
  { file: 'sections/waf-config.ts', marker: '<button type="button" class="btn btn-ghost" data-waf-action="close-exclusion-modal">Cancel</button>', count: 1, label: 'WAF exclusion cancel' },
  { file: 'sections/waf-config.ts', marker: '<button type="button" class="btn btn-primary" data-waf-action="add-exclusion">Add Exclusion</button>', count: 1, label: 'WAF exclusion create' },
  { file: 'security.ts', marker: '<button type="button" class="btn btn-outline" data-action="close-security-rule-editor">Cancel</button>', count: 1, label: 'Security Rule editor cancel' },
  { file: 'security.ts', marker: '<button type="button" class="btn btn-outline" data-action="save-security-rule" data-rule-id="${current.id || \'\'}" data-save-mode="draft">Save as Draft</button>', count: 1, label: 'Security Rule editor save draft' },
  { file: 'security.ts', marker: '<button type="button" class="btn btn-primary" data-action="save-security-rule" data-rule-id="${current.id || \'\'}">${editing ? \'Deploy changes\' : \'Deploy\'}</button>', count: 1, label: 'Security Rule editor deploy' }
];
for (const contract of wafAndSecurityRuleButtonContracts) {
  const full = path.join(srcRoot, contract.file);
  if (!existsSync(full)) continue;
  const source = readFileSync(full, 'utf8');
  const count = source.split(contract.marker).length - 1;
  if (count !== contract.count) {
    fail(`${contract.file} must expose ${contract.count} native ${contract.label} control${contract.count === 1 ? '' : 's'}`);
  }
}

const securityWorkflowButtonContracts = [
  { file: 'security.ts', marker: '<button type="button" class="btn btn-outline" data-nav-target="${endpoint}">Open Configuration</button>', count: 1, label: 'feature configuration link' },
  { file: 'security.ts', marker: '<button type="button" class="btn btn-outline" data-action="refresh-security-analytics">Retry</button>', count: 1, label: 'Security Events retry' },
  { file: 'sections/antibots-render-rules-tab.ts', marker: '<button type="button" class="btn btn-primary" data-antibot-action="show-add-rule-modal">', count: 1, label: 'Bot Protection create rule' },
  { file: 'sections/antibots-render-rules-tab.ts', marker: '<button type="button" class="btn btn-outline btn-sm" data-antibot-action="show-add-rule-modal">Create First Rule</button>', count: 1, label: 'Bot Protection first rule' },
  { file: 'sections/antibots-render-classification-tab.ts', marker: '<button type="button" class="btn btn-outline section-class-manage-btn" data-antibot-action="show-good-bots-modal">', count: 1, label: 'Bot Protection access-list management' },
  { file: 'sections/httpsecurity/render-payload-basic.ts', marker: '<button type="button" data-httpsec-action="set-field" data-httpsec-path="upload_limit.max_body_size"', count: 1, label: 'App Security payload preset' },
  { file: 'sections/httpsecurity/render-response-protection.ts', marker: '<button type="button" class="btn btn-outline btn-sm" data-httpsec-action="add-tag-from-input" data-httpsec-path="info_hiding.strip_headers" data-httpsec-input-id="strip-hdr-input">Add header</button>', count: 1, label: 'App Security privacy header add' },
  { file: 'sections/httpsecurity/render-response-protection.ts', marker: '<button type="button" data-httpsec-action="add-tag" data-httpsec-path="info_hiding.strip_headers" data-httpsec-value="${encodeHTTPSecurityValue(h)}" class="btn btn-outline btn-xs text-mono">', count: 1, label: 'App Security privacy header suggestion' },
  { file: 'sections/httpsecurity/controls/header-builder.ts', marker: '<button type="button" class="btn btn-outline btn-sm" data-httpsec-action="add-tag-from-input" data-httpsec-path="${path}" data-httpsec-input-id="${inputId}">Add</button>', count: 1, label: 'App Security header builder add' },
  { file: 'sections/httpsecurity/render-request-policy.ts', marker: '<button type="button" class="btn btn-outline btn-sm" data-httpsec-action="add-tag-from-input" data-httpsec-path="host_validator.allowed_hosts" data-httpsec-input-id="host-add-input">Add</button>', count: 1, label: 'App Security host add' }
];
for (const contract of securityWorkflowButtonContracts) {
  const full = path.join(srcRoot, contract.file);
  if (!existsSync(full)) continue;
  const source = readFileSync(full, 'utf8');
  const count = source.split(contract.marker).length - 1;
  if (count !== contract.count) {
    fail(`${contract.file} must expose ${contract.count} native ${contract.label} control${contract.count === 1 ? '' : 's'}`);
  }
}

const remainingDesktopButtonContracts = [
  { file: 'dashboards/system.ts', marker: '<button type="button" class="btn btn-outline btn-sm" data-system-dashboard-action="refresh" aria-busy="false">Refresh</button>', count: 1, label: 'System Health refresh' },
  { file: 'sections/traffic/ratelimit.ts', marker: '<button type="button" class="operator-btn operator-btn-primary flow-rate-add-rule" data-traffic-action="open-add-rate-rule-modal">', count: 1, label: 'Traffic Control route-rule entry' },
  { file: 'sections/edge-access/v2/shell.ts', marker: '<button type="button" class="btn btn-primary" data-section-action="close-modal">Done</button>', count: 2, label: 'Edge Access modal completion' }
];
for (const contract of remainingDesktopButtonContracts) {
  const full = path.join(srcRoot, contract.file);
  if (!existsSync(full)) continue;
  const source = readFileSync(full, 'utf8');
  const count = source.split(contract.marker).length - 1;
  if (count !== contract.count) {
    fail(`${contract.file} must expose ${contract.count} native ${contract.label} control${contract.count === 1 ? '' : 's'}`);
  }
}

const desktopInteractionSemanticsContracts = [
  { file: 'rule-editor.ts', marker: '<button type="button" class="rule-item ${isSelected ? \'selected\' : \'\'}" data-rule-editor-action="select-rule" data-rule-index="${index}" aria-pressed="${isSelected ? \'true\' : \'false\'}">', count: 1, label: 'Rule Editor rule selector' },
  { file: 'rule-editor.ts', marker: '<button type="button" class="btn btn-sm btn-outline btn-danger-text" data-rule-editor-action="remove-pattern" data-pattern-index="${index}" aria-label="Remove detection pattern ${index + 1}"', count: 1, label: 'Rule Editor pattern removal action' },
  { file: 'sections/waf-config.ts', marker: '<button type="button" class="section-profile-row ${isActive ? \'is-active\' : \'\'}" data-waf-action="apply-profile" data-waf-value="${escapeWafHtml(p.id)}" aria-pressed="${isActive ? \'true\' : \'false\'}"', count: 1, label: 'WAF protection-profile selector' },
  { file: 'sections/waf-config.ts', marker: '<button type="button" class="btn btn-ghost btn-sm text-danger" data-waf-action="delete-exclusion" data-waf-value="${escapeWafHtml(ex.id)}"', count: 1, label: 'WAF exclusion removal action' },
  { file: 'alerts.ts', marker: 'const detailButton = `<button type="button" class="btn btn-ghost btn-xs" data-action="alerts-open-detail" data-alert-id="${escapeAttr(alert.id)}">View details</button>`;', count: 1, label: 'Alert detail action' },
  { file: 'alerts.ts', marker: '<article class="alert-item ${!alert.read ? \'unread\' : \'\'} ${alert.unresolved ? \'unresolved\' : \'\'}">', count: 1, label: 'Alert item container' }
];
for (const contract of desktopInteractionSemanticsContracts) {
  const full = path.join(srcRoot, contract.file);
  if (!existsSync(full)) continue;
  const source = readFileSync(full, 'utf8');
  const count = source.split(contract.marker).length - 1;
  if (count !== contract.count) {
    fail(`${contract.file} must expose ${contract.count} semantic ${contract.label} control${contract.count === 1 ? '' : 's'}`);
  }
}

const multilineDesktopButtonContracts = [
  { file: 'sections/antibots-render-rules-tab.ts', marker: '<button type="button" class="section-rule-priority-btn ${isFirst ? \'disabled\' : \'\'}"', count: 1, label: 'Bot Protection move-up control' },
  { file: 'sections/antibots-render-rules-tab.ts', marker: '<button type="button" class="section-rule-priority-btn ${isLast ? \'disabled\' : \'\'}"', count: 1, label: 'Bot Protection move-down control' },
  { file: 'sections/antibots-render-rules-tab.ts', marker: '<button type="button" class="btn-link" data-antibot-action="edit-rule"', count: 1, label: 'Bot Protection edit link' },
  { file: 'sections/antibots-render-rules-tab.ts', marker: 'data-antibot-action="delete-rule"', count: 1, label: 'Bot Protection delete action' },
  { file: 'sections/waf-config.ts', marker: '<button type="button" class="btn-icon section-condition-remove"\n                         data-waf-action="remove-section-condition-row" aria-label="Remove condition">', count: 1, label: 'WAF condition removal' },
  { file: 'sections/waf-config.ts', marker: '<button type="button" class="btn ${negate ? \'btn-danger\' : \'btn-outline\'}"\n                                 data-waf-action="toggle-negate"\n                                 title="Invert match condition" aria-pressed="${negate ? \'true\' : \'false\'}">', count: 1, label: 'WAF negation toggle' },
  { file: 'sections/ui-components.ts', marker: '<button type="button" class="config-section-nav-item ${tab.id === activeId ? \'is-active\' : \'\'}"\n                            ${actionAttr}="${action}" ${valueAttr}="${tab.id}" ${tab.id === activeId ? \'aria-current="page"\' : \'\'}>', count: 1, label: 'shared configuration navigation' },
  { file: 'sections/traffic-config.ts', marker: '<button type="button" class="operator-btn operator-btn-secondary btn-xs"\n                                    ${this.blacklistPagination.page === 1 ? \'disabled\' : \'\'}\n                                    data-traffic-action="blacklist-prev-page">', count: 1, label: 'Traffic Control previous page' },
  { file: 'sections/traffic-config.ts', marker: '<button type="button" class="operator-btn operator-btn-secondary btn-xs"\n                                    ${this.blacklistPagination.page >= totalPages ? \'disabled\' : \'\'}\n                                    data-traffic-action="blacklist-next-page">', count: 1, label: 'Traffic Control next page' },
  { file: 'sections/traffic/ratelimit.ts', marker: '<button type="button" class="operator-btn operator-btn-secondary btn-xs flow-rate-remove-rule"\n                                                data-traffic-action="remove-rate-rule"', count: 1, label: 'Traffic Control route-rule removal' }
];
for (const contract of multilineDesktopButtonContracts) {
  const full = path.join(srcRoot, contract.file);
  if (!existsSync(full)) continue;
  const source = readFileSync(full, 'utf8').replace(/\r\n/g, '\n');
  const count = source.split(contract.marker).length - 1;
  if (count !== contract.count) {
    fail(`${contract.file} must expose ${contract.count} native ${contract.label} control${contract.count === 1 ? '' : 's'}`);
  }
}

const wafRuleEditorLabelContracts = [
  { marker: '<label class="section-form-label" for="cr-id">Rule ID</label>', label: 'Rule ID' },
  { marker: '<label class="section-form-label" for="cr-name">Rule Name</label>', label: 'Rule Name' },
  { marker: '<label class="section-form-label" for="cr-sev">Severity</label>', label: 'Severity' },
  { marker: '<label class="section-form-label" for="cr-msg">Log Message</label>', label: 'Log Message' },
  { marker: '<label class="section-form-label" for="cr-score">Anomaly Score</label>', label: 'Anomaly Score' },
  { marker: '<label class="section-form-label" for="cr-tags">Tags</label>', label: 'Tags' },
  { marker: '<select class="section-condition-zone section-input" aria-label="Zone">', label: 'condition zone' },
  { marker: '<select class="section-condition-operator section-input" aria-label="Match operator">', label: 'condition operator' },
  { marker: '<input type="text" class="section-condition-field section-input" aria-label="Field name"', label: 'condition field' },
  { marker: '<input type="text" class="section-condition-pattern section-input section-pattern-input" aria-label="Match pattern"', label: 'condition pattern' }
];
const wafRuleEditorSource = readFileSync(path.join(srcRoot, 'sections/waf-config.ts'), 'utf8');
for (const contract of wafRuleEditorLabelContracts) {
  if ((wafRuleEditorSource.split(contract.marker).length - 1) !== 1) {
    fail(`sections/waf-config.ts must expose one accessible ${contract.label} field label`);
  }
}

const ruleEditorLabelContracts = [
  { marker: '<label class="form-label" for="rule-id">Rule ID</label>', label: 'Rule ID' },
  { marker: '<label class="form-label" for="rule-score-slider">Score (1-100)</label>', label: 'score slider' },
  { marker: '<input type="number" id="rule-score" value="${rule.score}" min="1" max="100" aria-label="Score value"', label: 'score value' },
  { marker: '<label class="form-label" for="rule-severity">Severity</label>', label: 'Severity' },
  { marker: '<label class="form-label" for="rule-message">Alert Message</label>', label: 'Alert Message' },
  { marker: '<select id="common-patterns" data-rule-editor-action="insert-common-pattern" class="settings-input text-12 w-200" aria-label="Pattern template library">', label: 'pattern template library' },
  { marker: '<input type="text" value="${this.escapeHtml(pattern)}" aria-label="Detection pattern ${index + 1}"', label: 'detection pattern' },
  { marker: '<textarea id="source-code" aria-label="Policy source"', label: 'policy source' },
  { marker: '<select id="test-method" class="settings-input w-120" aria-label="Request method">', label: 'request method' },
  { marker: '<input type="text" id="test-uri" class="settings-input flex-1" aria-label="Request URI"', label: 'request URI' },
  { marker: '<label class="test-label" for="test-headers">Headers (One per line)</label>', label: 'request headers' },
  { marker: '<label class="test-label" for="test-body">Request Body</label>', label: 'request body' }
];
for (const contract of ruleEditorLabelContracts) {
  if ((ruleEditorSource.split(contract.marker).length - 1) !== 1) {
    fail(`rule-editor.ts must expose one accessible ${contract.label} field label`);
  }
}

const closeDialogContracts = [
  { file: 'profile.ts', marker: '<button type="button" data-action="profile-close-mfa-modal" class="modal-close" aria-label="Close login verification setup">', count: 1 },
  { file: 'profile.ts', marker: '<button type="button" class="btn btn-primary" data-action="profile-update-password">Update Password</button>', count: 1 },
  { file: 'profile.ts', marker: '<button type="button" class="btn btn-sm ${mfaEnabled ? \'btn-outline\' : \'btn-primary\'}" data-action="profile-setup-mfa">', count: 1 },
  { file: 'profile.ts', marker: '<button type="button" class="btn btn-outline btn-sm ${mfaEnabled ? \'btn-outline-warning\' : \'\'}" data-action="profile-disable-mfa"', count: 1 },
  { file: 'profile.ts', marker: '<button type="button" class="btn btn-primary w-100" data-action="profile-start-mfa-flow">Begin Pairing</button>', count: 1 },
  { file: 'profile.ts', marker: '<button type="button" class="btn btn-primary" data-action="profile-enable-mfa" id="btn-enable-mfa">Activate</button>', count: 1 },
  { file: 'profile.ts', marker: '<button type="button" class="btn btn-primary w-100" data-action="profile-close-mfa-modal">Done</button>', count: 1 },
  { file: 'sections/ui-components.ts', marker: 'type="button" class="section-confirm-close" data-section-action="close-modal" aria-label="Close dialog"', count: 1 },
  { file: 'sections/ui-components.ts', marker: 'type="button" class="btn btn-outline section-confirm-cancel" data-section-action="close-modal">Cancel</button>', count: 1 },
  { file: 'sections/ui-components.ts', marker: 'type="button" id="${confirmBtnId}" class="btn btn-primary section-confirm-primary', count: 1 },
  { file: 'sections/antibots-render-classification-tab.ts', marker: 'type="button" class="section-modal-close section-goodbot-close" data-antibot-action="close-good-bots-modal" aria-label="Close access list">', count: 1 },
  { file: 'sections/antibots-render-classification-tab.ts', marker: 'type="button" class="btn btn-outline" data-antibot-action="close-good-bots-modal">Done</button>', count: 1 },
  { file: 'sections/traffic-config.ts', marker: 'type="button" class="operator-btn operator-btn-secondary" data-traffic-action="close-modal">Cancel</button>', count: 5 },
  { file: 'sections/traffic-config.ts', marker: 'type="button" class="operator-btn operator-btn-primary" data-traffic-action="save-added-ips"', count: 1 },
  { file: 'sections/traffic-config.ts', marker: 'type="button" class="operator-btn operator-btn-primary" data-traffic-action="save-geo-selection">Save Changes</button>', count: 1 },
  { file: 'sections/traffic-config.ts', marker: 'type="button" class="operator-btn operator-btn-primary" data-traffic-action="save-flood-object">Add object</button>', count: 1 },
  { file: 'sections/traffic-config.ts', marker: 'type="button" class="operator-btn operator-btn-primary" data-traffic-action="save-added-vips">Add scoped exceptions</button>', count: 1 },
  { file: 'sections/traffic-config.ts', marker: 'type="button" class="operator-btn operator-btn-primary" data-traffic-action="save-reputation-rule">Add Override Rule</button>', count: 1 },
  { file: 'sections/traffic-config.ts', marker: 'data-traffic-action="close-modal" aria-label="Close dialog"', count: 5 },
  { file: 'ssl.ts', marker: 'type="button" class="btn btn-outline" data-ssl-action="close-modal">Cancel</button>', count: 1 },
  { file: 'ssl.ts', marker: 'type="button" class="btn btn-primary" data-ssl-action="upload-certificate">', count: 1 },
  { file: 'categories.ts', marker: 'type="button" class="btn font-600" data-categories-action="open-add-policy-modal">+ Create Policy</button>', count: 1 },
  { file: 'categories.ts', marker: 'type="button" class="btn btn-xs btn-outline-danger" data-categories-action="delete-policy"', count: 1 },
  { file: 'categories.ts', marker: 'aria-label="Delete ${escapeHtml(displayName)} policy"', count: 1 },
  { file: 'categories.ts', marker: 'type="button" class="btn btn-xs font-600" data-categories-action="edit-policy"', count: 1 },
  { file: 'categories.ts', marker: 'type="button" class="btn btn-outline btn-sm" data-categories-action="close-modal" data-modal-id="add-policy-modal">Close</button>', count: 1 },
  { file: 'categories.ts', marker: 'type="button" class="btn btn-outline" data-categories-action="close-modal" data-modal-id="add-policy-modal">Cancel</button>', count: 1 },
  { file: 'categories.ts', marker: 'type="button" class="btn" data-categories-action="create-policy">Create Policy</button>', count: 1 },
  { file: 'sections/waf-config.ts', marker: 'type="button" class="btn btn-primary btn-sm section-btn-inline" data-waf-action="open-rule-editor">', count: 2 },
  { file: 'sections/waf-config.ts', marker: 'type="button" class="btn btn-ghost btn-sm" data-waf-action="open-rule-editor"', count: 1 },
  { file: 'sections/waf-config.ts', marker: 'type="button" class="btn btn-ghost btn-sm text-danger" data-waf-action="delete-rule"', count: 1 },
  { file: 'sections/waf-config.ts', marker: 'type="button" class="btn btn-outline btn-sm section-btn-inline" data-waf-action="cancel-editor">', count: 1 },
  { file: 'sections/waf-config.ts', marker: 'type="button" class="btn btn-primary btn-sm section-btn-inline" data-waf-action="submit-custom-rule"', count: 1 },
  { file: 'sections/waf-config.ts', marker: 'data-waf-action="close-exclusion-modal" aria-label="Close dialog"', count: 1 },
  { file: 'sections/antibots-render-exceptions-tab.ts', marker: 'data-antibot-action="close-exception-modal" aria-label="Close dialog"', count: 1 },
  { file: 'ssl.ts', marker: 'data-ssl-action="close-modal" aria-label="Close dialog"', count: 1 },
  { file: 'alerts.ts', marker: 'data-action="alerts-close-detail" aria-label="Close dialog"', count: 1 },
  { file: 'sections/edge-access/v2/shell.ts', marker: 'type="button" class="section-modal-close" data-section-action="close-modal" aria-label="Close dialog"', count: 3 },
  { file: 'sections/edge-access/v2/shell.ts', marker: 'type="button" class="section-confirm-close" data-section-action="close-modal" aria-label="Close dialog"', count: 3 }
];
for (const contract of closeDialogContracts) {
  const full = path.join(srcRoot, contract.file);
  if (!existsSync(full)) continue;
  const source = readFileSync(full, 'utf8');
  const count = source.split(contract.marker).length - 1;
  if (count === 0 && contract.file === 'sections/traffic-config.ts' && contract.count > 1) {
    continue;
  }
  if (count !== contract.count) {
    fail(`${contract.file} must expose ${contract.count} labelled native dialog closer${contract.count === 1 ? '' : 's'}`);
  }
}

const missingTsSource = jsFiles.filter((file) => !tsRuntimeFiles.includes(file)).sort();
if (missingTsSource.length > 0) {
  fail(`Found runtime JS without TS source: ${missingTsSource.join(', ')}`);
}

const missingRuntimeJs = tsRuntimeFiles.filter((file) => !jsFiles.includes(file)).sort();
if (missingRuntimeJs.length > 0) {
  fail(`Found TS runtime source without generated JS output: ${missingRuntimeJs.join(', ')}`);
}

const showToastCallAllowlist = new Set(['core/notify.ts']);
for (const file of tsSourceFiles) {
  if (showToastCallAllowlist.has(file)) continue;

  const full = path.join(srcRoot, file);
  const content = readFileSync(full, 'utf8');
  if (/window\.showToast\s*\(/.test(content)) {
    fail(`${rel(full)} must not call window.showToast directly (use window.AdminNotify or a safe wrapper)`);
  }
}

const legacyGlobalPattern = /window\.AdminNotify|typeof Toast\s*!==\s*'undefined'|typeof SectionUI\s*!==\s*'undefined'/;

const inlineHandlerCounts = [];
const windowAssignmentCounts = [];
const directDomCounts = [];
for (const file of tsSourceFiles) {
  if (file.endsWith('.d.ts')) continue;

  const full = path.join(srcRoot, file);
  const content = readFileSync(full, 'utf8');

  const inlineMatches = content.match(inlineHandlerPattern);
  if (inlineMatches) {
    inlineHandlerCounts.push([file, inlineMatches.length]);
    fail(`${rel(full)} must not contain inline HTML handler markup`);
  }

  const windowMatches = content.match(windowAssignmentPattern);
  if (windowMatches) {
    windowAssignmentCounts.push([file, windowMatches.length]);
    fail(`${rel(full)} assigns to window.* (legacy globals are strictly forbidden)`);
  }

  if (legacyGlobalPattern.test(content)) {
    fail(`${rel(full)} contains legacy global guard patterns (window.AdminNotify, typeof Toast, typeof SectionUI)`);
  }

  const directDomMatches = content.match(directDomPattern);
  if (directDomMatches) {
    directDomCounts.push([file, directDomMatches.length]);
    const normalizedFile = file.split(path.sep).join('/');
    if (!directDomAllowlist.has(normalizedFile)) {
      fail(`${rel(full)} uses raw document DOM helpers outside the migration allowlist (prefer AdminDOM/AdminEvents/shared helpers)`);
    }
  }

  if (file.startsWith('sections/edge-access/') && legacySectionClassPrefixPattern.test(content)) {
    fail(`${rel(full)} contains legacy section-prefixed class names (access-/antibot-/waf-/traffic-)`);
  }

  if (malformedSharedClassPattern.test(content)) {
    fail(`${rel(full)} contains malformed shared class names (section-section-*)`);
  }

  if (file.startsWith('sections/') && deprecatedSharedClassTokenPattern.test(content)) {
    fail(`${rel(full)} contains deprecated shared class tokens (legacy control/preset/traffic class names)`);    
  }
}

for (const file of cssSourceFiles) {
  const full = path.join(adminRoot, file);
  const content = readFileSync(full, 'utf8');
  if (legacySectionSelectorPrefixPattern.test(content)) {
    fail(`${rel(full)} contains legacy section-prefixed selectors (access-/antibot-/waf-/traffic-)`);
  }

  if (deprecatedSectionSelectorPattern.test(content)) {
    fail(`${rel(full)} contains deprecated section selectors (.modal-list-item/.geo-region-*)`);
  }
}

const authPages = ['login.html', 'reset_request.html', 'reset_confirm.html'];
const authEntrypoints = {
  'login.html': '/dist/js/auth/login.js',
  'reset_request.html': '/dist/js/auth/reset-request.js',
  'reset_confirm.html': '/dist/js/auth/reset-confirm.js'
};
for (const page of authPages) {
  const file = path.join(adminRoot, page);
  const content = readFileSync(file, 'utf8');

  const inlineScriptPattern = /<script\b(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
  let scriptMatch = null;
  while ((scriptMatch = inlineScriptPattern.exec(content)) !== null) {
    if ((scriptMatch[1] || '').trim().length > 0) {
      fail(`${rel(file)} must not contain inline script blocks`);
    }
  }

  if (/\son[a-z]+\s*=\s*"/i.test(content)) {
    fail(`${rel(file)} must not contain inline HTML event handlers`);
  }

  const entry = authEntrypoints[page];
  const moduleScriptPattern = new RegExp(`<script\\b[^>]*\\btype=["']module["'][^>]*\\bsrc=["']${entry.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:\\?[^"']*)?["'][^>]*>\\s*</script>`, 'i');
  if (!moduleScriptPattern.test(content)) {
    fail(`${rel(file)} must load module entrypoint ${entry} via <script type="module" ...>`);
  }
}

const indexContent = readFileSync(indexHtml, 'utf8');
if (/\son[a-z]+\s*=\s*"/i.test(indexContent)) {
  fail('web/admin/index.html must not contain inline HTML event handlers (use data-* hooks with TS listeners)');
}

const adminEntrypointPattern = /<script\b[^>]*\btype=["']module["'][^>]*\bsrc=["']\/dist\/js\/main\.js(?:\?[^"']*)?["'][^>]*>\s*<\/script>/i;
if (!adminEntrypointPattern.test(indexContent)) {
  fail('web/admin/index.html must load /dist/js/main.js via <script type="module" ...>');
}

const classicLocalScriptPattern = /<script\b(?![^>]*\btype=["']module["'])(?=[^>]*\bsrc=["']\/dist\/js\/)[^>]*>\s*<\/script>/i;
if (classicLocalScriptPattern.test(indexContent)) {
  fail('web/admin/index.html must load compiled admin JS through module entrypoints, not classic /dist/js/*.js scripts');
}

const enterpriseNavSource = readFileSync(path.join(srcRoot, 'enterprise-nav.ts'), 'utf8');
const routerSource = readFileSync(path.join(srcRoot, 'router.ts'), 'utf8');
const routesSource = readFileSync(path.join(srcRoot, 'routes.ts'), 'utf8');

if (!enterpriseNavSource.includes("target: 'access_config'") || !enterpriseNavSource.includes("module: 'access_control'")) {
  fail('enterprise-nav.ts must keep the stable access_config target and access_control module for Edge Access');
}

if (!enterpriseNavSource.includes("label: 'Edge Access'")) {
  fail('enterprise-nav.ts must render the visible section label as Edge Access');
}

if (enterpriseNavSource.includes("label: 'Access Control'")) {
  fail('enterprise-nav.ts must not render the old Access Control nav label');
}

for (const labelFile of ['dashboards/index.ts', 'dashboards/system.ts', 'security.ts']) {
  const full = path.join(srcRoot, labelFile);
  if (existsSync(full) && readFileSync(full, 'utf8').includes('Access Control')) {
    fail(`${rel(full)} must use the visible label Edge Access instead of Access Control`);
  }
}

const edgeAccessDir = path.join(srcRoot, 'sections', 'edge-access');
if (existsSync(edgeAccessDir)) {
  const edgeAccessFiles = walkFiles(edgeAccessDir)
    .filter((file) => file.endsWith('.ts'))
    .map((file) => path.relative(edgeAccessDir, file).split(path.sep).join('/'));
  const edgeAccessRenderer = readFileSync(path.join(edgeAccessDir, 'v2', 'components.ts'), 'utf8');
  const edgeAccessTypes = readFileSync(path.join(edgeAccessDir, 'types.ts'), 'utf8');
  const edgeAccessShell = readFileSync(path.join(edgeAccessDir, 'v2', 'shell.ts'), 'utf8');
  const edgeAccessFacade = readFileSync(path.join(edgeAccessDir, 'facade.ts'), 'utf8');
  const accessConfigEntrypoint = existsSync(path.join(srcRoot, 'sections', 'access-config.ts'))
    ? readFileSync(path.join(srcRoot, 'sections', 'access-config.ts'), 'utf8')
    : '';
  const unsupportedAccessLabels = ['MFA', 'Password Policy', 'Account Lockout'];
  const removedLegacyAccessModules = [
    'access-action-helpers',
    'access-config-bindings',
    'access-config-bindings-deps',
    'access-config-composition',
    'access-config-facade-parts',
    'access-config-legacy',
    'access-config-shared',
    'access-display-helpers',
    'access-menu-wrappers',
    'access-render-helpers',
    'access-tag-input-helpers',
    'access-toast-helpers',
    'access-ui-helpers'
  ];
  const removedLegacyEdgeAccessModules = [
    'access-rule-draft',
    'access-rule-modal',
    'activity-modal',
    'api',
    'identity-trust-draft',
    'identity-trust-modal',
    'normalizers',
    'policy-contract',
    'protected-app-draft',
    'protected-app-modal',
    'renderers',
    'service-credential-draft',
    'service-credential-modal',
    'settings-draft',
    'shell'
  ];
  const removedLegacyAccessSources = removedLegacyAccessModules.map((name) => `sections/${name}.ts`);
  const removedLegacyAccessJs = removedLegacyAccessModules.map((name) => `sections/${name}.js`);

  const existingLegacyAccessSources = removedLegacyAccessSources
    .filter((file) => existsSync(path.join(srcRoot, file)))
    .sort();
  if (existingLegacyAccessSources.length > 0) {
    fail(`Remove deleted legacy Access frontend source files: ${existingLegacyAccessSources.join(', ')}`);
  }

  const existingLegacyAccessJs = removedLegacyAccessJs
    .filter((file) => existsSync(path.join(generatedJsRoot, file)))
    .sort();
  if (existingLegacyAccessJs.length > 0) {
    fail(`Remove deleted legacy Access generated JS files: ${existingLegacyAccessJs.join(', ')}`);
  }

  for (const moduleName of removedLegacyEdgeAccessModules) {
    if (existsSync(path.join(edgeAccessDir, `${moduleName}.ts`))) {
      fail(`Remove deleted legacy Edge Access source file edge-access/${moduleName}.ts`);
    }
    if (existsSync(path.join(generatedJsRoot, 'sections', 'edge-access', `${moduleName}.js`))) {
      fail(`Remove deleted legacy Edge Access generated file edge-access/${moduleName}.js`);
    }
  }

  if (accessConfigEntrypoint && accessConfigEntrypoint.includes('access-config-legacy')) {
    fail('access-config.ts must remain a thin Edge Access compatibility entrypoint without referencing access-config-legacy.ts');
  }
  if (edgeAccessFacade.includes('LegacyEdgeAccessConfigFacade')
    || edgeAccessFacade.includes('loadAppFirstShellEnabled')
    || edgeAccessFacade.includes("from './shell.js'")) {
    fail('Edge Access must use the permanent V2 facade without a legacy shell or feature-gate fallback');
  }

  for (const file of tsSourceFiles) {
    const full = path.join(srcRoot, file);
    const content = readFileSync(full, 'utf8');
    for (const moduleName of removedLegacyAccessModules) {
      if (content.includes(`'./${moduleName}.js'`) || content.includes(`"./${moduleName}.js"`)) {
        fail(`${rel(full)} imports deleted legacy Access module ${moduleName}.js`);
      }
    }
  }

  for (const file of edgeAccessFiles) {
    const full = path.join(edgeAccessDir, file);
    const content = readFileSync(full, 'utf8');
    if (file !== 'v2/endpoints.ts' && content.includes('sections/access_control')) {
      fail(`${rel(full)} must not contain raw Edge Access endpoint strings; use edge-access/v2/endpoints.ts`);
    }
    if (content.includes('authentication.default_action')) {
      fail(`${rel(full)} must use authorization.default_action, not authentication.default_action`);
    }
    if (file !== 'v2/policies-components.ts') {
      for (const label of unsupportedAccessLabels) {
        if (content.includes(label)) {
          fail(`${rel(full)} must not render unsupported legacy Access setting "${label}"`);
        }
      }
    }
  }

  const v2AppsContract = readFileSync(path.join(edgeAccessDir, 'v2', 'apps-contract.ts'), 'utf8');
  const v2AppsComponents = readFileSync(path.join(edgeAccessDir, 'v2', 'apps-components.ts'), 'utf8');
  const v2AppsShell = readFileSync(path.join(edgeAccessDir, 'v2', 'shell.ts'), 'utf8');
  if (v2AppsContract.includes("policy-contract")) {
    fail('Edge Access V2 Apps must not import the policy authoring client');
  }
  for (const forbiddenEditor of ['data-policy-principal', 'data-policy-requirement', 'data-policy-decision', 'policy-editor']) {
    if (v2AppsComponents.includes(forbiddenEditor) || v2AppsShell.includes(forbiddenEditor)) {
      fail(`Edge Access V2 Apps must not render policy authoring control ${forbiddenEditor}`);
    }
  }
  if (!v2AppsContract.includes('createWithRoute') || !v2AppsContract.includes('enabled: false')) {
    fail('Edge Access V2 Apps must create shortcut Routes disabled through the dedicated create-with-route operation');
  }
  if (/update\([^)]*\)[\s\S]{0,700}origin_url/.test(v2AppsContract)) {
    fail('Edge Access V2 Apps must not send Route-owned fields through App updates');
  }

  const v2PoliciesContract = readFileSync(path.join(edgeAccessDir, 'v2', 'policies-contract.ts'), 'utf8');
  const v2PoliciesComponents = readFileSync(path.join(edgeAccessDir, 'v2', 'policies-components.ts'), 'utf8');
  if (v2PoliciesComponents.includes('origin_url') || v2PoliciesComponents.includes('route_mode') || v2PoliciesComponents.includes('oidc_provider_id') || v2PoliciesComponents.includes('jwt_issuer_url')) {
    fail('Edge Access V2 Policy pages must not render Route-owned or App trust-source controls');
  }
  if (!v2PoliciesContract.includes('policy-workspace') || !v2PoliciesContract.includes('decision-explorer')) {
    fail('Edge Access V2 must use dedicated Policy workspace and Decision Explorer read models');
  }
  if (/createPolicy|updatePolicy|createAttachment|updateAttachment|detachAttachment/.test(v2PoliciesComponents.slice(v2PoliciesComponents.indexOf('function renderDecisions')))) {
    fail('Edge Access V2 Decision Explorer must remain read-only');
  }

  const edgeAccessUserFacingCopyFiles = new Map([
    ['v2/components.ts', edgeAccessRenderer],
    ['v2/apps-components.ts', v2AppsComponents],
    ['v2/policies-components.ts', v2PoliciesComponents],
    ['v2/runtime-components.ts', readFileSync(path.join(edgeAccessDir, 'v2', 'runtime-components.ts'), 'utf8')]
  ]);

  for (const [file, content] of edgeAccessUserFacingCopyFiles) {
    if (/\bAccess Rules\b/.test(content)) {
      fail(`edge-access/${file} must use the user-facing label "Advanced Rules"; keep Access Rules only for backend/internal compatibility code`);
    }

    const jwtLoginCopyPatterns = [
      /\bJWT\s+(?:login|browser login)\b/i,
      /\bJWT\s+redirects?\s+(?:users\s+)?to\s+login\b/i,
      /\bJWT\s+(?:performs|starts|creates|opens|shows|uses|provides)\s+(?:a\s+)?(?:browser\s+)?login\b/i,
      /\blogin\s+with\s+JWT\b/i,
      /\bJWT\s+sign-?in\b/i
    ];
    if (jwtLoginCopyPatterns.some((pattern) => pattern.test(content))) {
      fail(`edge-access/${file} must not describe JWT as browser login; JWT copy must stay bearer-token oriented`);
    }

    const publicIdentityGatedPatterns = [
      /\bpublic\s+(?:app|apps|route|routes|access)\s+(?:is|are)\s+identity[- ]gated\b/i,
      /\bpublic\s+(?:app|apps|route|routes|access)\s+requires?\s+(?:an?\s+)?identity\b/i,
      /\bpublic\s+(?:app|apps|route|routes|access)\s+enforces?\s+(?:an?\s+)?identity\b/i,
      /\bpublic\s+(?:app|apps|route|routes|access)\s+uses?\s+(?:an?\s+)?identity\s+gate\b/i
    ];
    if (publicIdentityGatedPatterns.some((pattern) => pattern.test(content))) {
      fail(`edge-access/${file} must not describe public routes as identity-gated; public copy must say no identity gate`);
    }
  }

  if (!routerSource.includes('access_config') || !routerSource.includes('AccessControlConfigFacade.init()')) {
    fail('router.ts must keep the stable access_config route target wired to AccessControlConfigFacade.init()');
  }

  for (const token of ['Access', 'routes-protect-access', 'Open App', 'Protect', 'loadAppsForRouting']) {
    if (!routesSource.includes(token)) {
      fail(`routes.ts must include the Edge Access Routing integration token "${token}"`);
    }
  }

  if (!edgeAccessTypes.includes('openProtectedAppForRoute(routeId: string)') || !edgeAccessShell.includes('openProtectedAppForRoute(routeId: string)')) {
    fail('Edge Access facade must expose openProtectedAppForRoute(routeId) for Routing handoff');
  }
}

const editionTypes = readFileSync(path.join(root, 'internal', 'edition', 'types.go'), 'utf8');
const enterpriseBundlePath = path.join(root, 'internal', 'app', 'bundle_enterprise.go');
const enterpriseBundle = existsSync(enterpriseBundlePath) ? readFileSync(enterpriseBundlePath, 'utf8') : '';
if (!editionTypes.includes('FeatureAccessControl') || !editionTypes.includes('FeatureID = "access_control.all"')) {
  fail('Phase 13 must preserve the existing FeatureAccessControl entitlement');
}

if (editionTypes.includes('FeatureEdgeAccess') || (enterpriseBundle && enterpriseBundle.includes('FeatureEdgeAccess'))) {
  fail('Phase 13 must not introduce a new Edge Access entitlement');
}

const inGitRepo = (() => {
  try {
    execSync('git rev-parse --is-inside-work-tree', { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
})();

if (inGitRepo) {
  const changed = execSync('git diff --name-only -- web/admin/dist/js', { encoding: 'utf8' }).trim();
  if (changed) {
    fail(`Generated runtime JS is out-of-sync with TS source:\n${changed}`);
  }
}

const inlineHandlerTotal = inlineHandlerCounts.reduce((sum, [, count]) => sum + count, 0);
const windowAssignmentTotal = windowAssignmentCounts.reduce((sum, [, count]) => sum + count, 0);
const directDomTotal = directDomCounts.reduce((sum, [, count]) => sum + count, 0);

console.log(
  `admin-guardrails: legacy surface inline-handlers=${inlineHandlerTotal} window-assignments=${windowAssignmentTotal} direct-dom=${directDomTotal}`
);
console.log('admin-guardrails: OK');
