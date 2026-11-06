import React, { useEffect, useState, useMemo } from 'react';
import {
  Table,
  TableHead,
  TableRow,
  TableHeader,
  TableBody,
  TableCell,
  Toggle,
  Select,
  SelectItem,
  InlineNotification,
  DataTableSkeleton,
  Button,
  Search,
} from '@carbon/react';
import {
  Firewall,
  Renew,
  Bot,
  ArrowsHorizontal,
  Filter,
  DataCheck,
  Layers,
  ChevronDown,
  ChevronUp,
  CheckmarkOutline,
  CloseOutline,
  Security,
} from '@carbon/icons-react';
import type { WAFHealth } from '../types';
import { apiService } from '../services/api';
import { PageHeader, SectionCard } from '../components/common';

export type WafPolicyGroupKey =
  | 'attack-protection'
  | 'scanner-detection'
  | 'protocol-enforcement'
  | 'request-protection'
  | 'response-protection'
  | 'general-protection';

const GROUP_ICONS: Record<
  WafPolicyGroupKey,
  React.ComponentType<{ size?: number; className?: string; style?: React.CSSProperties }>
> = {
  'attack-protection': Firewall,
  'scanner-detection': Bot,
  'protocol-enforcement': ArrowsHorizontal,
  'request-protection': Filter,
  'response-protection': DataCheck,
  'general-protection': Layers,
};

export function formatManagedRuleName(fileName: string): string {
  const acronymMap: Record<string, string> = {
    api: 'API',
    csrf: 'CSRF',
    dos: 'DoS',
    lfi: 'LFI',
    php: 'PHP',
    rce: 'RCE',
    rfi: 'RFI',
    sqli: 'SQL Injection',
    sql: 'SQL',
    xss: 'Cross-Site Scripting (XSS)',
    xml: 'XML',
    iis: 'IIS',
    java: 'Java',
  };

  const specificTitles: Record<string, string> = {
    'REQUEST-901-INITIALIZATION.conf': 'Core Initialization & Anomaly Thresholds',
    'REQUEST-905-COMMON-EXCEPTIONS.conf': 'Common Application Exceptions',
    'REQUEST-911-METHOD-ENFORCEMENT.conf': 'HTTP Method Enforcement',
    'REQUEST-913-SCANNER-DETECTION.conf': 'Automated Scanner & Crawler Detection',
    'REQUEST-920-PROTOCOL-ENFORCEMENT.conf': 'HTTP Protocol Compliance',
    'REQUEST-921-PROTOCOL-ATTACK.conf': 'HTTP Protocol Attack Defense',
    'REQUEST-922-MULTIPART-ATTACK.conf': 'Multipart Upload Inspection',
    'REQUEST-930-APPLICATION-ATTACK-LFI.conf': 'Local File Inclusion (LFI)',
    'REQUEST-931-APPLICATION-ATTACK-RFI.conf': 'Remote File Inclusion (RFI)',
    'REQUEST-932-APPLICATION-ATTACK-RCE.conf': 'Remote Code Execution (RCE)',
    'REQUEST-933-APPLICATION-ATTACK-PHP.conf': 'PHP Code Injection',
    'REQUEST-934-APPLICATION-ATTACK-GENERIC.conf': 'Generic Application Attacks',
    'REQUEST-941-APPLICATION-ATTACK-XSS.conf': 'Cross-Site Scripting (XSS)',
    'REQUEST-942-APPLICATION-ATTACK-SQLI.conf': 'SQL Injection (SQLi)',
    'REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf': 'Session Fixation',
    'REQUEST-944-APPLICATION-ATTACK-JAVA.conf': 'Java Deserialization & Exploits',
    'REQUEST-949-BLOCKING-EVALUATION.conf': 'Inbound Anomaly Score Evaluation',
    'REQUEST-999-COMMON-EXCEPTIONS-AFTER.conf': 'Post-Evaluation Exceptions',
    'RESPONSE-950-DATA-LEAKAGES.conf': 'Data & Credential Leakage Prevention',
    'RESPONSE-951-DATA-LEAKAGES-SQL.conf': 'SQL Error & Schema Leakage',
    'RESPONSE-952-DATA-LEAKAGES-JAVA.conf': 'Java Stack Trace Disclosure',
    'RESPONSE-953-DATA-LEAKAGES-PHP.conf': 'PHP Error & Path Disclosure',
    'RESPONSE-954-DATA-LEAKAGES-IIS.conf': 'IIS & ASP.NET Banner Leakage',
    'RESPONSE-955-WEB-SHELLS.conf': 'Web Shell Execution Signatures',
    'RESPONSE-956-DATA-LEAKAGES-RUBY.conf': 'Ruby Exception & Backtrace Leaks',
    'RESPONSE-959-BLOCKING-EVALUATION.conf': 'Outbound Anomaly Score Evaluation',
    'RESPONSE-980-CORRELATION.conf': 'Transaction Correlation Logging',
  };

  const exact = specificTitles[fileName] || specificTitles[fileName.replace(/\.disabled$/i, '.conf')];
  if (exact) return exact;

  const normalized = String(fileName || '')
    .replace(/\.disabled$/i, '')
    .replace(/\.conf$/i, '')
    .replace(/^(REQUEST|RESPONSE|RESPONSE-BODY)-/i, '')
    .replace(/^\d{3,4}-/, '')
    .replace(/^(APPLICATION-ATTACK|APPLICATION|ATTACK)-/i, '')
    .replace(/[-_]+/g, ' ')
    .trim()
    .toLowerCase();
  if (!normalized) return 'Managed Protection';
  return normalized
    .split(/\s+/)
    .map((part) => acronymMap[part] || part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ')
    .replace(/\bSql Injection\b/g, 'SQL Injection')
    .replace(/\bCross Site Scripting\b/g, 'Cross-Site Scripting (XSS)');
}

export function getManagedRulePolicyGroup(
  fileName: string,
  category?: string,
  group?: string
): {
  key: WafPolicyGroupKey;
  label: string;
  description: string;
} {
  const name = formatManagedRuleName(fileName).toLowerCase();
  const rawGroup = String(group || '').replace(/[_-]+/g, ' ').toLowerCase();
  const cat = String(category || '').toLowerCase();
  const combined = `${name} ${rawGroup} ${cat}`;

  if (cat === 'response' || /response|leakage|disclosure|error/i.test(combined)) {
    return {
      key: 'response-protection',
      label: 'Response Protection',
      description: 'Detects information leaks, server errors, and stack traces.',
    };
  }
  if (/\b(scanner|recon|crawler|automation|bot|probe)\b/i.test(combined)) {
    return {
      key: 'scanner-detection',
      label: 'Scanner Detection',
      description: 'Blocks vulnerability scanners, crawlers, and automated probes.',
    };
  }
  if (/\b(protocol|method|header|encoding|content type|file upload|multipart)\b/i.test(combined)) {
    return {
      key: 'protocol-enforcement',
      label: 'Protocol Enforcement',
      description: 'Validates HTTP RFC compliance, methods, and header formats.',
    };
  }
  if (/\b(sql|xss|injection|rce|rfi|lfi|php|java|attack|exploit|scripting)\b/i.test(combined)) {
    return {
      key: 'attack-protection',
      label: 'Attack Protection',
      description: 'Defends against SQL injection, XSS, RCE, and file inclusion.',
    };
  }
  if (cat === 'request') {
    return {
      key: 'request-protection',
      label: 'Request Protection',
      description: 'Inspects incoming requests for malicious payloads.',
    };
  }
  return {
    key: 'general-protection',
    label: 'General Protection',
    description: 'Core initialization, anomaly score checks, and correlation logging.',
  };
}

export function getManagedRuleDescription(fileName: string, group?: string, category?: string): string {
  const friendlyName = formatManagedRuleName(fileName);
  const fn = fileName.toUpperCase();
  if (fn.includes('SQLI')) return 'Detects SQL query injection, boolean evaluation, union exploits, and DBMS fingerprinting payloads.';
  if (fn.includes('XSS')) return 'Mitigates cross-site scripting vectors, script tag injection, DOM events, and obfuscated JavaScript.';
  if (fn.includes('LFI')) return 'Blocks path traversal, directory traversal (/../), null byte injection, and unauthorized system file access.';
  if (fn.includes('RFI')) return 'Prevents remote file inclusion payloads attempting to force application fetches of malicious offsite code.';
  if (fn.includes('RCE')) return 'Detects OS command injection, shell piping, PowerShell, and system executable invocation attempts.';
  if (fn.includes('PHP')) return 'Guards against PHP code injection, unserialize exploits, eval/assert invocations, and upload backdoors.';
  if (fn.includes('JAVA')) return 'Protects against Java deserialization, Spring4Shell, Struts OGNL, and Log4j exploits.';
  if (fn.includes('SCANNER')) return 'Identifies automated reconnaissance probes, scanners (Nikto, SQLmap, Acunetix), and malicious bots.';
  if (fn.includes('PROTOCOL-ENFORCEMENT')) return 'Validates HTTP protocol compliance, HTTP request RFC bounds, restricted methods, and header formats.';
  if (fn.includes('PROTOCOL-ATTACK')) return 'Defends against HTTP request smuggling, HTTP response splitting, and parameter pollution.';
  if (fn.includes('MULTIPART-ATTACK')) return 'Inspects multipart form upload boundaries, header anomalies, and file-parsing evasion attempts.';
  if (fn.includes('SESSION-FIXATION')) return 'Blocks session fixation payloads that attempt to pre-set session identifier cookies.';
  if (fn.includes('METHOD-ENFORCEMENT')) return 'Restricts HTTP methods to standard verbs (GET, POST, HEAD, OPTIONS) and drops unauthorized verbs.';
  if (fn.includes('GENERIC')) return 'Defends against generic application attacks, unauthorized file inclusions, and command obfuscation.';
  if (fn.includes('INITIALIZATION')) return 'Initializes Core Rule Set transactional variables, anomaly score counters, and inspection engine state.';
  if (fn.includes('COMMON-EXCEPTIONS')) return 'Permits standard CMS and application exceptions to prevent false positives on known-safe requests.';
  if (fn.includes('BLOCKING-EVALUATION')) return 'Evaluates cumulative anomaly scores against inbound and outbound thresholds to trigger enforcement.';
  if (fn.includes('CORRELATION')) return 'Correlates matched rule events across request and response phases for security analysis.';
  if (fn.includes('WEB-SHELLS')) return 'Detects web shell outputs, backdoor commands, and malicious script execution signatures in responses.';
  if (fn.includes('LEAKAGES-SQL')) return 'Inspects responses to prevent database error dumps, driver traces, and structure leakage.';
  if (fn.includes('LEAKAGES-JAVA')) return 'Catches uncaught Java stack traces and runtime exceptions in outbound responses.';
  if (fn.includes('LEAKAGES-PHP')) return 'Stops PHP fatal errors, display_errors leaks, and source path disclosure in outbound responses.';
  if (fn.includes('LEAKAGES-IIS')) return 'Filters IIS error pages, ASP.NET trace lines, and server identification banners.';
  if (fn.includes('LEAKAGES-RUBY')) return 'Detects Ruby/Rails backtraces, framework exceptions, and information disclosure in responses.';
  if (fn.includes('DATA-LEAKAGES')) return 'Monitors outbound response bodies for sensitive credentials, server tokens, and private keys.';
  const cat = String(category || '').toLowerCase();
  if (cat === 'response') return `${friendlyName} checks outbound responses for sensitive data and leakage.`;
  const groupStr = String(group || '').trim();
  const groupText = groupStr && groupStr.toLowerCase() !== friendlyName.toLowerCase()
    ? `${groupStr.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, (char) => char.toUpperCase())} protection`
    : 'built-in protection';
  return `${friendlyName} inspects incoming requests using ${groupText}.`;
}

export interface ManagedRuleItem {
  id: string;
  fileName: string;
  name: string;
  description: string;
  policyGroup: WafPolicyGroupKey;
  policyGroupLabel: string;
  category: string;
  enabled: boolean;
  status: 'healthy' | 'warning' | 'error' | 'disabled';
}

interface PolicyGroupDefinition {
  key: WafPolicyGroupKey;
  label: string;
  description: string;
  rules: ManagedRuleItem[];
}

export const WafRulesPage: React.FC = () => {
  const [rules, setRules] = useState<ManagedRuleItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [notification, setNotification] = useState<{
    kind: 'success' | 'error' | 'info';
    message: string;
  } | null>(null);

  const [wafHealth, setWafHealth] = useState<WAFHealth | null>(null);
  const [statusFilter, setStatusFilter] = useState<'all' | 'enabled' | 'disabled'>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [bulkProcessing, setBulkProcessing] = useState<boolean>(false);
  const [collapsedGroups, setCollapsedGroups] = useState<Record<string, boolean>>({});

  const loadData = async () => {
    setLoading(true);
    try {
      const [fullCfg, rawFiles] = await Promise.all([
        apiService.getWafFullConfig(),
        apiService.getWafCrsFiles(),
      ]);

      setWafHealth(fullCfg.health || null);

      const sourceFiles = Array.isArray(rawFiles) ? rawFiles : [];
      const formatted: ManagedRuleItem[] = sourceFiles.map((file) => {
        const fileName = file.name;
        const groupInfo = getManagedRulePolicyGroup(fileName, file.category, file.group);
        return {
          id: fileName,
          fileName,
          name: formatManagedRuleName(fileName),
          description: getManagedRuleDescription(fileName, file.group, file.category),
          policyGroup: groupInfo.key,
          policyGroupLabel: groupInfo.label,
          category: file.category || 'attack',
          enabled: file.enabled !== false,
          status: (file.status as any) || (file.enabled !== false ? 'healthy' : 'disabled'),
        };
      });

      setRules(formatted);
    } catch {
      setNotification({ kind: 'error', message: 'Failed to load managed rulesets.' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleToggleRule = async (rule: ManagedRuleItem, checked: boolean) => {
    const updated: ManagedRuleItem = {
      ...rule,
      enabled: checked,
      status: checked ? 'healthy' : 'disabled',
    };
    setRules((prev) => prev.map((r) => (r.id === rule.id ? updated : r)));

    const action = checked ? 'enable' : 'disable';
    const res = await apiService.toggleWafCrsFile(rule.fileName, action);
    if (!res.success) {
      const reverted: ManagedRuleItem = {
        ...rule,
        enabled: !checked,
        status: !checked ? 'healthy' : 'disabled',
      };
      setRules((prev) => prev.map((r) => (r.id === rule.id ? reverted : r)));
      setNotification({
        kind: 'error',
        message: `Failed to ${action} ${rule.name}: ${res.error || 'Engine update failed'}`,
      });
    } else {
      setNotification({
        kind: 'success',
        message: `${rule.name} ${action}d successfully.`,
      });
    }
  };

  const handleBulkToggle = async (targets: ManagedRuleItem[], enable: boolean) => {
    if (targets.length === 0) return;
    setBulkProcessing(true);
    const action = enable ? 'enable' : 'disable';
    const targetFileNames = targets.map((t) => t.fileName);

    setRules((prev) =>
      prev.map((r) => {
        if (targetFileNames.includes(r.fileName)) {
          return { ...r, enabled: enable, status: enable ? 'healthy' : 'disabled' };
        }
        return r;
      })
    );

    const res = await apiService.bulkToggleWafCrsFiles(targetFileNames, action);
    setBulkProcessing(false);
    if (res.success) {
      const count = res.changed?.length ?? targetFileNames.length;
      setNotification({
        kind: 'success',
        message: `All ${targetFileNames.length} selected rulesets ${enable ? 'enabled' : 'disabled'} (${count} changed).`,
      });
    } else {
      await loadData();
      setNotification({
        kind: 'error',
        message: `Managed rule bulk change failed: ${res.error || 'Engine build failed'}`,
      });
    }
  };

  const toggleGroupCollapse = (groupKey: string) => {
    setCollapsedGroups((prev) => ({
      ...prev,
      [groupKey]: !prev[groupKey],
    }));
  };

  const policyGroups: PolicyGroupDefinition[] = useMemo(() => {
    const groupMap = new Map<WafPolicyGroupKey, PolicyGroupDefinition>();

    rules.forEach((file) => {
      const groupInfo = getManagedRulePolicyGroup(file.fileName, file.category);
      const existing = groupMap.get(groupInfo.key);
      if (existing) {
        existing.rules.push(file);
      } else {
        groupMap.set(groupInfo.key, {
          key: groupInfo.key,
          label: groupInfo.label,
          description: groupInfo.description,
          rules: [file],
        });
      }
    });

    return Array.from(groupMap.values()).sort((a, b) => a.label.localeCompare(b.label));
  }, [rules]);

  const visibleGroups = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();

    return policyGroups
      .map((group) => {
        const filteredRules = group.rules.filter((rule) => {
          if (statusFilter === 'enabled' && !rule.enabled) return false;
          if (statusFilter === 'disabled' && rule.enabled) return false;
          if (q) {
            const match =
              rule.name.toLowerCase().includes(q) ||
              rule.description.toLowerCase().includes(q) ||
              group.label.toLowerCase().includes(q);
            if (!match) return false;
          }
          return true;
        });

        return {
          ...group,
          rules: filteredRules,
        };
      })
      .filter((group) => group.rules.length > 0);
  }, [policyGroups, statusFilter, searchQuery]);

  const allFilteredRules = useMemo(
    () => visibleGroups.flatMap((g) => g.rules),
    [visibleGroups]
  );

  const allCollapsed = useMemo(() => {
    if (visibleGroups.length === 0) return false;
    return visibleGroups.every((g) => collapsedGroups[g.key]);
  }, [visibleGroups, collapsedGroups]);

  const toggleAllCollapse = () => {
    const nextState = !allCollapsed;
    const updated: Record<string, boolean> = {};
    visibleGroups.forEach((g) => {
      updated[g.key] = nextState;
    });
    setCollapsedGroups(updated);
  };

  return (
    <div style={{ padding: '32px 32px 80px', width: '100%', boxSizing: 'border-box' }}>
      <PageHeader
        kicker="Application firewall"
        title="Managed rulesets"
        icon={Firewall}
        action={
          <Button
            kind="tertiary"
            size="md"
            renderIcon={Renew}
            disabled={loading}
            onClick={loadData}
          >
            {loading ? 'Refreshing...' : 'Reload rulesets'}
          </Button>
        }
      />

      {wafHealth?.status === 'degraded' && (
        <div style={{ marginBottom: '20px' }}>
          <InlineNotification
            kind="warning"
            title="Ruleset reload failed"
            subtitle={
              wafHealth.message ||
              'Your previous managed rule settings remain active. Review the configuration and try again.'
            }
            lowContrast
          />
        </div>
      )}

      {notification && (
        <div style={{ marginBottom: '20px' }}>
          <InlineNotification
            kind={notification.kind}
            title={notification.message}
            onCloseButtonClick={() => setNotification(null)}
          />
        </div>
      )}

      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '16px',
          marginTop: '16px',
          marginBottom: '24px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          <div style={{ width: '280px' }}>
            <Search
              id="managed-rules-search"
              labelText="Search protections"
              placeholder="Search rules by name, ID, or keyword..."
              size="sm"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onClear={() => setSearchQuery('')}
            />
          </div>

          <div style={{ width: '170px' }}>
            <Select
              id="managed-status-filter"
              labelText="Status filter"
              hideLabel
              size="sm"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as 'all' | 'enabled' | 'disabled')}
            >
              <SelectItem value="all" text={`All statuses (${rules.length})`} />
              <SelectItem
                value="enabled"
                text={`Active only (${rules.filter((r) => r.enabled).length})`}
              />
              <SelectItem
                value="disabled"
                text={`Disabled only (${rules.filter((r) => !r.enabled).length})`}
              />
            </Select>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <Button
            kind="ghost"
            size="sm"
            onClick={toggleAllCollapse}
          >
            {allCollapsed ? 'Expand all' : 'Collapse all'}
          </Button>
          <Button
            kind="ghost"
            size="sm"
            renderIcon={CheckmarkOutline}
            disabled={bulkProcessing || allFilteredRules.length === 0}
            onClick={() => handleBulkToggle(allFilteredRules, true)}
          >
            Enable all
          </Button>
          <Button
            kind="ghost"
            size="sm"
            renderIcon={CloseOutline}
            disabled={bulkProcessing || allFilteredRules.length === 0}
            onClick={() => handleBulkToggle(allFilteredRules, false)}
          >
            Disable all
          </Button>
        </div>
      </div>

      {loading ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <SectionCard title="Protocol Violations" description="OWASP Core Rule Set protections">
            <DataTableSkeleton columnCount={3} rowCount={4} showHeader={false} showToolbar={false} />
          </SectionCard>
          <SectionCard title="Application Attacks" description="Injection, XSS, and RCE protections">
            <DataTableSkeleton columnCount={3} rowCount={4} showHeader={false} showToolbar={false} />
          </SectionCard>
        </div>
      ) : visibleGroups.length === 0 ? (
        <div
          style={{
            textAlign: 'center',
            padding: '48px 16px',
            background: 'var(--cds-layer-01)',
            border: '1px solid var(--cds-border-subtle)',
          }}
        >
          <Security size={32} style={{ marginBottom: '8px', fill: 'var(--cds-icon-secondary)' }} />
          <div
            style={{
              fontWeight: 600,
              fontSize: '14px',
              marginBottom: '4px',
              color: 'var(--cds-text-primary)',
            }}
          >
            {searchQuery ? 'No matching protections found' : 'No managed protections found'}
          </div>
          <div
            style={{
              color: 'var(--cds-text-secondary)',
              fontSize: '13px',
              maxWidth: '440px',
              margin: '0 auto 16px',
            }}
          >
            {searchQuery
              ? `No managed protection matched "${searchQuery}".`
              : 'OWASP Core Rule Set protections are not loaded or unavailable.'}
          </div>
          {searchQuery && (
            <Button kind="tertiary" size="sm" onClick={() => setSearchQuery('')}>
              Clear search
            </Button>
          )}
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {visibleGroups.map((group) => {
            const enabledCount = group.rules.filter((r) => r.enabled).length;
            const isCollapsed = Boolean(collapsedGroups[group.key]);

            return (
              <SectionCard
                key={group.key}
                title={group.label}
                description={group.description}
                icon={GROUP_ICONS[group.key]}
                padded={false}
                action={
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <span
                      style={{
                        fontSize: '13px',
                        color: 'var(--cds-text-secondary)',
                        fontWeight: 500,
                      }}
                    >
                      {enabledCount}/{group.rules.length} active
                    </span>
                    <Button
                      kind="ghost"
                      size="sm"
                      hasIconOnly
                      renderIcon={isCollapsed ? ChevronDown : ChevronUp}
                      iconDescription={isCollapsed ? 'Expand section' : 'Collapse section'}
                      onClick={() => toggleGroupCollapse(group.key)}
                    />
                  </div>
                }
              >
                {!isCollapsed && (
                  <div style={{ overflowX: 'auto', width: '100%' }}>
                    <Table size="md" aria-label={`${group.label} protections table`}>
                      <TableHead>
                        <TableRow>
                          <TableHeader style={{ width: '32%' }}>Protection</TableHeader>
                          <TableHeader>Description</TableHeader>
                          <TableHeader style={{ width: '220px', textAlign: 'right' }}>
                            Action
                          </TableHeader>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {group.rules.map((rule) => {
                          const isEnabled = rule.enabled !== false;
                          return (
                            <TableRow key={rule.id} style={{ opacity: isEnabled ? 1 : 0.65 }}>
                              <TableCell>
                                <span
                                  style={{
                                    fontWeight: 600,
                                    color: 'var(--cds-text-primary)',
                                    fontSize: '14px',
                                  }}
                                >
                                  {rule.name}
                                </span>
                              </TableCell>
                              <TableCell
                                style={{
                                  fontSize: '13px',
                                  color: 'var(--cds-text-secondary)',
                                  lineHeight: 1.5,
                                }}
                              >
                                {rule.description}
                              </TableCell>
                              <TableCell style={{ textAlign: 'right' }}>
                                <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: '8px' }}>
                                  <Toggle
                                    id={`toggle-crs-${rule.id}`}
                                    size="sm"
                                    labelText=""
                                    hideLabel
                                    toggled={isEnabled}
                                    onToggle={(checked) => handleToggleRule(rule, checked)}
                                    aria-label={`Toggle ${rule.name}`}
                                  />
                                </div>
                              </TableCell>
                            </TableRow>
                          );
                        })}
                      </TableBody>
                    </Table>
                  </div>
                )}
              </SectionCard>
            );
          })}
        </div>
      )}

      <div
        style={{
          textAlign: 'center',
          fontSize: '11px',
          color: 'var(--cds-text-helper)',
          marginTop: '32px',
          marginBottom: '16px',
        }}
      >
        Powered by OWASP ModSecurity Core Rule Set (CRS)
      </div>

    </div>
  );
};
