import React, { useEffect, useState, useMemo } from 'react';
import {
  Tile,
DataTable,
  TableContainer,
  TableToolbar,
  TableToolbarContent,
  TableToolbarSearch,
  Table,
  TableHead,
  TableRow,
  TableHeader,
  TableBody,
  TableCell,
  Button,
Select,
  SelectItem,
InlineNotification,
  DataTableSkeleton,
  PaginationSkeleton,
  Pagination,
} from '@carbon/react';
import {
  Renew,
  Download,
Security,
  Document,
} from '@carbon/icons-react';
import type { SecurityEventItem, NavItemKey } from '../types';
import { apiService } from '../services/api';
import { PageHeader, KpiCard, MetricStrip} from '../components/common';
import { COUNTRIES_MAP, normalizeToCountryCode } from '../data/geoData';
import {
  EventTimeCell,
  EventMethodTag,
  EventPathCell,
  EventRuleCell,
  EventActionBadge,
  EventStatusTag,
  EventSourceCell,
  EventInspectButton,
  EventInspectorModal,
} from '../components/events';

const countryNames: Record<string, string> = COUNTRIES_MAP;

export function isPrivateOrLoopbackIp(ip?: string): boolean {
  if (!ip) return false;
  const trimmed = ip.trim();
  return (
    trimmed === '127.0.0.1' ||
    trimmed === '::1' ||
    trimmed === 'localhost' ||
    trimmed.startsWith('10.') ||
    trimmed.startsWith('192.168.') ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(trimmed) ||
    trimmed.startsWith('fc00:') ||
    trimmed.startsWith('fe80:')
  );
}

export function getValidCountryCode(code?: string, ip?: string): string | null {
  if (ip && isPrivateOrLoopbackIp(ip)) return null;
  return normalizeToCountryCode(code);
}

function formatExactTime(timestamp: string | number | undefined): string {
  if (!timestamp) return '-';
  try {
    let d: Date;
    if (typeof timestamp === 'number') {
      d = new Date(timestamp < 1e11 ? timestamp * 1000 : timestamp);
    } else {
      const num = Number(timestamp);
      if (!isNaN(num) && /^\d+$/.test(String(timestamp).trim())) {
        d = new Date(num < 1e11 ? num * 1000 : num);
      } else {
        d = new Date(timestamp);
      }
    }
    if (isNaN(d.getTime())) return String(timestamp);
    return d.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return String(timestamp);
  }
}

function formatRelativeTime(timestamp: string | number | undefined): string {
  if (!timestamp) return '';
  try {
    let timeSec: number;
    if (typeof timestamp === 'number') {
      timeSec = timestamp > 1e11 ? Math.floor(timestamp / 1000) : timestamp;
    } else {
      const num = Number(timestamp);
      if (!isNaN(num) && /^\d+$/.test(String(timestamp).trim())) {
        timeSec = num > 1e11 ? Math.floor(num / 1000) : num;
      } else {
        timeSec = Math.floor(new Date(timestamp).getTime() / 1000);
      }
    }
    if (isNaN(timeSec)) return '';
    const diffSec = Math.max(0, Math.floor(Date.now() / 1000) - timeSec);
    if (diffSec < 10) return 'just now';
    if (diffSec < 60) return `${diffSec}s ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHours = Math.floor(diffMin / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays}d ago`;
  } catch {
    return '';
  }
}

function formatEventUtc(timestamp: string | number | undefined): string {
  if (!timestamp) return '-';
  try {
    let d: Date;
    if (typeof timestamp === 'number') {
      d = new Date(timestamp < 1e11 ? timestamp * 1000 : timestamp);
    } else {
      const num = Number(timestamp);
      if (!isNaN(num) && /^\d+$/.test(String(timestamp).trim())) {
        d = new Date(num < 1e11 ? num * 1000 : num);
      } else {
        d = new Date(timestamp);
      }
    }
    if (isNaN(d.getTime())) return String(timestamp);
    return d.toUTCString();
  } catch {
    return String(timestamp);
  }
}

interface ThreatLogsPageProps {
  onNavigate?: (key: NavItemKey) => void;
}

export const ThreatLogsPage: React.FC<ThreatLogsPageProps> = ({ onNavigate }) => {
  const [logs, setLogs] = useState<SecurityEventItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [notification, setNotification] = useState<{ kind: 'success' | 'error' | 'info'; message: string } | null>(null);

  const [searchQuery, setSearchQuery] = useState<string>('');
  const [timeWindow, setTimeWindow] = useState<string>('24h');
  const [decisionFilter, setDecisionFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');

  const [pageSize, setPageSize] = useState<number>(10);
  const [currentPage, setCurrentPage] = useState<number>(1);

  const [selectedLog, setSelectedLog] = useState<SecurityEventItem | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const queryParams: Record<string, any> = { window: timeWindow };
      if (decisionFilter !== 'all') queryParams.type = decisionFilter;
      if (severityFilter !== 'all') queryParams.severity = severityFilter;
      if (categoryFilter !== 'all') queryParams.category = categoryFilter;
      if (searchQuery.trim()) queryParams.q = searchQuery.trim();
      const fetched = await apiService.getThreatLogs(queryParams);
      setLogs(fetched);
    } catch {
      setNotification({ kind: 'error', message: 'Failed to load threat log records' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [timeWindow, decisionFilter, severityFilter, categoryFilter]);

  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      if (decisionFilter === 'blocked' && !log.blocked) return false;
      if (decisionFilter === 'allowed' && log.blocked) return false;

      if (severityFilter !== 'all' && (log.severity || '').toLowerCase() !== severityFilter) return false;

      if (categoryFilter !== 'all') {
        const normalizedCat = (log.category || '').toLowerCase().replace(/[\s_-]+/g, '');
        const targetCat = categoryFilter.toLowerCase().replace(/[\s_-]+/g, '');
        if (!normalizedCat.includes(targetCat)) return false;
      }

      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const haystack = `${log.client_ip || ''} ${log.path || ''} ${log.rule_name || ''} ${log.rule_id || ''} ${log.country || ''} ${log.user_agent || ''} ${log.method || ''} ${log.category || ''}`.toLowerCase();
        if (!haystack.includes(q)) return false;
      }

      return true;
    });
  }, [logs, decisionFilter, severityFilter, categoryFilter, searchQuery]);

  const totalItems = filteredLogs.length;
  const paginatedLogs = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredLogs.slice(start, start + pageSize);
  }, [filteredLogs, currentPage, pageSize]);

  const logsMap = useMemo(() => {
    const map = new Map<string, SecurityEventItem>();
    logs.forEach((item, idx) => {
      map.set(String(item.id || `threat-${idx}`), item);
    });
    return map;
  }, [logs]);

  const totalCount = logs.length;
  const blockedCount = logs.filter((l) => l.blocked).length;
  const blockRate = totalCount > 0 ? ((blockedCount / totalCount) * 100).toFixed(1) : '0.0';
  const detectedCount = totalCount - blockedCount;
  const uniqueIPs = new Set(logs.map((l) => l.client_ip)).size;

  const handleExportCSV = () => {
    if (!filteredLogs.length) {
      setNotification({ kind: 'error', message: 'No threat logs available to export' });
      return;
    }

    const headers = [
      'Timestamp',
      'DateTime_UTC',
      'Client_IP',
      'Country',
      'City',
      'Method',
      'Path',
      'Status_Code',
      'Triggered_Rule',
      'Rule_ID',
      'Severity',
      'Decision',
      'Anomaly_Score',
      'Latency_ms',
      'User_Agent',
    ];

    const escapeCSV = (val: unknown): string => {
      if (val === null || val === undefined) return '""';
      const str = String(val).replace(/"/g, '""');
      return `"${str}"`;
    };

    const rows = filteredLogs.map((l) =>
      [
        l.timestamp,
        formatEventUtc(l.timestamp),
        escapeCSV(l.client_ip),
        escapeCSV(l.country || 'XX'),
        escapeCSV(l.city || ''),
        escapeCSV(l.method),
        escapeCSV(l.path),
        l.status_code,
        escapeCSV(l.rule_name || '-'),
        escapeCSV(l.rule_id || '-'),
        escapeCSV(l.severity || 'high'),
        escapeCSV(l.blocked ? 'BLOCKED' : 'ALLOWED'),
        l.score || 0,
        l.latency_ms || 0,
        escapeCSV(l.user_agent || '-'),
      ].join(',')
    );

    const csvContent = [headers.join(','), ...rows].join('\r\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `aegis-threat-logs-${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    setNotification({ kind: 'success', message: `Exported ${filteredLogs.length} threat events to CSV` });
  };

  const handleResetFilters = () => {
    setSearchQuery('');
    setTimeWindow('24h');
    setDecisionFilter('all');
    setSeverityFilter('all');
    setCategoryFilter('all');
    setCurrentPage(1);
  };

  const tableHeaders = [
    { key: 'time', header: 'Time' },
    { key: 'client', header: 'Source' },
    { key: 'method', header: 'Method' },
    { key: 'path', header: 'Path' },
    { key: 'status', header: 'Status' },
    { key: 'rule', header: 'Rule / Reason' },
    { key: 'verdict', header: 'Decision' },
    { key: 'actions', header: '' },
  ];

  const tableRows = useMemo(() => {
    return paginatedLogs.map((item, idx) => {
      const isBlocked = Boolean(item.blocked ?? (String(item.action).toUpperCase() === 'BLOCK'));
      return {
        id: String(item.id || `threat-${idx}`),
        time: formatExactTime(item.timestamp),
        relativeTime: formatRelativeTime(item.timestamp),
        client: item.client_ip || '-',
        countryName: countryNames[item.country || ''] || item.country || 'Unknown',
        method: item.method || 'GET',
        path: item.path || '/',
        status: item.status_code || 403,
        rule: item.rule_name || item.rule_id || 'Threat Intercepted',
        verdict: isBlocked ? 'Blocked' : 'Allowed',
        isBlocked,
        severity: item.severity || 'high',
        raw: item,
      };
    });
  }, [paginatedLogs]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', padding: '32px', width: '100%', boxSizing: 'border-box' }}>
      <PageHeader
        kicker="Threat operations"
        title="Threat logs"
        icon={Document}
        action={
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Button kind="ghost" size="md" renderIcon={Renew} onClick={loadData}>
              Refresh
            </Button>
            <Button kind="tertiary" size="md" renderIcon={Download} onClick={handleExportCSV}>
              Export CSV
            </Button>
            <Button
              kind="primary"
              size="md"
              renderIcon={Security}
              onClick={() => {
                window.location.hash = '#waf-rulesets';
              }}
            >
              WAF Rules
            </Button>
          </div>
        }
      />

      {notification && (
        <InlineNotification
          kind={notification.kind}
          title={notification.message}
          onCloseButtonClick={() => setNotification(null)}
        />
      )}

      <MetricStrip minColWidth="200px">
        <KpiCard
          label="Total events"
          value={totalCount.toLocaleString()}
          subtext="In selected window"
          status="default"
          loading={loading}
        />
        <KpiCard
          label="Blocked events"
          value={blockedCount.toLocaleString()}
          subtext={`${blockRate}% block rate`}
          status="default"
          loading={loading}
        />
        <KpiCard
          label="Monitored events"
          value={detectedCount.toLocaleString()}
          subtext="Detection-only mode"
          status="default"
          loading={loading}
        />
        <KpiCard
          label="Unique client IPs"
          value={uniqueIPs.toLocaleString()}
          subtext="Distinct client IPs"
          status="default"
          loading={loading}
        />
      </MetricStrip>

      <Tile style={{ padding: '16px 20px' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'flex-end', gap: '16px' }}>

          <div style={{ width: '160px' }}>
            <Select
              id="threat-time-window"
              labelText="Time Window"
              size="md"
              value={timeWindow}
              onChange={(e) => setTimeWindow(e.target.value)}
            >
              <SelectItem value="15m" text="Last 15 Minutes" />
              <SelectItem value="1h" text="Last 1 Hour" />
              <SelectItem value="24h" text="Last 24 Hours" />
              <SelectItem value="7d" text="Last 7 Days" />
              <SelectItem value="30d" text="Last 30 Days" />
              <SelectItem value="all" text="All Events" />
            </Select>
          </div>

          <div style={{ width: '160px' }}>
            <Select
              id="threat-decision"
              labelText="Decision"
              size="md"
              value={decisionFilter}
              onChange={(e) => {
                setDecisionFilter(e.target.value);
                setCurrentPage(1);
              }}
            >
              <SelectItem value="all" text="All Decisions" />
              <SelectItem value="blocked" text="Blocked Only" />
              <SelectItem value="allowed" text="Allowed / Detected" />
            </Select>
          </div>

          <div style={{ width: '150px' }}>
            <Select
              id="threat-severity"
              labelText="Severity"
              size="md"
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setCurrentPage(1);
              }}
            >
              <SelectItem value="all" text="All Severities" />
              <SelectItem value="critical" text="Critical" />
              <SelectItem value="high" text="High" />
              <SelectItem value="medium" text="Medium" />
              <SelectItem value="low" text="Low" />
            </Select>
          </div>

          <div style={{ width: '180px' }}>
            <Select
              id="threat-category"
              labelText="Category"
              size="md"
              value={categoryFilter}
              onChange={(e) => {
                setCategoryFilter(e.target.value);
                setCurrentPage(1);
              }}
            >
              <SelectItem value="all" text="All Categories" />
              <SelectItem value="sql" text="SQL Injection" />
              <SelectItem value="xss" text="Cross-Site Scripting" />
              <SelectItem value="traversal" text="Path Traversal" />
              <SelectItem value="rce" text="Remote Code Exec" />
              <SelectItem value="bot" text="Bot & Crawler" />
              <SelectItem value="rate" text="Rate Limiting" />
              <SelectItem value="protocol" text="Protocol Violation" />
            </Select>
          </div>

          <div>
            <Button kind="ghost" size="md" onClick={handleResetFilters}>
              Reset filters
            </Button>
          </div>
        </div>
      </Tile>

      <div>
        {loading ? (
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <DataTableSkeleton headers={tableHeaders} rowCount={pageSize > 10 ? 10 : pageSize} columnCount={tableHeaders.length} />
            <PaginationSkeleton />
          </div>
        ) : (
          <DataTable rows={tableRows} headers={tableHeaders}>
            {({ rows, headers, getHeaderProps, getRowProps, getTableProps }) => (
              <TableContainer title="Forensic stream">
                <TableToolbar>
                  <TableToolbarContent>
                    <TableToolbarSearch
                      persistent
                      placeholder="Filter visible threat events..."
                      value={searchQuery}
                      onChange={(e: any) => {
                        setSearchQuery(e.target.value);
                        setCurrentPage(1);
                      }}
                    />
                  </TableToolbarContent>
                </TableToolbar>

                <Table {...getTableProps()} size="md" aria-label="Threat Logs Forensic Table">
                  <TableHead>
                    <TableRow>
                      {headers.map((h) => {
                        const { key, ...headerProps } = getHeaderProps({ header: h });
                        return (
                          <TableHeader key={key} {...headerProps}>
                            {h.header}
                          </TableHeader>
                        );
                      })}
                    </TableRow>
                  </TableHead>

                  <TableBody>
                    {rows.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={headers.length} style={{ textAlign: 'center', padding: '48px 16px' }}>
                          <Document size={32} style={{ marginBottom: '8px', fill: 'var(--cds-icon-secondary)' }} />
                          <div style={{ fontWeight: 600, marginBottom: '4px' }}>
                            {logs.length === 0
                              ? `No threat events in the selected window (${timeWindow}).`
                              : 'No threat events matching filters'}
                          </div>
                          <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px' }}>
                            {logs.length === 0
                              ? 'No threat events recorded in this time window.'
                              : 'Try clearing your search query or broadening the filter options.'}
                          </div>
                          {logs.length === 0 && (
                            <div style={{ marginTop: '16px', display: 'flex', gap: '8px', justifyContent: 'center' }}>
                              <Button size="sm" kind="tertiary" onClick={() => setTimeWindow('7d')}>
                                Switch to 7 Days
                              </Button>
                              <Button size="sm" kind="tertiary" onClick={() => setTimeWindow('30d')}>
                                Switch to 30 Days
                              </Button>
                            </div>
                          )}
                        </TableCell>
                      </TableRow>
                    ) : (
                      rows.map((row) => {
                        const rowData = tableRows.find((r) => r.id === row.id);
                        const raw = rowData?.raw || logsMap.get(row.id) || paginatedLogs.find((l) => String(l.id) === row.id) || {
                          id: row.id,
                          timestamp: new Date().toISOString(),
                          client_ip: '-',
                          country: 'XX',
                          method: 'GET',
                          host: 'api.aegis.internal',
                          path: '/',
                          status_code: 403,
                          action: 'BLOCK',
                          blocked: true,
                          rule_name: 'Threat Intercepted',
                          severity: 'high',
                        } as SecurityEventItem;

                        const isBlocked = rowData?.isBlocked ?? Boolean(raw.blocked ?? (String(raw.action).toUpperCase() === 'BLOCK'));
                                                                        const { key, ...rowProps } = getRowProps({ row });

                        return (
                          <TableRow key={key} {...rowProps}>
                            <TableCell>
                              <EventTimeCell timestamp={raw.timestamp} />
                            </TableCell>

                            <TableCell>
                              <EventSourceCell ip={raw.client_ip} country={raw.country} />
                            </TableCell>

                            <TableCell>
                              <EventMethodTag method={raw.method} />
                            </TableCell>

                            <TableCell>
                              <EventPathCell path={raw.path} maxWidth="240px" />
                            </TableCell>

                            <TableCell>
                              <EventStatusTag status={raw.status_code} showLabel={false} />
                            </TableCell>

                            <TableCell>
                              <EventRuleCell rule={raw.rule_name} id={raw.rule_id} maxWidth="240px" />
                            </TableCell>

                            <TableCell>
                              <EventActionBadge action={raw.action || (isBlocked ? 'BLOCK' : 'ALLOW')} />
                            </TableCell>

                            <TableCell style={{ textAlign: 'right' }}>
                              <EventInspectButton onClick={() => setSelectedLog(raw)} />
                            </TableCell>
                          </TableRow>
                        );
                      })
                    )}
                  </TableBody>
                </Table>

                <Pagination
                  totalItems={totalItems}
                  pageSize={pageSize}
                  pageSizes={[10, 25, 50, 100]}
                  page={currentPage}
                  onChange={({ page, pageSize: newPageSize }) => {
                    setCurrentPage(page);
                    setPageSize(newPageSize);
                  }}
                />
              </TableContainer>
            )}
          </DataTable>
        )}
      </div>

      <EventInspectorModal
        open={!!selectedLog}
        event={selectedLog}
        onClose={() => setSelectedLog(null)}
        sectionLabel="Threat Telemetry"
        onApplyFilter={(_field, val) => {
          setSearchQuery(val);
          setCurrentPage(1);
        }}
        onNavigate={onNavigate}
      />
    </div>
  );
};
