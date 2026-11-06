import React, { useState, useEffect, useCallback } from 'react';
import {
  DataTable,
  TableContainer,
  Table,
  TableHead,
  TableRow,
  TableHeader,
  TableBody,
  TableCell,
  Button,
  Pagination,
  DataTableSkeleton,
  InlineNotification,
  TextInput,
  Grid,
  Column,
  Layer,
  Form,
  FormGroup,
} from '@carbon/react';
import {
  Renew,
  Download,
  Document,
  UserAdmin,
} from '@carbon/icons-react';
import { PageHeader } from '../components/common';
import { apiService } from '../services/api';
import type { AuditEntry, AuditLogsMeta } from '../types';
import './AuditLogsPage.scss';

interface AuditPageRecord {
  logs: AuditEntry[];
  meta?: AuditLogsMeta;
}

interface AuditFilters {
  action: string;
  actor: string;
  from: string;
  to: string;
}

function toAuditISOTime(value: string): string {
  if (!value) return '';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '' : date.toISOString();
}

function formatAuditTime(value?: string): string {
  if (!value) return 'Unknown';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Unknown' : date.toLocaleString();
}

function isOpaqueAuditResource(resource: string): boolean {
  return /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(resource);
}

function formatAuditAction(action: string): string {
  return (
    action
      .split(':')
      .filter(Boolean)
      .map((part) => part.replace(/[_-]+/g, ' ').replace(/\b\w/g, (char) => char.toUpperCase()))
      .join(': ') || 'System event'
  );
}

function describeAuditActivity(log: AuditEntry): { title: string; detail: string } {
  const action = log.action || 'system:event';
  const titles: Record<string, string> = {
    'auth:login_success': 'Signed in',
    'auth:login_failure': 'Sign-in failed',
    'auth:logout': 'Signed out',
    'auth:mfa_enable': 'Enabled multi-factor authentication',
    'auth:mfa_disable': 'Disabled multi-factor authentication',
    'auth:mfa_failure': 'Multi-factor authentication failed',
    'alerts:read': 'Viewed alerts',
  };
  const details: Record<string, string> = {
    'auth:login_success': 'Administrator session established.',
    'auth:logout': 'Administrator session ended.',
    'auth:mfa_enable': 'Multi-factor authentication is now enabled.',
    'auth:mfa_disable': 'Multi-factor authentication is now disabled.',
  };
  const rawDetail = log.details || log.metadata || '';
  const resource = log.resource && !isOpaqueAuditResource(log.resource) ? `Affected: ${log.resource}` : '';
  return {
    title: titles[action] || formatAuditAction(action),
    detail: details[action] || rawDetail || resource || 'No additional context was recorded.',
  };
}

const TABLE_HEADERS = [
  { key: 'time', header: 'Time' },
  { key: 'actor', header: 'Actor' },
  { key: 'activity', header: 'Activity' },
  { key: 'ip', header: 'Source IP' },
];

export const AuditLogsPage: React.FC = () => {
  const [logs, setLogs] = useState<AuditEntry[]>([]);
  const [meta, setMeta] = useState<AuditLogsMeta | undefined>(undefined);
  const [pageIndex, setPageIndex] = useState<number>(0);
  const [pageSize, setPageSize] = useState<number>(20);
  const [pages, setPages] = useState<AuditPageRecord[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [exporting, setExporting] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [notification, setNotification] = useState<{ kind: 'success' | 'error' | 'info'; message: string } | null>(null);

  const [actionInput, setActionInput] = useState<string>('');
  const [actorInput, setActorInput] = useState<string>('');
  const [fromInput, setFromInput] = useState<string>('');
  const [toInput, setToInput] = useState<string>('');

  const [appliedFilters, setAppliedFilters] = useState<AuditFilters>({
    action: '',
    actor: '',
    from: '',
    to: '',
  });

  const fetchAuditPage = useCallback(
    async (cursor: string, targetPage: number, filters: AuditFilters = appliedFilters, size: number = pageSize) => {
      setLoading(true);
      setError(null);
      try {
        const fromISO = toAuditISOTime(filters.from);
        const toISO = toAuditISOTime(filters.to);
        const response = await apiService.getAuditLogs({
          limit: size,
          cursor: cursor || undefined,
          action: filters.action || undefined,
          actor: filters.actor || undefined,
          from: fromISO || undefined,
          to: toISO || undefined,
        });

        const fetchedLogs = response.data || [];
        setLogs(fetchedLogs);
        setMeta(response.meta);
        setPageIndex(targetPage);

        setPages((prevPages) => {
          const nextPages = [...prevPages];
          nextPages[targetPage] = { logs: fetchedLogs, meta: response.meta };
          nextPages.length = targetPage + 1;
          return nextPages;
        });
      } catch (err: any) {
        console.error('Failed to load audit logs:', err);
        setError(err?.message || 'Unable to load audit records. Refresh the page to retry.');
        setLogs([]);
        setMeta(undefined);
      } finally {
        setLoading(false);
      }
    },
    [appliedFilters, pageSize]
  );

  useEffect(() => {
    fetchAuditPage('', 0, { action: '', actor: '', from: '', to: '' }, 20);
  }, []);

  const handleApplyFilters = (e: React.FormEvent) => {
    e.preventDefault();
    const nextFilters: AuditFilters = {
      action: actionInput.trim(),
      actor: actorInput.trim(),
      from: fromInput.trim(),
      to: toInput.trim(),
    };
    setAppliedFilters(nextFilters);
    setPageIndex(0);
    setPages([]);
    fetchAuditPage('', 0, nextFilters, pageSize);
  };

  const handleClearFilters = () => {
    setActionInput('');
    setActorInput('');
    setFromInput('');
    setToInput('');
    const cleared: AuditFilters = { action: '', actor: '', from: '', to: '' };
    setAppliedFilters(cleared);
    setPageIndex(0);
    setPages([]);
    fetchAuditPage('', 0, cleared, pageSize);
  };

  const handleRefresh = () => {
    setPageIndex(0);
    setPages([]);
    fetchAuditPage('', 0, appliedFilters, pageSize);
  };

  const handleNextPage = () => {
    if (!meta?.next_cursor) return;
    fetchAuditPage(meta.next_cursor, pageIndex + 1, appliedFilters, pageSize);
  };

  const handlePreviousPage = () => {
    if (pageIndex <= 0) return;
    const targetPage = pageIndex - 1;
    const cachedPage = pages[targetPage];
    if (cachedPage) {
      setPageIndex(targetPage);
      setLogs(cachedPage.logs);
      setMeta(cachedPage.meta);
    }
  };

  const handlePageSizeChange = (newPageSize: number) => {
    setPageSize(newPageSize);
    setPageIndex(0);
    setPages([]);
    fetchAuditPage('', 0, appliedFilters, newPageSize);
  };

  const handleExportCSV = async () => {
    setExporting(true);
    try {
      const fromISO = toAuditISOTime(appliedFilters.from);
      const toISO = toAuditISOTime(appliedFilters.to);
      const { blob, truncated } = await apiService.exportAuditLogs({
        action: appliedFilters.action || undefined,
        actor: appliedFilters.actor || undefined,
        from: fromISO || undefined,
        to: toISO || undefined,
      });

      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'aegis-audit-logs.csv';
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);

      setNotification({
        kind: 'success',
        message: truncated
          ? 'Exported the first 5,000 matching audit records.'
          : 'Audit log export downloaded.',
      });
    } catch (err: any) {
      console.error('Failed to export audit logs:', err);
      setNotification({
        kind: 'error',
        message: err instanceof Error ? err.message : 'Audit export failed.',
      });
    } finally {
      setExporting(false);
    }
  };

  const count = meta?.count ?? logs.length;
  const start = count ? pageIndex * pageSize + 1 : 0;
  const end = count ? start + count - 1 : 0;

  const tableRows = logs.map((log, idx) => ({
    id: log.id || `audit-${pageIndex}-${idx}`,
    time: log.created_at || '',
    actor: log.username || 'System',
    activity: log.action || '',
    ip: log.ip_address || '-',
  }));

  return (
    <main className="audit-logs-page" id="main-content">
      <PageHeader
        kicker="System"
        title="Audit logs"
        icon={Document}
        action={
          <div className="audit-logs-header-actions">
            <Button
              kind="ghost"
              size="md"
              renderIcon={Renew}
              onClick={handleRefresh}
              disabled={loading}
            >
              Refresh
            </Button>
            <Button
              kind="tertiary"
              size="md"
              renderIcon={Download}
              onClick={handleExportCSV}
              disabled={loading || exporting}
            >
              Export CSV
            </Button>
          </div>
        }
      />

      {notification && (
        <div className="audit-logs-notification">
          <InlineNotification
            kind={notification.kind}
            title={notification.message}
            onCloseButtonClick={() => setNotification(null)}
          />
        </div>
      )}

      {loading ? (
        <DataTableSkeleton headers={TABLE_HEADERS} rowCount={8} columnCount={TABLE_HEADERS.length} />
      ) : (
        <DataTable rows={tableRows} headers={TABLE_HEADERS}>
          {({ rows, headers, getTableProps, getHeaderProps, getRowProps }) => (
            <TableContainer
              title="Recent activity"
              aria-busy={loading ? 'true' : 'false'}
            >
              <Layer level={1}>
                <Form
                  onSubmit={handleApplyFilters}
                  aria-label="Filter audit activity"
                  className="audit-filter-form"
                >
                  <Grid fullWidth className="audit-filter-grid">
                    <Column sm={4} md={4} lg={4}>
                      <TextInput
                        id="audit-filter-action"
                        labelText="Action"
                        placeholder="auth:login_success"
                        size="md"
                        maxLength={128}
                        value={actionInput}
                        onChange={(e) => setActionInput(e.target.value)}
                      />
                    </Column>

                    <Column sm={4} md={4} lg={4}>
                      <TextInput
                        id="audit-filter-actor"
                        labelText="Actor"
                        placeholder="security-operator"
                        size="md"
                        maxLength={128}
                        value={actorInput}
                        onChange={(e) => setActorInput(e.target.value)}
                      />
                    </Column>

                    <Column sm={4} md={8} lg={5}>
                      <FormGroup legendText="Time range" className="audit-filter-range-group">
                        <div className="audit-filter-range-controls">
                          <TextInput
                            id="audit-filter-from"
                            labelText="From local time"
                            hideLabel
                            type="datetime-local"
                            size="md"
                            value={fromInput}
                            onChange={(e) => setFromInput(e.target.value)}
                            aria-label="From local time"
                          />
                          <span
                            className="audit-filter-separator"
                            aria-hidden="true"
                          >
                            to
                          </span>
                          <TextInput
                            id="audit-filter-to"
                            labelText="To local time"
                            hideLabel
                            type="datetime-local"
                            size="md"
                            value={toInput}
                            onChange={(e) => setToInput(e.target.value)}
                            aria-label="To local time"
                          />
                        </div>
                      </FormGroup>
                    </Column>

                    <Column sm={4} md={8} lg={3} className="audit-filter-actions">
                      <Button size="md" kind="primary" type="submit" disabled={loading}>
                        Apply
                      </Button>
                      <Button size="md" kind="secondary" type="button" onClick={handleClearFilters} disabled={loading}>
                        Clear
                      </Button>
                    </Column>
                  </Grid>
                </Form>
              </Layer>

              <Table {...getTableProps()} size="lg" useZebraStyles={false} aria-label="Audit logs activity table">
                <TableHead>
                  <TableRow>
                    {headers.map((header) => (
                      <TableHeader
                        {...getHeaderProps({ header })}
                        key={header.key}
                      >
                        {header.header}
                      </TableHeader>
                    ))}
                  </TableRow>
                </TableHead>

                <TableBody>
                  {rows.map((row, index) => {
                    const log = logs[index];
                    if (!log) return null;
                    const activity = describeAuditActivity(log);
                    const sourceIP = log.ip_address || '-';
                    const sourceDetail = log.ip_address_source
                      ? `${log.ip_address_source}${log.peer_ip_address ? ` via ${log.peer_ip_address}` : ''}`
                      : '';

                    return (
                      <TableRow {...getRowProps({ row })} key={row.id}>
                        <TableCell className="audit-table-time-cell">
                          <time>
                            {formatAuditTime(log.created_at)}
                          </time>
                        </TableCell>

                        <TableCell>
                          <div className="audit-actor-wrapper">
                            <div
                              className="audit-actor-icon-box"
                              aria-hidden="true"
                            >
                              <UserAdmin size={16} />
                            </div>
                            <span className="audit-actor-name">
                              {log.username || 'System'}
                            </span>
                          </div>
                        </TableCell>

                        <TableCell>
                          <div className="audit-activity-wrapper">
                            <strong className="audit-activity-title">
                              {activity.title}
                            </strong>
                            <span className="audit-activity-detail">
                              {activity.detail}
                            </span>
                          </div>
                        </TableCell>

                        <TableCell>
                          <span
                            className="audit-source-ip"
                            title={sourceDetail || sourceIP}
                          >
                            {sourceIP}
                          </span>
                        </TableCell>
                      </TableRow>
                    );
                  })}

                  {rows.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={4} className="audit-empty-cell">
                        <div className="audit-empty-content">
                          <Document size={32} className="audit-empty-icon" />
                          <div className="audit-empty-title">
                            {error ? 'Audit logs unavailable' : 'No audit records'}
                          </div>
                          <div className="audit-empty-subtitle">
                            {error
                              ? 'Unable to load audit records. Refresh the page to retry.'
                              : 'No audit records match the current filter criteria.'}
                          </div>
                        </div>
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>

              <Pagination
                backwardText="Previous page"
                forwardText="Next page"
                itemsPerPageText="Rows per page:"
                page={pageIndex + 1}
                pageSize={pageSize}
                pageSizes={[20, 50, 100, 200]}
                pagesUnknown={true}
                isLastPage={!meta?.next_cursor}
                totalItems={logs.length === 0 ? 0 : undefined}
                itemText={() => (count ? `Showing ${start}–${end}` : 'No audit records')}
                itemRangeText={() => 'No audit records'}
                pageText={(p) => `Page ${p}`}
                onChange={({ page, pageSize: newPageSize }) => {
                  if (newPageSize !== pageSize) {
                    handlePageSizeChange(newPageSize);
                  } else if (page > pageIndex + 1) {
                    handleNextPage();
                  } else if (page < pageIndex + 1) {
                    handlePreviousPage();
                  }
                }}
              />
            </TableContainer>
          )}
        </DataTable>
      )}
    </main>
  );
};
