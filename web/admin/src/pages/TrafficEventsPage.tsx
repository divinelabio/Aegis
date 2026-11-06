import {
  EventTimeCell,
  EventMethodTag,
  EventPathCell,
  EventStatusTag,
  EventSourceCell,
  EventInspectButton,
  EventInspectorModal,
} from '../components/events';
import React, { useEffect, useState, useMemo } from 'react';
import {
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
  Tag,
  Select,
  SelectItem,
  Modal,
  InlineNotification,
  DataTableSkeleton,
  SkeletonText,
  SkeletonPlaceholder,
  PaginationSkeleton,
  TextInput,
  Tile,
Pagination,
  ProgressBar,
  Layer,
  useTheme,
  ContentSwitcher,
  Switch,
} from '@carbon/react';
import {
  Renew,
Filter,
  Maximize,
  Activity,
  ChevronDown,
  ChevronUp,
  Information,
  Launch,
WarningAlt,
} from '@carbon/icons-react';
import { AreaChart, StackedAreaChart } from '@carbon/charts-react';
import { ScaleTypes, ChartTheme } from '@carbon/charts';
import type {
  AreaChartOptions,
  StackedAreaChartOptions,
  ChartTabularData,
} from '@carbon/charts';
import { PageHeader, MetricStrip, KpiCard } from '../components/common';
import { COUNTRIES_MAP, normalizeToCountryCode } from '../data/geoData';
import { countryCodeToFlag } from '../components/common/CountryBadge';
import type {
  SecurityEventItem,
  TrafficEventsDashboardData,
  TrafficEventsSummary,
  TrafficEventsBreakdownItem,
  NavItemKey,
} from '../types';
import { apiService } from '../services/api';

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

function formatCompact(value: number): string {
  if (!value) return '0';
  const formatted = new Intl.NumberFormat('en-US', {
    notation: 'compact',
    maximumFractionDigits: 1,
  }).format(value);
  return formatted.replace(/([KMBT])$/i, (m) => m.toUpperCase());
}

function formatTrafficBytes(value: number): string {
  const bytes = Math.max(0, Number(value) || 0);
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let amount = bytes / 1024;
  let index = 0;
  while (amount >= 1024 && index < units.length - 1) {
    amount /= 1024;
    index += 1;
  }
  return `${new Intl.NumberFormat(undefined, { maximumFractionDigits: amount >= 100 ? 0 : 1 }).format(amount)} ${units[index]}`;
}

function formatEventTime(timestamp: string | number | undefined): string {
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
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return String(timestamp);
  }
}

function isMonoValue(filterKey: string, val: string): boolean {
  if (['path', 'ip', 'ja3', 'ja4', 'asn', 'rule_id', 'matched_field', 'status', 'method', 'methods', 'status_class'].includes(filterKey)) return true;
  if (typeof val === 'string' && (val.startsWith('/') || /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(val))) return true;
  return false;
}

function renderTrafficItemLabelText(dimensionKey: string, item: TrafficEventsBreakdownItem): string {
  const raw = String(item.value || item.label || '—');
  if (dimensionKey === 'countries') {
    const code = raw.trim().toUpperCase();
    if (countryNames[code]) return countryNames[code];
  }
  if (dimensionKey === 'methods') {
    return raw.toUpperCase();
  }
  return raw;
}

function getTrafficBarColor(dimensionKey: string, item: TrafficEventsBreakdownItem): string {
  const val = (item.value || item.label || '').toLowerCase();
  if (dimensionKey === 'status' || dimensionKey === 'status_codes' || dimensionKey === 'status_class') {
    if (val.startsWith('2')) return 'var(--cds-support-success, #24a148)';
    if (val.startsWith('3')) return 'var(--cds-text-secondary, #8d8d8d)';
    if (val.startsWith('4')) return 'var(--cds-support-warning, #ff832b)';
    if (val.startsWith('5')) return 'var(--cds-support-error, #da1e28)';
  }
  return 'var(--cds-interactive, #eb6200)';
}

function formatNumber(n?: number): string {
  return new Intl.NumberFormat().format(n || 0);
}

function renderTrafficItemPrefix(dimensionKey: string, item: TrafficEventsBreakdownItem): React.ReactNode {
  if (dimensionKey === 'countries') {
    const code = String(item.value || item.label || '').trim().toUpperCase();
    if (code.length === 2 && /^[A-Z]{2}$/.test(code) && code !== 'XX') {
      return (
        <span
          style={{
            fontFamily: 'var(--cds-font-mono, monospace)',
            fontSize: '10px',
            fontWeight: 600,
            color: 'var(--cds-text-secondary)',
            marginRight: '6px',
          }}
        >
          {code}
        </span>
      );
    }
  }
  return null;
}

function hasLaunchIcon(dimensionKey: string): boolean {
  const k = dimensionKey.toLowerCase();
  return k.includes('ip') || k.includes('host') || k.includes('domain') || k.includes('url') || k.includes('uri') || k.includes('path');
}

interface TrafficEventsPageProps {
  onNavigate?: (key: NavItemKey) => void;
}

export const TrafficEventsPage: React.FC<TrafficEventsPageProps> = ({ onNavigate }) => {
  const { theme } = useTheme();
  const [trafficChartMode, setTrafficChartMode] = useState<'volume' | 'status'>('volume');
  const [dashboard, setDashboard] = useState<TrafficEventsDashboardData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [notification, setNotification] = useState<{ kind: 'success' | 'error'; message: string } | null>(null);

  const [timeWindow, setTimeWindow] = useState<string>('24h');
  const [customSince, setCustomSince] = useState<string>('');
  const [customUntil, setCustomUntil] = useState<string>('');
  const [showTimeModal, setShowTimeModal] = useState<boolean>(false);

  const [activeFilters, setActiveFilters] = useState<Record<string, string>>({});
  const [filterModalOpen, setFilterModalOpen] = useState<boolean>(false);
  const [newFilterField, setNewFilterField] = useState<string>('path');
  const [newFilterOp, setNewFilterOp] = useState<string>('equals');
  const [newFilterValue, setNewFilterValue] = useState<string>('');

  const [searchQuery, setSearchQuery] = useState<string>('');
  const [pageSize, setPageSize] = useState<number>(20);
  const [currentPage, setCurrentPage] = useState<number>(1);

  const [selectedEvent, setSelectedEvent] = useState<SecurityEventItem | null>(null);
  const [statsModalData, setStatsModalData] = useState<{ title: string; filterKey: string; items: TrafficEventsBreakdownItem[] } | null>(null);
  const [showAllBreakdowns, setShowAllBreakdowns] = useState<boolean>(false);
  const [storageWarningDismissed, setStorageWarningDismissed] = useState<boolean>(false);

  const [chartsReady, setChartsReady] = useState<boolean>(false);
  useEffect(() => {
    if (!loading && (dashboard?.timeseries?.length || 0) > 0) {
      const timer = setTimeout(() => {
        setChartsReady(true);
      }, 50);
      return () => clearTimeout(timer);
    } else if (loading) {
      setChartsReady(false);
    }
  }, [loading, dashboard?.timeseries?.length]);

  const loadData = async () => {
    setLoading(true);
    try {
      const query: Record<string, any> = {
        window: timeWindow === 'custom' ? '24h' : timeWindow,
        ...activeFilters,
      };
      if (timeWindow === 'custom' && customSince) {
        const d = new Date(customSince);
        query.since = !isNaN(d.getTime()) ? d.toISOString() : customSince;
      }
      if (timeWindow === 'custom' && customUntil) {
        const d = new Date(customUntil);
        query.until = !isNaN(d.getTime()) ? d.toISOString() : customUntil;
      }

      const data = await apiService.getTrafficEventsDashboard(query);
      setDashboard(data);
    } catch {
      setNotification({ kind: 'error', message: 'Failed to load traffic events telemetry' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [timeWindow, activeFilters]);

  const handleApplyFilter = (key: string, val: string) => {
    setActiveFilters((prev) => ({ ...prev, [key]: val }));
    setCurrentPage(1);
  };

  const handleRemoveFilter = (key: string) => {
    setActiveFilters((prev) => {
      const next = { ...prev };
      delete next[key];
      return next;
    });
    setCurrentPage(1);
  };

  const handleClearFilters = () => {
    setActiveFilters({});
    setCurrentPage(1);
  };

  const handleAddFilterFromModal = () => {
    if (!newFilterValue.trim()) return;
    handleApplyFilter(newFilterField, newFilterValue.trim());
    setNewFilterValue('');
    setFilterModalOpen(false);
  };

  const summary: TrafficEventsSummary = dashboard?.summary || {
    total_requests: 0,
    status_2xx: 0,
    status_3xx: 0,
    status_4xx: 0,
    status_5xx: 0,
    avg_latency_ms: 0,
    p95_latency_ms: 0,
    unique_source_ips: 0,
    unique_countries: 0,
    total_bytes_sent: 0,
    current_rps: 0,
  };

  const totalReq = summary.total_requests || 1;
  const serverErrors = summary.status_5xx || 0;
  const errorPercent = totalReq > 0 ? (serverErrors / totalReq) * 100 : 0;

  const allEvents = dashboard?.events?.events || [];
  const filteredEvents = useMemo(() => {
    if (!searchQuery.trim()) return allEvents;
    const q = searchQuery.toLowerCase();
    return allEvents.filter(
      (e) =>
        (e.client_ip || '').toLowerCase().includes(q) ||
        (e.path || '').toLowerCase().includes(q) ||
        (e.host || '').toLowerCase().includes(q) ||
        (e.route_name || '').toLowerCase().includes(q) ||
        (e.rule_name || '').toLowerCase().includes(q)
    );
  }, [allEvents, searchQuery]);

  const totalEvents = filteredEvents.length;
  const paginatedEvents = filteredEvents.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const eventsById = useMemo(() => {
    const map = new Map<string, SecurityEventItem>();
    allEvents.forEach((evt, idx) => {
      const key = String(evt.id || `evt-${idx}`);
      map.set(key, evt);
    });
    return map;
  }, [allEvents]);

  const breakdownCardsDef: Array<{ key: string; title: string; filterKey: string }> = [
    { key: 'ips', title: 'Top Source IPs', filterKey: 'ip' },
    { key: 'hosts', title: 'Top Hosts', filterKey: 'host' },
    { key: 'routes', title: 'Top Routes', filterKey: 'route' },
    { key: 'upstreams', title: 'Top Upstreams', filterKey: 'upstream' },
    { key: 'paths', title: 'Top Paths', filterKey: 'path' },
    { key: 'methods', title: 'Methods', filterKey: 'method' },
    { key: 'http_versions', title: 'HTTP Version', filterKey: 'http_version' },
    { key: 'status', title: 'Status Codes', filterKey: 'status' },
    { key: 'content_types', title: 'Response Content Type', filterKey: 'content_type' },
    { key: 'user_agents', title: 'User Agents', filterKey: 'user_agent' },
    { key: 'countries', title: 'Countries', filterKey: 'country' },
    { key: 'ip_versions', title: 'IP Version', filterKey: 'ip_version' },
    { key: 'ja3', title: 'JA3 Fingerprints', filterKey: 'ja3' },
    { key: 'ja4', title: 'JA4 Fingerprints', filterKey: 'ja4' },
    { key: 'tls_versions', title: 'TLS Version', filterKey: 'tls_version' },
    { key: 'asn', title: 'Autonomous Systems (ASN)', filterKey: 'asn' },
  ];

  const visibleCards = showAllBreakdowns ? breakdownCardsDef : breakdownCardsDef.slice(0, 8);

  const timeseries = dashboard?.timeseries || [];
  const chartThemeName = theme === 'g100' ? ChartTheme.G100 : ChartTheme.G10;

  const areaData = useMemo<ChartTabularData>(() => {
    if (!timeseries || timeseries.length === 0) return [];
    return timeseries.map((pt) => {
      const total = Object.values(pt.counts || {}).reduce((a, b) => a + Number(b), 0);
      const isoDate = new Date(pt.timestamp < 1e11 ? pt.timestamp * 1000 : pt.timestamp).toISOString();
      return {
        group: 'Requests',
        date: isoDate,
        value: total,
      };
    });
  }, [timeseries]);

  const stackedAreaData = useMemo<ChartTabularData>(() => {
    if (!timeseries || timeseries.length === 0) return [];
    return timeseries.flatMap((pt) => {
      const isoDate = new Date(pt.timestamp < 1e11 ? pt.timestamp * 1000 : pt.timestamp).toISOString();
      const counts = pt.counts || {};
      return [
        { group: '2xx Success', date: isoDate, value: Number(counts['2xx'] || 0) },
        { group: '3xx Redirect', date: isoDate, value: Number(counts['3xx'] || 0) },
        { group: '4xx Client Error', date: isoDate, value: Number(counts['4xx'] || 0) },
        { group: '5xx Server Error', date: isoDate, value: Number(counts['5xx'] || 0) },
      ];
    });
  }, [timeseries]);

  const areaOptions: AreaChartOptions = useMemo(() => ({
    axes: {
      bottom: {
        mapsTo: 'date',
        scaleType: ScaleTypes.TIME,
      },
      left: {
        mapsTo: 'value',
        scaleType: ScaleTypes.LINEAR,
        ticks: {
          number: 4,
          formatter: (val: number | Date) => formatCompact(Number(val)),
        },
      },
    },
    curve: 'curveMonotoneX',
    height: '280px',
    resizable: true,
    theme: chartThemeName,
    color: {
      scale: {
        Requests: '#eb6200',
      },
    },
    toolbar: {
      enabled: false,
    },
    legend: {
      enabled: false,
    },
    timeScale: {
      addSpaceOnEdges: 0,
    },
  }), [chartThemeName]);

  const stackedAreaOptions: StackedAreaChartOptions = useMemo(() => ({
    axes: {
      bottom: {
        mapsTo: 'date',
        scaleType: ScaleTypes.TIME,
      },
      left: {
        mapsTo: 'value',
        scaleType: ScaleTypes.LINEAR,
        stacked: true,
        ticks: {
          number: 4,
          formatter: (val: number | Date) => formatCompact(Number(val)),
        },
      },
    },
    curve: 'curveMonotoneX',
    height: '280px',
    resizable: true,
    theme: chartThemeName,
    color: {
      scale: {
        '2xx Success': '#198038',
        '3xx Redirect': '#0072c3',
        '4xx Client Error': '#f1c21b',
        '5xx Server Error': '#da1e28',
      },
    },
    toolbar: {
      enabled: false,
    },
    legend: {
      enabled: false,
    },
    timeScale: {
      addSpaceOnEdges: 0,
    },
  }), [chartThemeName]);

  const r2xx = summary.status_2xx || 0;
  const r3xx = summary.status_3xx || 0;
  const r4xx = summary.status_4xx || 0;
  const r5xx = summary.status_5xx || 0;
  const sumResp = r2xx + r3xx + r4xx + r5xx;
  const safeResp = sumResp || 1;

  const p2xx = (r2xx / safeResp) * 100;
  const p3xx = (r3xx / safeResp) * 100;
  const p4xx = (r4xx / safeResp) * 100;
  const p5xx = (r5xx / safeResp) * 100;

  const tableHeaders = [
    { key: 'timestamp', header: 'Time' },
    { key: 'method', header: 'Method' },
    { key: 'path', header: 'Path' },
    { key: 'host', header: 'Host' },
    { key: 'status_code', header: 'Status' },
    { key: 'client_ip', header: 'Source' },
    { key: 'actions', header: '' },
  ];

  const tableRows = useMemo(() => {
    return paginatedEvents.map((evt, idx) => ({
      id: String(evt.id || `evt-${idx}`),
      time: formatEventTime(evt.timestamp),
      method: evt.method || 'GET',
      path: evt.path || '/',
      host: evt.host || '-',
      status: evt.status_code || 200,
      source: (() => {
        const countryCode = getValidCountryCode(evt.country, evt.client_ip);
        const flag = countryCode ? countryCodeToFlag(countryCode) : '';
        const countryName = countryCode ? (COUNTRIES_MAP[countryCode] || countryCode) : '';
        return countryCode
          ? `${flag ? `${flag} ` : ''}${countryCode} ${countryName} · ${evt.client_ip || '-'}`
          : (evt.client_ip || '-');
      })(),
    }));
  }, [paginatedEvents]);

  return (
    <div className="security-events-shell">
      <PageHeader
        kicker="Threat operations"
        title="Traffic events"
        icon={Activity}
        badge={
          Object.keys(activeFilters).length > 0 ? (
            <Tag type="high-contrast" size="sm" >
              {Object.keys(activeFilters).length} Filter{Object.keys(activeFilters).length > 1 ? 's' : ''} Active
            </Tag>
          ) : undefined
        }
        action={
          <div className="security-events-command-bar">
            <Select
              id="traffic-time-select"
              labelText="Time window filter"
              aria-label="Time window"
              hideLabel
              inline
              size="sm"
              value={['15m', '1h', '24h', '7d', '30d'].includes(timeWindow) ? timeWindow : 'custom'}
              onChange={(e) => {
                if (e.target.value === 'custom') {
                  setShowTimeModal(true);
                } else {
                  setTimeWindow(e.target.value);
                }
              }}
              style={{ width: '130px' }}
            >
              <SelectItem value="15m" text="Last 15m" />
              <SelectItem value="1h" text="Last 1h" />
              <SelectItem value="24h" text="Last 24h" />
              <SelectItem value="7d" text="Last 7d" />
              <SelectItem value="30d" text="Last 30d" />
              {!['15m', '1h', '24h', '7d', '30d'].includes(timeWindow) && (
                <SelectItem value="custom" text="Custom range..." />
              )}
            </Select>

            <Button
              kind="secondary"
              size="sm"
              renderIcon={Filter}
              
              onClick={() => setFilterModalOpen(true)}
            >
              Add filter
            </Button>

            <Button
              kind="ghost"
              size="sm"
              renderIcon={Renew}
              hasIconOnly
              iconDescription="Refresh Telemetry"
              
              disabled={loading}
              onClick={loadData}
            />
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

      {dashboard?.health?.db_available === false && !storageWarningDismissed && (
        <InlineNotification
          kind="warning"
          title="Analytics Storage Offline"
          subtitle={dashboard.health.message || 'Storage database is disconnected. Showing live in-memory telemetry; historical data is unavailable.'}
          onCloseButtonClick={() => setStorageWarningDismissed(true)}
        />
      )}

      {Object.keys(activeFilters).length > 0 && (
        <div className="security-filter-bar">
          <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--cds-text-secondary)' }}>
            Active Filters:
          </span>
          <div className="security-filter-chips">
            {Object.entries(activeFilters).map(([k, v]) => (
              <Tag
                key={k}
                type="warm-gray"
                size="sm"
                filter
                
                onClose={() => handleRemoveFilter(k)}
              >
                <strong>{k}:</strong> {v}
              </Tag>
            ))}
          </div>
          <Button kind="ghost" size="sm"  onClick={handleClearFilters}>
            Clear all
          </Button>
        </div>
      )}

      <MetricStrip columns={6} minColWidth="120px">
        <KpiCard
          label="Total requests"
          value={formatCompact(summary.total_requests)}
          subtext={`Last ${timeWindow === 'custom' ? 'Custom' : timeWindow}`}
          status="default"
          onClick={handleClearFilters}
          loading={loading}
        />
        <KpiCard
          label="Request rate"
          value={`${summary.current_rps.toFixed(1)} rps`}
          subtext="Current 1-min rate"
          status="default"
          loading={loading}
        />
        <KpiCard
          label="Unique source IPs"
          value={formatCompact(summary.unique_source_ips)}
          subtext={`${summary.unique_countries} countries`}
          status="default"
          loading={loading}
        />
        <KpiCard
          label="Bandwidth"
          value={formatTrafficBytes(summary.total_bytes_sent)}
          subtext="Response bytes egressed"
          status="default"
          loading={loading}
        />
        <KpiCard
          label="P95 latency"
          value={`${summary.p95_latency_ms.toFixed(1)} ms`}
          subtext={`Avg ${summary.avg_latency_ms.toFixed(1)} ms`}
          status="default"
          loading={loading}
        />
        <KpiCard
          label="5xx Server errors"
          value={`${errorPercent.toFixed(2)}%`}
          subtext={`${formatCompact(serverErrors)} server errors`}
          status="default"
          onClick={() => handleApplyFilter('status_class', '5xx')}
          loading={loading}
        />
      </MetricStrip>

      <Tile className="security-events-chart-card">
        <div className="security-events-chart-header">
          <div>
            <h4 className="security-events-chart-title">Traffic overview</h4>
          </div>
          <ContentSwitcher
            size="sm"
            selectedIndex={trafficChartMode === 'volume' ? 0 : 1}
            onChange={(e) => setTrafficChartMode(e.name === 'volume' ? 'volume' : 'status')}
            className="security-events-switcher"
          >
            <Switch name="volume" text="Volume" />
            <Switch name="status" text="By status" />
          </ContentSwitcher>
        </div>

        <div className="security-events-status-legend">
          {loading ? (
            <>
              <span className="security-events-legend-item">
                <SkeletonText width="140px" />
              </span>
              <span className="security-events-legend-item">
                <SkeletonText width="120px" />
              </span>
              <span className="security-events-legend-item" style={{ marginLeft: 'auto' }}>
                <SkeletonText width="100px" />
              </span>
            </>
          ) : trafficChartMode === 'volume' ? (
            <span className="security-events-legend-item">
              <span className="security-events-legend-square" style={{ background: '#eb6200' }} />
              Total requests ({formatCompact(summary.total_requests)})
            </span>
          ) : (
            <>
              <span className="security-events-legend-item">
                <span className="security-events-legend-square" style={{ background: '#24a148' }} />
                2xx Successful ({formatCompact(r2xx)} · {p2xx.toFixed(1)}%)
              </span>
              <span className="security-events-legend-item">
                <span className="security-events-legend-square" style={{ background: '#8d8d8d' }} />
                3xx Redirect ({formatCompact(r3xx)} · {p3xx.toFixed(1)}%)
              </span>
              <span className="security-events-legend-item">
                <span className="security-events-legend-square" style={{ background: '#ff832b' }} />
                4xx Client error ({formatCompact(r4xx)} · {p4xx.toFixed(1)}%)
              </span>
              <span className="security-events-legend-item">
                <span className="security-events-legend-square" style={{ background: '#da1e28' }} />
                5xx Server error ({formatCompact(r5xx)} · {p5xx.toFixed(1)}%)
              </span>
            </>
          )}
        </div>

        <div style={{ width: '100%', height: '280px', marginTop: '10px' }}>
          {loading || (!chartsReady && timeseries.length > 0) ? (
            <div style={{ width: '100%', height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
              <SkeletonPlaceholder style={{ width: '100%', height: '260px', borderRadius: '4px' }} />
            </div>
          ) : timeseries.length === 0 ? (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--cds-text-helper)', fontSize: '13px' }}>
              No traffic recorded in the selected time window.
            </div>
          ) : trafficChartMode === 'volume' ? (
            <AreaChart data={areaData} options={areaOptions} />
          ) : (
            <StackedAreaChart data={stackedAreaData} options={stackedAreaOptions} />
          )}
        </div>
      </Tile>

      <section style={{ marginTop: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h3 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--cds-text-primary)', margin: 0 }}>Forensic Breakdowns</h3>
          </div>
        </div>

        <div className="security-events-stat-grid">
          {loading ? (
            [1, 2, 3, 4, 5, 6, 7, 8].map((i) => (
              <Tile key={i} className="cf-card">
                <div className="cf-card-head" style={{ paddingBottom: '8px' }}>
                  <SkeletonText width="50%" />
                </div>
                <div className="cf-card-rows" style={{ padding: '6px 0' }}>
                  {[1, 2, 3, 4, 5].map((s) => (
                    <div key={s} className="cf-card-row cf-card-row--skeleton">
                      <SkeletonText width="100%" />
                    </div>
                  ))}
                </div>
              </Tile>
            ))
          ) : (
            visibleCards.map((def) => {
              const rawItems = dashboard?.breakdowns?.[def.key] || [];
              const top5 = rawItems.slice(0, 5);
              const totalInCard = rawItems.reduce((acc, curr) => acc + (curr.count || 0), 0);
              const maxInTop5 = Math.max(...top5.map((it) => it.count || 0), 1);

              return (
                <Tile key={def.key} className="cf-card">
                  <div className="cf-card-head">
                    <div className="cf-card-title-group" title={`Top 5 ${def.title.toLowerCase()} occurring in requests`}>
                      <h4 className="cf-card-title" title={def.title}>
                        {def.title}
                      </h4>
                      <Information size={14} className="cf-card-info-icon" />
                    </div>
                    <Button
                      kind="ghost"
                      size="sm"
                      hasIconOnly
                      renderIcon={Maximize}
                      iconDescription={`Expand ${def.title}`}
                      onClick={() => setStatsModalData({ title: def.title, filterKey: def.filterKey, items: rawItems })}
                    />
                  </div>

                  <div className="cf-card-rows">
                    {top5.length > 0 ? (
                      top5.map((item, idx) => {
                        const filterVal = item.key || item.value || item.label || '-';
                const displayVal = item.value || item.label || '-';
                        const isFilterActive = activeFilters[def.filterKey] === displayVal;
                        const itemPct = totalInCard > 0 ? (item.count / totalInCard) * 100 : 0;
                        const barRatio = Math.min(100, Math.max(item.count > 0 ? 4 : 0, Math.round(((item.count || 0) / maxInTop5) * 100)));
                        const isMono = isMonoValue(def.filterKey, displayVal);
                        const displayLabel = renderTrafficItemLabelText(def.key, item);
                        const barColor = getTrafficBarColor(def.key, item);

                        return (
                          <div
                            key={idx}
                            className={`cf-card-row ${isFilterActive ? 'cf-card-row--active' : ''}`}
                            role="button"
                            tabIndex={0}
                            title={`${displayLabel}: ${formatNumber(item.count)} (${itemPct.toFixed(1)}%) - Click to filter`}
                            onClick={() => handleApplyFilter(def.filterKey, filterVal)}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter') handleApplyFilter(def.filterKey, filterVal);
                            }}
                          >
                            <div className="cf-card-row-label-group">
                              {renderTrafficItemPrefix(def.key, item)}
                              <span
                                className={`cf-card-row-label ${isMono ? 'cf-card-row-label--mono' : ''}`}
                                title={displayLabel}
                              >
                                {displayLabel}
                              </span>
                              {hasLaunchIcon(def.key) && (
                                <Launch size={12} className="cf-card-row-launch" />
                              )}
                            </div>

                            <div className="cf-card-mini-gauge-track">
                              <div
                                className="cf-card-mini-gauge-fill"
                                style={{
                                  width: `${barRatio}%`,
                                  backgroundColor: isFilterActive ? 'var(--cds-focus, var(--cds-interactive, #eb6200))' : barColor,
                                }}
                              />
                            </div>

                            <span className="cf-card-row-value">
                              {formatCompact(item.count)}
                            </span>
                          </div>
                        );
                      })
                    ) : (
                      <div className="cf-card-empty">
                        <Information size={18} />
                        <span>No data recorded</span>
                      </div>
                    )}
                  </div>
                </Tile>
              );
            })
          )}
        </div>

        {breakdownCardsDef.length > 8 && (
          <div style={{ width: '100%', marginTop: '16px' }}>
            <button
              type="button"
              className="security-statistics-show-more"
              aria-expanded={showAllBreakdowns}
              onClick={() => setShowAllBreakdowns((prev) => !prev)}
            >
              <span>
                {showAllBreakdowns
                  ? 'Collapse to top 8 breakdown cards'
                  : `View all ${breakdownCardsDef.length} breakdown cards (+${breakdownCardsDef.length - 8} more)`}
              </span>
              {showAllBreakdowns ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
            </button>
          </div>
        )}
      </section>

      <section style={{ marginTop: '24px' }}>
        <DataTable rows={tableRows} headers={tableHeaders}>
          {({ rows, headers, getHeaderProps, getRowProps, getTableProps }) => (
            <TableContainer title="Request events">
              <TableToolbar>
                <TableToolbarContent>
                  <TableToolbarSearch
                    persistent
                    placeholder="Filter events by IP, path, host, or rule..."
                    value={searchQuery}
                    onChange={(e: any) => setSearchQuery(e.target.value)}
                  />
                </TableToolbarContent>
              </TableToolbar>

              {loading ? (
                <DataTableSkeleton
                  headers={tableHeaders}
                  rowCount={6}
                  columnCount={tableHeaders.length}
                  showHeader={false}
                  showToolbar={false}
                />
              ) : (
                <Table {...getTableProps()} aria-label="Security Request Events">
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
                          <WarningAlt size={24} style={{ color: 'var(--cds-text-helper)', marginBottom: '8px' }} />
                          <div style={{ fontWeight: 600, marginBottom: '4px' }}>No traffic requests match criteria</div>
                          <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px' }}>
                            Adjust active filters or broaden your time window.
                          </div>
                        </TableCell>
                      </TableRow>
                    ) : (
                      rows.map((row) => {
                        const raw = eventsById.get(row.id) || paginatedEvents.find((e) => String(e.id) === row.id) || {
                          id: row.id,
                          timestamp: new Date().toISOString(),
                          method: 'GET',
                          path: '/',
                          host: '-',
                          status_code: 200,
                          client_ip: '-',
                          country: 'XX',
                        } as SecurityEventItem;
                                                const { key, ...rowProps } = getRowProps({ row });

                        return (
                          <TableRow key={key} {...rowProps}>
                            <TableCell>
                              <EventTimeCell timestamp={raw.timestamp} />
                            </TableCell>

                            <TableCell>
                              <EventMethodTag method={raw.method} />
                            </TableCell>

                            <TableCell>
                              <EventPathCell path={raw.path} />
                            </TableCell>

                            <TableCell style={{ fontFamily: 'var(--cds-font-mono)', fontSize: '12px', color: 'var(--cds-text-secondary)' }}>
                              {raw.host || '-'}
                            </TableCell>

                            <TableCell>
                              <EventStatusTag status={raw.status_code} />
                            </TableCell>

                            <TableCell>
                              <EventSourceCell ip={raw.client_ip} country={raw.country} />
                            </TableCell>

                            <TableCell style={{ textAlign: 'right' }}>
                              <EventInspectButton onClick={() => setSelectedEvent(raw)} />
                            </TableCell>
                          </TableRow>
                        );
                      })
                    )}
                  </TableBody>
                </Table>
              )}

                {loading ? (
                  <PaginationSkeleton />
                ) : (
                  <Pagination
                    totalItems={totalEvents}
                    pageSize={pageSize}
                    pageSizes={[20, 50, 100, 200]}
                    page={currentPage}
                    onChange={({ page, pageSize: newPageSize }) => {
                      setCurrentPage(page);
                      setPageSize(newPageSize);
                    }}
                  />
                )}
              </TableContainer>
            )}
          </DataTable>
      </section>

      <Modal
        open={filterModalOpen}
        modalHeading="Add Traffic Filter"
        primaryButtonText="Apply Filter"
        secondaryButtonText="Cancel"
        onRequestSubmit={handleAddFilterFromModal}
        onRequestClose={() => setFilterModalOpen(false)}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', padding: '16px 0' }}>
          <Select
            id="filter-field-select"
            labelText="Filter Dimension"
            value={newFilterField}
            onChange={(e) => setNewFilterField(e.target.value)}
          >
            <SelectItem value="path" text="Path (URI)" />
            <SelectItem value="host" text="Host" />
            <SelectItem value="route" text="Route" />
            <SelectItem value="upstream" text="Upstream" />
            <SelectItem value="ip" text="Client IP" />
            <SelectItem value="method" text="Method" />
            <SelectItem value="country" text="Country Code" />
            <SelectItem value="status" text="Status Code" />
            <SelectItem value="status_class" text="Status Class (2xx, 4xx, 5xx)" />
            <SelectItem value="user_agent" text="User Agent" />
            <SelectItem value="ja3" text="JA3 Fingerprint" />
            <SelectItem value="ja4" text="JA4 Fingerprint" />
            <SelectItem value="asn" text="ASN" />
            <SelectItem value="http_version" text="HTTP Version" />
            <SelectItem value="tls_version" text="TLS Version" />
          </Select>

          <Select
            id="filter-op-select"
            labelText="Operator"
            value={newFilterOp}
            onChange={(e) => setNewFilterOp(e.target.value)}
          >
            <SelectItem value="equals" text="equals" />
            <SelectItem value="contains" text="contains" />
            <SelectItem value="starts_with" text="starts with" />
            <SelectItem value="ends_with" text="ends with" />
          </Select>

          <TextInput
            id="filter-val-input"
            labelText="Value"
            placeholder="e.g. /api/v1/auth or 192.168.1.1"
            value={newFilterValue}
            onChange={(e) => setNewFilterValue(e.target.value)}
          />
        </div>
      </Modal>

      <Modal
        open={showTimeModal}
        modalHeading="Custom Telemetry Time Range"
        primaryButtonText="Apply Range"
        secondaryButtonText="Cancel"
        onRequestSubmit={() => {
          setTimeWindow('custom');
          setShowTimeModal(false);
          loadData();
        }}
        onRequestClose={() => setShowTimeModal(false)}
      >
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', padding: '16px 0' }}>
          <TextInput
            id="custom-since-input"
            labelText="Since (From)"
            type="datetime-local"
            value={customSince}
            onChange={(e) => setCustomSince(e.target.value)}
          />
          <TextInput
            id="custom-until-input"
            labelText="Until (To)"
            type="datetime-local"
            value={customUntil}
            onChange={(e) => setCustomUntil(e.target.value)}
          />
        </div>
      </Modal>

      <Modal
        open={!!statsModalData}
        modalHeading={`${statsModalData?.title || 'Dimension'} Breakdown`}
        passiveModal
        onRequestClose={() => setStatsModalData(null)}
        size="lg"
      >
        {statsModalData && (
          <div style={{ padding: '12px 0' }}>
            <p style={{ fontSize: '13px', color: 'var(--cds-text-secondary)', marginBottom: '16px' }}>
              Full distribution of requests across {statsModalData.title}. Click any row to filter telemetry.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '420px', overflowY: 'auto' }}>
              {statsModalData.items.map((item, idx) => {
                const isCountry = statsModalData.filterKey === 'country';
                const filterVal = item.key || item.value || item.label || '-';
                const displayVal = item.value || item.label || '-';
                const totalInModal = statsModalData.items.reduce((acc, curr) => acc + curr.count, 0) || 1;
                const pct = (item.count / totalInModal) * 100;
                const isMono = isMonoValue(statsModalData.filterKey, displayVal);
                const displayLabel = renderTrafficItemLabelText(statsModalData.filterKey, item);

                return (
                  <Layer key={idx}>
                    <Tile
                      style={{
                        display: 'grid',
                        gridTemplateColumns: '28px 1fr 140px 80px auto',
                        alignItems: 'center',
                        gap: '12px',
                        padding: '10px 14px',
                        borderRadius: '4px',
                        border: '1px solid var(--cds-border-subtle)',
                        background: 'var(--cds-layer-02)',
                      }}
                    >
                      <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--cds-text-helper)' }}>
                        #{idx + 1}
                      </span>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', minWidth: 0, overflow: 'hidden' }}>
                        {isCountry && displayVal !== 'XX' && (
                          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', marginRight: '6px' }}>
                            {countryCodeToFlag(displayVal) && (
                              <span className="country-flag" role="img" aria-label={displayVal} style={{ fontSize: '15px', lineHeight: 1 }}>
                                {countryCodeToFlag(displayVal)}
                              </span>
                            )}
                            <span
                              style={{
                                fontFamily: 'var(--cds-font-mono, monospace)',
                                fontSize: '11px',
                                fontWeight: 600,
                                color: 'var(--cds-text-secondary)',
                              }}
                            >
                              {displayVal}
                            </span>
                          </div>
                        )}
                        <span
                          style={{
                            fontFamily: isMono ? 'var(--cds-font-mono)' : 'inherit',
                            fontSize: '13px',
                            fontWeight: 600,
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          {displayLabel}
                        </span>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <ProgressBar
                          label=""
                          hideLabel
                          value={Math.min(100, pct)}
                          max={100}
                          size="small"
                        />
                        <span style={{ fontSize: '11px', color: 'var(--cds-text-secondary)', width: '36px', textAlign: 'right' }}>
                          {pct.toFixed(1)}%
                        </span>
                      </div>

                      <strong style={{ fontSize: '13px', textAlign: 'right', fontFamily: 'var(--cds-font-mono)' }}>{formatCompact(item.count)}</strong>

                      <Button
                        kind="ghost"
                        size="sm"
                        
                        onClick={() => {
                          handleApplyFilter(statsModalData.filterKey, filterVal);
                          setStatsModalData(null);
                        }}
                      >
                        Filter
                      </Button>
                    </Tile>
                  </Layer>
                );
              })}
            </div>
          </div>
        )}
      </Modal>

      <EventInspectorModal
        open={!!selectedEvent}
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
        sectionLabel="Traffic Telemetry"
        onNavigate={onNavigate}
        onApplyFilter={handleApplyFilter}
      />
    </div>
  );
};
