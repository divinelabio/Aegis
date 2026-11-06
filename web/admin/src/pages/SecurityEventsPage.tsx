import {
  EventTimeCell,
  EventRequestCell,
  EventRuleCell,
  EventActionBadge,
  EventSourceCell,
  EventInspectButton,
  EventInspectorModal,
} from '../components/events';
import React, { useEffect, useState, useMemo, useCallback } from 'react';
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
  Tag,
  Select,
  SelectItem,
  Modal,
  InlineNotification,
  DataTableSkeleton,
  SkeletonText,
  SkeletonPlaceholder,
  PaginationSkeleton,
  TabsSkeleton,
  Pagination,
  ProgressBar,
  TextInput,
ContentSwitcher,
  Switch,
  Tabs,
  TabList,
  Tab,
  useTheme,
} from '@carbon/react';
import {
  Renew,
Filter,
Security,
  Maximize,
  WarningAlt,
  ChevronDown,
  ChevronUp,
  Information,
  Launch,
} from '@carbon/icons-react';
import { AreaChart, StackedAreaChart } from '@carbon/charts-react';
import { ScaleTypes, ChartTheme } from '@carbon/charts';
import type {
  AreaChartOptions,
  StackedAreaChartOptions,
  ChartTabularData,
} from '@carbon/charts';
import type {
  SecurityEventItem,
  SecurityDashboardData,
  SecurityDashboardSummary,
  SecuritySectionAnalytics,
  SecuritySectionBreakdownItem,
  SecurityProtectionSummary,
  NavItemKey,
} from '../types';
import { apiService } from '../services/api';
import { PageHeader, MetricStrip, KpiCard } from '../components/common';
import { COUNTRIES_MAP, normalizeToCountryCode } from '../data/geoData';
import { countryCodeToFlag } from '../components/common/CountryBadge';

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

function formatNumber(value: number | undefined): string {
  return new Intl.NumberFormat('en-US').format(Math.max(0, Number(value) || 0));
}

function formatCompact(value: number | undefined): string {
  if (value === undefined || value === null) return '0';
  if (value < 1000) return String(value);
  const formatted = new Intl.NumberFormat('en-US', {
    notation: 'compact',
    maximumFractionDigits: 2,
  }).format(value);
  return formatted.replace(/K$/, 'k');
}

function formatPercent(value: number | undefined): string {
  return `${Math.max(0, Number(value) || 0).toFixed(1)}%`;
}

function timeRangeLabel(window = '24h'): string {
  const labels: Record<string, string> = {
    '15m': 'Last 15 minutes',
    '1h': 'Last hour',
    '24h': 'Last 24 hours',
    '7d': 'Last 7 days',
    '30d': 'Last 30 days',
  };
  if (labels[window]) return labels[window];
  const match = window.match(/^(\d+)(m|h)$/);
  if (!match) return 'Last 24 hours';
  const amount = Number(match[1]);
  if (match[2] === 'm') return `Last ${amount} minute${amount === 1 ? '' : 's'}`;
  if (amount % 168 === 0) return `Last ${amount / 168} week${amount === 168 ? '' : 's'}`;
  if (amount % 24 === 0) return `Last ${amount / 24} day${amount === 24 ? '' : 's'}`;
  return `Last ${amount} hour${amount === 1 ? '' : 's'}`;
}

const sectionLabels: Record<string, string> = {
  waf_core: 'Application Firewall',
  bot_protection: 'Bot Defense',
  traffic_control: 'Traffic Control',
  api_security: 'API Shield',
  http_security: 'App Security',
  access_control: 'Edge Access',
  security_rules: 'Security Rules',
};

const PROTECTION_SECTIONS = [
  { key: 'waf_core', label: 'WAF Core' },
  { key: 'bot_protection', label: 'Bot Defense' },
  { key: 'traffic_control', label: 'Traffic Control' },
  { key: 'api_security', label: 'API Shield' },
  { key: 'http_security', label: 'App Security' },
  { key: 'access_control', label: 'Edge Access' },
] as const;

function getSectionName(sec?: string): string {
  if (!sec) return 'Application Firewall';
  return sectionLabels[sec] || sec.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

function isMonoValue(filterKey: string, val: string): boolean {
  if (['path', 'ip', 'ja3', 'ja4', 'asn', 'rule_id', 'matched_field', 'status', 'method', 'methods'].includes(filterKey)) return true;
  if (typeof val === 'string' && (val.startsWith('/') || /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(val))) return true;
  return false;
}

function getBarColor(dimensionKey: string, item: SecuritySectionBreakdownItem): string {
  const val = (item.key || item.label || '').toLowerCase();

  if (dimensionKey === 'actions' || dimensionKey === 'decision_states' || dimensionKey === 'mitigations') {
    if (val.includes('block') || val.includes('drop') || val.includes('deny')) return 'var(--cds-support-error, #da1e28)';
    if (val.includes('detect') || val.includes('log')) return 'var(--cds-support-warning, #ff832b)';
    if (val.includes('challenge')) return 'var(--cds-support-info, #1192e8)';
    if (val.includes('allow') || val.includes('pass')) return 'var(--cds-support-success, #24a148)';
  }

  if (dimensionKey === 'severities') {
    if (val.includes('critical')) return 'var(--cds-support-error, #da1e28)';
    if (val.includes('high')) return '#fa4d56';
    if (val.includes('medium')) return 'var(--cds-support-caution-major, #08bdba)';
    if (val.includes('low')) return 'var(--cds-text-helper, #8d8d8d)';
  }

  if (dimensionKey === 'status' || dimensionKey === 'status_codes') {
    if (val.startsWith('2')) return 'var(--cds-support-success, #24a148)';
    if (val.startsWith('3')) return 'var(--cds-text-secondary, #8d8d8d)';
    if (val.startsWith('4')) return 'var(--cds-support-warning, #ff832b)';
    if (val.startsWith('5')) return 'var(--cds-support-error, #da1e28)';
  }

  return 'var(--cds-interactive, #eb6200)';
}

export function hasLaunchIcon(dimensionKey: string): boolean {
  const k = dimensionKey.toLowerCase();
  return (
    k.includes('ip') ||
    k.includes('host') ||
    k.includes('domain') ||
    k.includes('url') ||
    k.includes('uri')
  );
}

function renderItemPrefix(dimensionKey: string, item: SecuritySectionBreakdownItem) {
  const val = (item.key || item.label || '').toLowerCase();

  if (dimensionKey === 'actions' || dimensionKey === 'decision_states' || dimensionKey === 'mitigations') {
    let color = 'var(--cds-interactive, #eb6200)';
    if (val.includes('block') || val.includes('drop') || val.includes('deny')) color = 'var(--cds-support-error, #da1e28)';
    else if (val.includes('detect') || val.includes('log')) color = 'var(--cds-support-warning, #ff832b)';
    else if (val.includes('challenge')) color = 'var(--cds-support-info, #1192e8)';
    else if (val.includes('allow') || val.includes('pass')) color = 'var(--cds-support-success, #24a148)';
    return <span className="cf-card-dot" style={{ backgroundColor: color }} />;
  }

  if (dimensionKey === 'countries') {
    const code = String(item.key || item.label || '').trim().toUpperCase();
    if (code.length === 2 && /^[A-Z]{2}$/.test(code) && code !== 'XX') {
      return (
        <span
          style={{
            fontFamily: 'var(--cds-font-mono, monospace)',
            fontSize: '10px',
            fontWeight: 600,
            color: 'var(--cds-text-secondary)',
            marginRight: '4px',
            letterSpacing: '0.3px',
          }}
        >
          {code}
        </span>
      );
    }
  }

  return null;
}

export function renderItemLabelText(dimensionKey: string, item: SecuritySectionBreakdownItem): string {
  if (dimensionKey === 'countries') {
    const code = String(item.key || item.label || '').trim().toUpperCase();
    if (countryNames[code]) {
      return countryNames[code];
    }
  }
  if (dimensionKey === 'methods') {
    return String(item.label || item.key || '—').toUpperCase();
  }
  return item.label || item.key || '—';
}

interface SecurityEventsPageProps {
  onNavigate?: (key: NavItemKey) => void;
}

export const SecurityEventsPage: React.FC<SecurityEventsPageProps> = ({ onNavigate }) => {
  const { theme } = useTheme();
  const isDark = theme === 'g90' || theme === 'g100';
  const chartThemeName = isDark ? ChartTheme.G100 : ChartTheme.WHITE;

  const [dashboard, setDashboard] = useState<SecurityDashboardData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [timeWindow, setTimeWindow] = useState<string>('24h');
  const [activeFilters, setActiveFilters] = useState<Record<string, string>>({});
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedSection, setSelectedSection] = useState<string>('waf_core');
  const [expandedBreakdowns, setExpandedBreakdowns] = useState<boolean>(false);
  const [chartMode, setChartMode] = useState<'stacked' | 'volume'>('stacked');

  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(20);

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

  const [selectedEvent, setSelectedEvent] = useState<SecurityEventItem | null>(null);
  const [eventDrawerOpen, setEventDrawerOpen] = useState<boolean>(false);
  
  const [statsModalOpen, setStatsModalOpen] = useState<boolean>(false);
  const [statsModalTitle, setStatsModalTitle] = useState<string>('');
  const [statsModalFilterKey, setStatsModalFilterKey] = useState<string>('');
  const [statsModalItems, setStatsModalItems] = useState<SecuritySectionBreakdownItem[]>([]);

  const [filterModalOpen, setFilterModalOpen] = useState<boolean>(false);
  const [filterField, setFilterField] = useState<string>('section');
  const [filterOperator, setFilterOperator] = useState<string>('equals');
  const [filterValue, setFilterValue] = useState<string>('waf_core');
  const [storageWarningDismissed, setStorageWarningDismissed] = useState<boolean>(false);

  
  const loadData = useCallback(async (win = timeWindow, filters = activeFilters, silent = false) => {
    if (!silent) setLoading(true);
    else setRefreshing(true);

    try {
      const data = await apiService.getSecurityDashboard({ window: win, ...filters });
      setDashboard(data);
    } catch (err) {
      console.error('[SecurityEventsPage] Failed to load telemetry:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [timeWindow, activeFilters]);

  useEffect(() => {
    void loadData(timeWindow, activeFilters, false);
  }, [loadData, timeWindow, activeFilters]);

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

  const handleApplyFilterFromModal = () => {
    if (!filterValue.trim()) return;
    handleApplyFilter(filterField, filterValue.trim());
    setFilterModalOpen(false);
    setFilterValue('');
  };

  
  const handleOpenStatisticsModal = (title: string, filterKey: string, items?: SecuritySectionBreakdownItem[]) => {
    setStatsModalTitle(title);
    setStatsModalFilterKey(filterKey);
    setStatsModalItems(items || []);
    setStatsModalOpen(true);
  };

  const summary: SecurityDashboardSummary = dashboard?.summary || {
    total_requests: 0,
    blocked_requests: 0,
    detected_requests: 0,
    allowed_requests: 0,
    error_requests: 0,
    block_rate: 0,
    detection_rate: 0,
    avg_latency_ms: 0,
    p95_latency_ms: 0,
    avg_anomaly_score: 0,
    max_anomaly_score: 0,
    unique_source_ips: 0,
    unique_countries: 0,
    top_attack_category: 'None',
  };

  const protection: SecurityProtectionSummary = dashboard?.protection_summary || {
    blocked_attacks: summary.blocked_requests,
    detected_only: summary.detected_requests,
    rule_matches: 0,
    critical_high: 0,
    avg_anomaly_score: summary.avg_anomaly_score,
    max_anomaly_score: summary.max_anomaly_score,
  };

  const totalReq = summary.total_requests || 0;
  const blockedReq = summary.blocked_requests || 0;
  const detectedReq = summary.detected_requests || 0;
  const blockRate = summary.block_rate !== undefined ? summary.block_rate : (totalReq > 0 ? (blockedReq / totalReq) * 100 : 0);
  const criticalHigh = protection.critical_high || 0;

  const rawEvents = dashboard?.events?.events || [];
  const filteredEvents = useMemo(() => {
    let result = rawEvents;

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      result = result.filter((e) =>
        (e.client_ip || '').toLowerCase().includes(q) ||
        (e.path || '').toLowerCase().includes(q) ||
        (e.host || '').toLowerCase().includes(q) ||
        (e.rule_name || '').toLowerCase().includes(q) ||
        (e.rule_id || '').toLowerCase().includes(q) ||
        (e.method || '').toLowerCase().includes(q) ||
        (e.category || (e as any).categories?.[0] || e.section || '').toLowerCase().includes(q)
      );
    }

    return result;
  }, [rawEvents, searchQuery]);

  const totalEventsCount = filteredEvents.length;
  const paginatedEvents = filteredEvents.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const eventsById = useMemo(() => {
    const map = new Map<string, SecurityEventItem>();
    rawEvents.forEach((evt, idx) => {
      const key = String(evt.id || `sec-evt-${idx}`);
      map.set(key, evt);
    });
    return map;
  }, [rawEvents]);

  const timeseries = dashboard?.timeseries || [];

  const stackedTimeseriesData = useMemo<ChartTabularData>(() => {
    return timeseries.flatMap((pt) => {
      const rawTs = Number(pt.timestamp);
      const tsMs = !Number.isNaN(rawTs) && rawTs > 0 ? (rawTs < 1e12 ? rawTs * 1000 : rawTs) : Date.now();
      const dateObj = new Date(tsMs);
      const isoDate = !Number.isNaN(dateObj.getTime()) ? dateObj.toISOString() : new Date().toISOString();
      const counts = pt.counts || {};
      const total = Number(counts.total || counts.requests || 0);
      const blocked = Math.min(total, Math.max(0, Number(counts.block || counts.blocked || 0)));
      const detected = Math.min(total - blocked, Math.max(0, Number(counts.detect || counts.detected || 0)));

      return [
        { group: 'Blocked Threats', date: isoDate, value: blocked },
        { group: 'Detected Signals', date: isoDate, value: detected },
      ];
    });
  }, [timeseries]);

  const volumeTimeseriesData = useMemo<ChartTabularData>(() => {
    return timeseries.flatMap((pt) => {
      const rawTs = Number(pt.timestamp);
      const tsMs = !Number.isNaN(rawTs) && rawTs > 0 ? (rawTs < 1e12 ? rawTs * 1000 : rawTs) : Date.now();
      const dateObj = new Date(tsMs);
      const isoDate = !Number.isNaN(dateObj.getTime()) ? dateObj.toISOString() : new Date().toISOString();
      const counts = pt.counts || {};
      const total = Number(counts.total || counts.requests || 0);
      const blocked = Math.min(total, Math.max(0, Number(counts.block || counts.blocked || 0)));
      return [
        { group: 'Evaluated Requests', date: isoDate, value: total },
        { group: 'Mitigated Threats', date: isoDate, value: blocked },
      ];
    });
  }, [timeseries]);

  const tableRows = useMemo(() => {
    return paginatedEvents.map((e, idx) => {
      const countryCode = getValidCountryCode(e.country, e.client_ip);
      const flag = countryCode ? countryCodeToFlag(countryCode) : '';
      const countryName = countryCode ? (COUNTRIES_MAP[countryCode] || countryCode) : '';
      const sourceStr = countryCode
        ? `${flag ? `${flag} ` : ''}${countryCode} ${countryName} · ${e.client_ip || '—'}`
        : (e.client_ip || '—');
      return {
        id: String(e.id || `sec-evt-${idx}`),
        timestamp: String(e.timestamp || ''),
        method: e.method || 'GET',
        path: e.path || '/',
        rule: e.rule_name || e.rule_id || 'Detection',
        action: e.action || 'BLOCK',
        source: sourceStr,
        score: e.score ?? (e as any).anomaly_score ?? 0,
        severity: e.severity || (e as any).severities?.[0],
      };
    });
  }, [paginatedEvents]);

  const renderChartTooltip = useCallback((data: any) => {
    const items: any[] = Array.isArray(data) ? data : data ? [data] : [];
    if (!items.length) return '';

    const first = items[0] || {};
    const rawDate = first.date || first.timestamp;
    const dateObj = rawDate ? new Date(rawDate) : new Date();
    const formattedDate = !Number.isNaN(dateObj.getTime())
      ? dateObj.toLocaleString('en-US', {
          month: 'short',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit',
          hour12: true,
        })
      : String(rawDate || '');

    const rows = items.map((d: any) => {
      const isBlocked = d.group === 'Blocked Threats' || d.group === 'Mitigated Threats';
      const isDetected = d.group === 'Detected Signals';
      const bulletColor = isBlocked ? '#da1e28' : isDetected ? '#f1c21b' : '#eb6200';
      const val = Number(d.value) || 0;
      return `
        <div style="display: flex; align-items: center; justify-content: space-between; gap: 20px; padding: 4px 0; font-size: 12px;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="width: 8px; height: 8px; border-radius: 1px; background: ${bulletColor}; display: inline-block; flex-shrink: 0;"></span>
            <span style="color: var(--cds-text-secondary, #c6c6c6); font-weight: 500;">${d.group}</span>
          </div>
          <strong style="color: var(--cds-text-primary, #ffffff); font-family: monospace; font-size: 13px;">${formatNumber(val)}</strong>
        </div>
      `;
    }).join('');

    const sum = items.reduce((acc: number, curr: any) => acc + (Number(curr.value) || 0), 0);
    const totalRow = items.length > 1 ? `
      <div style="margin-top: 6px; padding-top: 6px; border-top: 1px solid var(--cds-border-subtle, #393939); display: flex; align-items: center; justify-content: space-between; font-size: 12px;">
        <span style="color: var(--cds-text-secondary, #c6c6c6); font-weight: 500;">Total Evaluated</span>
        <strong style="color: var(--cds-text-primary, #ffffff); font-family: monospace; font-size: 13px;">${formatNumber(sum)}</strong>
      </div>
    ` : '';

    return `
      <div style="padding: 10px 14px; background: var(--cds-layer-02, #262626); border: 1px solid var(--cds-border-subtle, #393939); border-radius: 4px; box-shadow: 0 4px 16px rgba(0,0,0,0.45); min-width: 200px;">
        <div style="font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: var(--cds-text-helper, #8d8d8d); margin-bottom: 6px;">
          ${formattedDate}
        </div>
        ${rows}
        ${totalRow}
      </div>
    `;
  }, []);

  const stackedAreaOptions: StackedAreaChartOptions = useMemo(() => ({
    axes: {
      bottom: {
        title: 'Timeline',
        mapsTo: 'date',
        scaleType: ScaleTypes.TIME,
      },
      left: {
        title: 'Decisions',
        mapsTo: 'value',
        scaleType: ScaleTypes.LINEAR,
        stacked: true,
        ticks: {
          number: 5,
          formatter: (val: number | Date) => formatCompact(Number(val)),
        },
      },
    },
    curve: 'curveMonotoneX',
    height: '340px',
    resizable: true,
    theme: chartThemeName,
    color: {
      scale: {
        'Blocked Threats': '#da1e28',
        'Detected Signals': '#ff832b',
      },
    },
    grid: {
      x: { enabled: false },
      y: { enabled: true },
    },
    tooltip: {
      enabled: true,
      customHTML: renderChartTooltip,
      valueFormatter: (val: any) => formatNumber(Number(val) || 0),
    },
    toolbar: { enabled: false },
    legend: { enabled: false },
    timeScale: { addSpaceOnEdges: 0 },
  }), [chartThemeName, renderChartTooltip]);

  const volumeAreaOptions: AreaChartOptions = useMemo(() => ({
    axes: {
      bottom: {
        title: 'Timeline',
        mapsTo: 'date',
        scaleType: ScaleTypes.TIME,
      },
      left: {
        title: 'Requests',
        mapsTo: 'value',
        scaleType: ScaleTypes.LINEAR,
        ticks: {
          number: 5,
          formatter: (val: number | Date) => formatCompact(Number(val)),
        },
      },
    },
    curve: 'curveMonotoneX',
    height: '340px',
    resizable: true,
    theme: chartThemeName,
    color: {
      scale: {
        'Evaluated Requests': '#eb6200',
        'Mitigated Threats': '#da1e28',
      },
    },
    grid: {
      x: { enabled: false },
      y: { enabled: true },
    },
    tooltip: {
      enabled: true,
      customHTML: renderChartTooltip,
      valueFormatter: (val: any) => formatNumber(Number(val) || 0),
    },
    toolbar: { enabled: false },
    legend: { enabled: false },
    timeScale: { addSpaceOnEdges: 0 },
  }), [chartThemeName, renderChartTooltip]);

  const sectionAnalyticsList: SecuritySectionAnalytics[] = dashboard?.section_analytics || [];
  const activeSectionKey = activeFilters.section || selectedSection;
  const currentSectionData =
    sectionAnalyticsList.find((s) => s.section === activeSectionKey) || {
      section: activeSectionKey,
      label: getSectionName(activeSectionKey),
      breakdowns: [],
    };

  const currentBreakdowns = currentSectionData.breakdowns || [];
  const visibleBreakdowns = expandedBreakdowns ? currentBreakdowns : currentBreakdowns.slice(0, 8);

  const selectedSectionIndex = Math.max(
    0,
    PROTECTION_SECTIONS.findIndex((s) => s.key === activeSectionKey)
  );

  const handleSectionTabChange = (state: any) => {
    const idx = typeof state === 'number' ? state : state?.selectedIndex;
    if (typeof idx === 'number' && idx >= 0 && idx < PROTECTION_SECTIONS.length) {
      const target = PROTECTION_SECTIONS[idx];
      if (target) {
        setSelectedSection(target.key);
        handleApplyFilter('section', target.key);
      }
    }
  };

  useEffect(() => {
    if (activeFilters.section && activeFilters.section !== selectedSection) {
      setSelectedSection(activeFilters.section);
    }
  }, [activeFilters.section, selectedSection]);

  const getBreakdownFilterKey = (breakdownKey: string): string => {
    const map: Record<string, string> = {
      attack_types: 'category',
      attack_categories: 'category',
      categories: 'category',
      reasons: 'category',
      severities: 'severity',
      reputation_bands: 'severity',
      rules: 'rule_id',
      matched_rules: 'rule_id',
      signals: 'matched_field',
      paths: 'path',
      hosts: 'host',
      ips: 'ip',
      countries: 'country',
      actions: 'action',
      mitigations: 'action',
      methods: 'method',
      status: 'status',
      user_agents: 'user_agent',
      score_bands: 'score_band',
      attack_payload_locations: 'matched_field',
      attack_layers: 'matched_field',
      ja3: 'ja3',
      ja4: 'ja4',
      asn: 'asn',
    };
    return map[breakdownKey] || 'category';
  };

  
  
  const filterKeyOptions = [
    { label: 'Protection Section', value: 'section' },
    { label: 'Decision / Action', value: 'action' },
    { label: 'Severity Level', value: 'severity' },
    { label: 'Attack Category', value: 'category' },
    { label: 'Rule ID', value: 'rule_id' },
    { label: 'Path / URI', value: 'path' },
    { label: 'Host / Domain', value: 'host' },
    { label: 'Source IP', value: 'ip' },
    { label: 'Country Code', value: 'country' },
    { label: 'HTTP Method', value: 'method' },
    { label: 'Matched Field', value: 'matched_field' },
    { label: 'User Agent', value: 'user_agent' },
    { label: 'JA3 Fingerprint', value: 'ja3' },
    { label: 'JA4 Fingerprint', value: 'ja4' },
    { label: 'ASN Number', value: 'asn' },
  ];

  return (
    <div className="security-events-shell">
      <PageHeader
        kicker="Threat operations"
        title="Security events"
        icon={Security}
        badge={
          Object.keys(activeFilters).length > 0 ? (
            <Tag type="high-contrast" size="sm">
              {Object.keys(activeFilters).length} Filter{Object.keys(activeFilters).length > 1 ? 's' : ''} Active
            </Tag>
          ) : undefined
        }
        action={
          <div className="security-events-command-bar">
            <Select
              id="waf-time-select"
              size="sm"
              labelText="Time window filter"
              hideLabel
              inline
              value={['15m', '1h', '24h', '7d', '30d'].includes(timeWindow) ? timeWindow : 'custom'}
              onChange={(e) => {
                const val = e.target.value;
                if (val !== 'custom') {
                  setTimeWindow(val);
                  setCurrentPage(1);
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
                <SelectItem value="custom" text={`Custom (${timeWindow})`} />
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
              hasIconOnly
              renderIcon={Renew}
              iconDescription="Refresh"
              disabled={loading || refreshing}
              onClick={() => void loadData(timeWindow, activeFilters, true)}
            />
          </div>
        }
      />

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
          <Button kind="ghost" size="sm" onClick={handleClearFilters}>
            Clear all
          </Button>
        </div>
      )}

      {dashboard?.health?.db_available === false && !storageWarningDismissed && (
        <InlineNotification
          kind="warning"
          title="Analytics storage offline"
          subtitle={dashboard.health.message || 'Analytics storage is not connected. Historical data is unavailable.'}
          onCloseButtonClick={() => setStorageWarningDismissed(true)}
        />
      )}

      <MetricStrip>
        <KpiCard
          label="Security events"
          value={formatNumber(totalReq)}
          subtext={timeRangeLabel(timeWindow)}
          status="default"
          onClick={handleClearFilters}
          loading={loading}
        />
        <KpiCard
          label="Blocked"
          value={formatNumber(blockedReq)}
          subtext={`${formatPercent(blockRate)} block rate`}
          status="default"
          onClick={() => handleApplyFilter('action', 'block')}
          loading={loading}
        />
        <KpiCard
          label="Detected"
          value={formatNumber(detectedReq)}
          subtext="Detect only"
          status="default"
          onClick={() => handleApplyFilter('action', 'detect')}
          loading={loading}
        />
        <KpiCard
          label="Block rate"
          value={formatPercent(blockRate)}
          subtext="Of total events"
          status="default"
          onClick={() => handleApplyFilter('action', 'block')}
          loading={loading}
        />
        <KpiCard
          label="Critical / high"
          value={formatNumber(criticalHigh)}
          subtext="Severity"
          status="default"
          onClick={() => handleApplyFilter('severity', 'high')}
          loading={loading}
        />
      </MetricStrip>

      <Tile className="security-events-chart-card">
        <div className="security-events-chart-header">
          <div>
            <h4 className="security-events-chart-title">Threat activity</h4>
          </div>
          <ContentSwitcher
            size="sm"
            className="security-events-switcher"
            selectedIndex={chartMode === 'stacked' ? 0 : 1}
            onChange={(data: any) => setChartMode((data?.name as 'stacked' | 'volume') || 'stacked')}
          >
            <Switch name="stacked" text="Decisions" />
            <Switch name="volume" text="Volume" />
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
          ) : chartMode === 'stacked' ? (
            <>
              <span className="security-events-legend-item">
                <span className="security-events-legend-square" style={{ background: '#da1e28' }} />
                Blocked events ({formatNumber(blockedReq)})
              </span>
              <span className="security-events-legend-item">
                <span className="security-events-legend-square" style={{ background: '#ff832b' }} />
                Detected events ({formatNumber(detectedReq)})
              </span>
              <span className="security-events-legend-item" style={{ marginLeft: 'auto', color: 'var(--cds-text-secondary)' }}>
                Block Rate: <strong style={{ color: '#da1e28' }}>{formatPercent(blockRate)}</strong>
              </span>
            </>
          ) : (
            <>
              <span className="security-events-legend-item">
                <span className="security-events-legend-square" style={{ background: '#eb6200' }} />
                Evaluated requests ({formatNumber(totalReq)})
              </span>
              <span className="security-events-legend-item">
                <span className="security-events-legend-square" style={{ background: '#da1e28' }} />
                Blocked events ({formatNumber(blockedReq)})
              </span>
              <span className="security-events-legend-item" style={{ marginLeft: 'auto', color: 'var(--cds-text-secondary)' }}>
                Allowed traffic: <strong style={{ color: 'var(--cds-text-primary)' }}>{formatNumber(Math.max(0, totalReq - blockedReq))}</strong>
              </span>
            </>
          )}
        </div>

        <div style={{ width: '100%', height: '340px', marginTop: '10px' }}>
          {loading || (!chartsReady && timeseries.length > 0) ? (
            <div style={{ width: '100%', height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
              <SkeletonPlaceholder style={{ width: '100%', height: '300px', borderRadius: '4px' }} />
            </div>
          ) : timeseries.length === 0 ? (
            <div className="security-events-chart-empty">No security events recorded in the selected time window.</div>
          ) : chartMode === 'stacked' ? (
            <StackedAreaChart data={stackedTimeseriesData} options={stackedAreaOptions} />
          ) : (
            <AreaChart data={volumeTimeseriesData} options={volumeAreaOptions} />
          )}
        </div>
      </Tile>
      <section style={{ marginTop: '24px' }}>
        <div style={{ marginBottom: '16px' }}>
          <div style={{ marginBottom: '12px' }}>
            <h3 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--cds-text-primary)', margin: 0 }}>
              Protection analytics
            </h3>
          </div>

          {loading ? (
            <TabsSkeleton />
          ) : (
            <Tabs selectedIndex={selectedSectionIndex} onChange={handleSectionTabChange}>
              <TabList aria-label="Protection analytics sections">
                {PROTECTION_SECTIONS.map((sec) => (
                  <Tab key={sec.key}>{sec.label}</Tab>
                ))}
              </TabList>
            </Tabs>
          )}
        </div>

        <div className="security-events-stat-grid">
          {loading ? (
            [1, 2, 3, 4, 5, 6, 7, 8].map((i) => (
              <Tile key={i} className="cf-card">
                <div className="cf-card-head">
                  <SkeletonText width="55%" />
                  <SkeletonText width="24px" />
                </div>
                <div className="cf-card-rows">
                  {[1, 2, 3, 4, 5].map((rowIdx) => (
                    <div key={rowIdx} className="cf-card-row cf-card-row--skeleton">
                      <div className="cf-card-row-label-group">
                        <SkeletonText width="65%" />
                      </div>
                      <div className="cf-card-mini-gauge-track">
                        <div className="cf-card-mini-gauge-fill" style={{ width: '45%' }} />
                      </div>
                      <SkeletonText width="28px" />
                    </div>
                  ))}
                </div>
              </Tile>
            ))
          ) : visibleBreakdowns.length > 0 ? (
            visibleBreakdowns.map((b) => {
              const filterKey = getBreakdownFilterKey(b.key);
              const items = b.items || [];
              const top5 = items.slice(0, 5);
              const totalInCard = items.reduce((acc, curr) => acc + (curr.count || 0), 0);
              const maxInTop5 = Math.max(...top5.map((it) => it.count || 0), 1);

              return (
                <Tile key={b.key} className="cf-card">
                  <div className="cf-card-head">
                    <div className="cf-card-title-group" title={`Top 5 ${b.label.toLowerCase()} occurring in requests`}>
                      <h4 className="cf-card-title" title={b.label}>
                        {b.label}
                      </h4>
                      <Information size={14} className="cf-card-info-icon" />
                    </div>
                    <Button
                      kind="ghost"
                      size="sm"
                      hasIconOnly
                      renderIcon={Maximize}
                      iconDescription={`Expand ${b.label}`}
                      onClick={() => handleOpenStatisticsModal(b.label, filterKey, items)}
                    />
                  </div>

                  <div className="cf-card-rows">
                    {top5.length > 0 ? (
                      top5.map((item, idx) => {
                        const itemVal = item.value || item.key || item.label;
                        const isFilterActive = activeFilters[filterKey] === itemVal;
                        const itemPct = totalInCard > 0 ? (item.count / totalInCard) * 100 : 0;
                        const barRatio = Math.min(100, Math.max(item.count > 0 ? 4 : 0, Math.round(((item.count || 0) / maxInTop5) * 100)));
                        const isMono = isMonoValue(filterKey, item.label || item.key || '');
                        const displayLabel = renderItemLabelText(b.key, item);
                        const barColor = getBarColor(b.key, item);

                        return (
                          <div
                            key={item.key || idx}
                            className={`cf-card-row ${isFilterActive ? 'cf-card-row--active' : ''}`}
                            role="button"
                            tabIndex={0}
                            title={`${displayLabel}: ${formatNumber(item.count)} (${itemPct.toFixed(1)}%) - Click to filter`}
                            onClick={() => handleApplyFilter(filterKey, itemVal)}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter') handleApplyFilter(filterKey, itemVal);
                            }}
                          >
                            <div className="cf-card-row-label-group">
                              {renderItemPrefix(b.key, item)}
                              <span
                                className={`cf-card-row-label ${isMono ? 'cf-card-row-label--mono' : ''}`}
                                title={displayLabel}
                              >
                                {displayLabel}
                              </span>
    
                              {hasLaunchIcon(b.key) && (
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
                        <span>No {b.label.toLowerCase()} recorded</span>
                      </div>
                    )}
                  </div>
                </Tile>
              );
            })
          ) : (
            <div className="security-events-stat-empty-section">
              <Information size={24} />
              <h4>No events recorded for {getSectionName(activeSectionKey)}</h4>
              <p>No telemetry recorded within the selected time window.</p>
            </div>
          )}
        </div>

        {currentBreakdowns.length > 8 && (
          <div style={{ width: '100%', marginTop: '16px' }}>
            <button
              type="button"
              className="security-statistics-show-more"
              aria-expanded={expandedBreakdowns}
              onClick={() => setExpandedBreakdowns(!expandedBreakdowns)}
            >
              <span>
                {expandedBreakdowns
                  ? 'Collapse to top 8 breakdown cards'
                  : `View all ${currentBreakdowns.length} breakdown cards (+${currentBreakdowns.length - 8} more)`}
              </span>
              {expandedBreakdowns ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
            </button>
          </div>
        )}
      </section>

      <section style={{ marginTop: '24px' }}>
        <DataTable
          rows={tableRows}
          headers={[
            { key: 'timestamp', header: 'Time' },
            { key: 'request', header: 'Request' },
            { key: 'rule', header: 'Rule / Reason' },
            { key: 'action', header: 'Decision' },
            { key: 'source', header: 'Source' },
            { key: 'actions', header: '' },
          ]}
        >
          {({ rows, headers, getTableProps, getHeaderProps, getRowProps }) => (
            <TableContainer
              title={
                Object.keys(activeFilters).length > 0
                  ? 'Recent matching security events'
                  : `Recent ${getSectionName(activeSectionKey)} events`
              }
            >
              <TableToolbar>
                <TableToolbarContent>
                  <TableToolbarSearch
                    placeholder="Search by IP, Path, Rule ID, Method..."
                    value={searchQuery}
                    onChange={(e: any, val?: string) => setSearchQuery(val ?? e?.target?.value ?? '')}
                  />
                  <Button
                    kind="secondary"
                    size="sm"
                    renderIcon={Filter}
                    onClick={() => setFilterModalOpen(true)}
                  >
                    Filter
                  </Button>
                  <Button
                    kind="ghost"
                    size="sm"
                    hasIconOnly
                    renderIcon={Renew}
                    iconDescription="Refresh"
                    onClick={() => void loadData(timeWindow, activeFilters, true)}
                  />
                </TableToolbarContent>
              </TableToolbar>

              {loading ? (
                <DataTableSkeleton
                  headers={headers}
                  rowCount={8}
                  columnCount={headers.length}
                  showHeader={false}
                  showToolbar={false}
                />
              ) : (
                <Table {...getTableProps()} size="sm">
                  <TableHead>
                    <TableRow>
                      {headers.map((h) => {
                        const { key, ...hProps } = getHeaderProps({ header: h });
                        return (
                          <TableHeader key={key || h.key} {...hProps}>
                            {h.header}
                          </TableHeader>
                        );
                      })}
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {rows.length > 0 ? (
                      rows.map((row) => {
                        const evt = eventsById.get(row.id) || paginatedEvents.find((e) => String(e.id) === String(row.id));
                        if (!evt) return null;

                        const { key, ...rProps } = getRowProps({ row });
                        return (
                          <TableRow
                            key={key || row.id}
                            {...rProps}
                            style={{ cursor: 'pointer' }}
                            onClick={async () => {
                              setSelectedEvent(evt);
                              setEventDrawerOpen(true);
                              try {
                                const details = await apiService.getSecurityEventDetails(evt.id);
                                if (details) {
                                  setSelectedEvent((prev) => (prev && prev.id === evt.id ? { ...prev, ...details } : prev));
                                }
                              } catch (err) {
                                console.warn('Failed to hydrate security event details:', err);
                              }
                            }}
                          >
                            <TableCell style={{ whiteSpace: 'nowrap', width: '160px' }}>
                              <EventTimeCell timestamp={evt.timestamp} />
                            </TableCell>
                            <TableCell style={{ minWidth: '220px', maxWidth: '360px' }}>
                              <EventRequestCell method={evt.method} path={evt.path} />
                            </TableCell>
                            <TableCell style={{ minWidth: '200px' }}>
                              <EventRuleCell rule={evt.rule_name} id={evt.rule_id} />
                            </TableCell>
                            <TableCell style={{ width: '110px' }}>
                              <EventActionBadge action={evt.action} />
                            </TableCell>
                            <TableCell style={{ whiteSpace: 'nowrap', width: '180px' }}>
                              <EventSourceCell ip={evt.client_ip} country={evt.country} />
                            </TableCell>
                            <TableCell style={{ textAlign: 'right', width: '48px' }}>
                              <EventInspectButton
                                onClick={async (e: React.MouseEvent) => {
                                  e.stopPropagation();
                                  setSelectedEvent(evt);
                                  setEventDrawerOpen(true);
                                  try {
                                    const details = await apiService.getSecurityEventDetails(evt.id);
                                    if (details) {
                                      setSelectedEvent((prev) => (prev && prev.id === evt.id ? { ...prev, ...details } : prev));
                                    }
                                  } catch (err) {
                                    console.warn('Failed to hydrate security event details:', err);
                                  }
                                }}
                              />
                            </TableCell>
                          </TableRow>
                        );
                      })
                    ) : (
                      <TableRow>
                        <TableCell colSpan={6} style={{ textAlign: 'center', padding: '32px' }}>
                          <WarningAlt size={24} style={{ color: 'var(--cds-text-helper)', marginBottom: '8px' }} />
                          <p style={{ margin: 0, fontWeight: 600 }}>No matching security events</p>
                          <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>
                            No events match the active filters in this time window.
                          </span>

                          <div style={{ display: 'flex', justifyContent: 'center', gap: '8px', marginTop: '12px' }}>
                            {timeWindow !== '30d' && (
                              <Button
                                kind="tertiary"
                                size="sm"
                                onClick={() => setTimeWindow('30d')}
                              >
                                View last 30 days
                              </Button>
                            )}
                            {Object.keys(activeFilters).length > 0 && (
                              <Button
                                kind="ghost"
                                size="sm"
                                onClick={handleClearFilters}
                              >
                                Clear filters
                              </Button>
                            )}
                          </div>

                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              )}

              {loading ? (
                <PaginationSkeleton />
              ) : (
                <Pagination
                  page={currentPage}
                  pageSize={pageSize}
                  pageSizes={[10, 20, 50, 100]}
                  totalItems={totalEventsCount}
                  onChange={({ page, pageSize: newSize }) => {
                    setCurrentPage(page);
                    setPageSize(newSize);
                  }}
                />
              )}
            </TableContainer>
          )}
        </DataTable>
      </section>

      <EventInspectorModal
        onNavigate={onNavigate}
        open={eventDrawerOpen}
        event={selectedEvent}
        onClose={() => setEventDrawerOpen(false)}
        sectionLabel={`${getSectionName(selectedEvent?.section)} Event`}
        onApplyFilter={(field: string, value: string) => handleApplyFilter(field as any, value)}
      />

      <Modal
        open={statsModalOpen}
        modalHeading={`${statsModalTitle} Breakdown Details`}
        modalLabel="Breakdown"
        primaryButtonText="Close"
        onRequestClose={() => setStatsModalOpen(false)}
        onRequestSubmit={() => setStatsModalOpen(false)}
        size="md"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <p style={{ fontSize: '13px', color: 'var(--cds-text-secondary)', margin: 0 }}>
            {formatNumber(statsModalItems.reduce((acc, i) => acc + (i.count || 0), 0))} total events across {statsModalItems.length} values
          </p>

          <div style={{ maxHeight: '420px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '8px', paddingRight: '6px' }}>
            {statsModalItems.map((item, idx) => {
              const maxVal = Math.max(...statsModalItems.map((i) => i.count || 0), 1);
              const pct = Math.round(((item.count || 0) / maxVal) * 100);
              const itemVal = item.value || item.key || item.label;

              return (
                <div
                  key={item.key || idx}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '8px 12px',
                    background: 'var(--cds-layer-02)',
                    border: '1px solid var(--cds-border-subtle)',
                    borderRadius: '4px',
                    gap: '12px',
                  }}
                >
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                      <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--cds-text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={item.label || item.key}>
                        {item.label || item.key}
                      </span>
                      <strong style={{ fontSize: '12px', fontFamily: 'monospace' }}>
                        {formatNumber(item.count)}
                      </strong>
                    </div>
                    <ProgressBar label="" hideLabel value={pct} max={100} size="small" />
                  </div>

                  <Button
                    kind="tertiary"
                    size="sm"
                    onClick={() => {
                      handleApplyFilter(statsModalFilterKey, itemVal);
                      setStatsModalOpen(false);
                    }}
                  >
                    Filter
                  </Button>
                </div>
              );
            })}
          </div>
        </div>
      </Modal>

      <Modal
        open={filterModalOpen}
        modalHeading="Add filter"
        modalLabel="Filter Builder"
        primaryButtonText="Apply Filter"
        secondaryButtonText="Cancel"
        onRequestClose={() => setFilterModalOpen(false)}
        onRequestSubmit={handleApplyFilterFromModal}
        size="sm"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <Select
            id="filter-field-select"
            labelText="Filter Dimension"
            value={filterField}
            onChange={(e) => setFilterField(e.target.value)}
          >
            {filterKeyOptions.map((opt) => (
              <SelectItem key={opt.value} value={opt.value} text={opt.label} />
            ))}
          </Select>

          <Select
            id="filter-op-select"
            labelText="Operator"
            value={filterOperator}
            onChange={(e) => setFilterOperator(e.target.value)}
          >
            <SelectItem value="equals" text="equals (=)" />
            <SelectItem value="contains" text="contains" />
            <SelectItem value="starts_with" text="starts with" />
            <SelectItem value="in" text="is in" />
          </Select>

          {filterField === 'section' ? (
            <Select
              id="filter-value-section"
              labelText="Protection Section"
              value={filterValue}
              onChange={(e) => setFilterValue(e.target.value)}
            >
              <SelectItem value="waf_core" text="Application Firewall (WAF Core)" />
              <SelectItem value="bot_protection" text="Bot Defense" />
              <SelectItem value="traffic_control" text="Traffic Control" />
              <SelectItem value="api_security" text="API Shield" />
              <SelectItem value="http_security" text="App Security" />
              <SelectItem value="access_control" text="Edge Access" />
            </Select>
          ) : filterField === 'action' ? (
            <Select
              id="filter-value-action"
              labelText="Decision / Action"
              value={filterValue}
              onChange={(e) => setFilterValue(e.target.value)}
            >
              <SelectItem value="block" text="Block (Mitigated)" />
              <SelectItem value="detect" text="Detect (Logged)" />
              <SelectItem value="challenge" text="Challenge (Issued)" />
              <SelectItem value="ratelimit" text="Rate Limit" />
              <SelectItem value="allow" text="Allow" />
            </Select>
          ) : filterField === 'severity' ? (
            <Select
              id="filter-value-severity"
              labelText="Severity Level"
              value={filterValue}
              onChange={(e) => setFilterValue(e.target.value)}
            >
              <SelectItem value="critical" text="Critical" />
              <SelectItem value="high" text="High" />
              <SelectItem value="medium" text="Medium" />
              <SelectItem value="low" text="Low" />
            </Select>
          ) : filterField === 'method' ? (
            <Select
              id="filter-value-method"
              labelText="HTTP Method"
              value={filterValue}
              onChange={(e) => setFilterValue(e.target.value)}
            >
              <SelectItem value="GET" text="GET" />
              <SelectItem value="POST" text="POST" />
              <SelectItem value="PUT" text="PUT" />
              <SelectItem value="DELETE" text="DELETE" />
              <SelectItem value="PATCH" text="PATCH" />
              <SelectItem value="HEAD" text="HEAD" />
              <SelectItem value="OPTIONS" text="OPTIONS" />
            </Select>
          ) : (
            <TextInput
              id="filter-value-text"
              labelText="Filter Value"
              placeholder={filterField === 'path' ? '/api/v1/auth/login' : filterField === 'ip' ? '198.51.100.44' : 'Value...'}
              value={filterValue}
              onChange={(e) => setFilterValue(e.target.value)}
            />
          )}
        </div>
      </Modal>
    </div>
  );
};
export default SecurityEventsPage;
