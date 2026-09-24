// =============================================================================
// SYSTEM HEALTH DASHBOARD
// Resource monitoring: CPU, Memory, Runtime, and Uptime
// =============================================================================

import * as AdminDOM from '../core/dom.js';
import { api } from '../api.js';
import { formatNumber, setHTML, setText } from '../core/view-helpers.js';
import {
  renderMetricSkeleton,
  renderMetricSubSkeleton,
  renderChartSkeleton,
  renderSystemServicesSkeleton,
  renderTextSkeleton
} from './skeletons.js';

interface MemoryPoint {
  time: string;
  value: number;
}

interface SystemDashboardResponse {
  num_cpu?: number;
  goroutines?: number;
  heap_alloc_mb?: number;
  memory_mb?: number;
  memory_sys_mb?: number;
  heap_inuse_mb?: number;
  heap_idle_mb?: number;
  heap_released_mb?: number;
  next_gc_mb?: number;
  uptime?: string;
  uptime_seconds?: number;
  num_gc?: number;
  heap_objects?: number;
  total_alloc_mb?: number;
  gc_pause_total_ms?: number;
  last_gc_unix?: number;
  go_version?: string;
  os?: string;
  arch?: string;
  [key: string]: unknown;
}

interface HealthResponse {
  status?: string;
  checks?: HealthCheck[];
}

interface HealthCheck {
  name?: string;
  status?: string;
  message?: string;
}

// Store memory history for timeline chart
let memoryHistory: MemoryPoint[] = [];
const MAX_MEMORY_POINTS = 60;
let systemDashboardInteractionsBound = false;

export const systemTemplate = `
    <div class="operator-frame system-health-frame">
        <div class="operator-frame-header">
            <div class="operator-frame-title-block">
                <div class="operator-frame-kicker">PLATFORM &amp; GOVERNANCE</div>
                <h2 class="operator-frame-title">System Health &amp; Engine Telemetry</h2>
                <p class="operator-frame-subtitle">Real-time CPU cores, memory allocation, goroutine concurrency, and runtime infrastructure telemetry.</p>
            </div>
            <div class="operator-frame-actions">
                <button type="button" class="btn btn-outline btn-sm" data-system-dashboard-action="refresh" aria-busy="false">Refresh</button>
            </div>
        </div>

        <div class="operator-frame-body system-health-body">
            <div class="operator-metric-strip system-health-metrics">
                <div class="operator-metric-item">
                    <div class="operator-metric-label">CPU Cores</div>
                    <div id="stat-cpu-cores" class="operator-metric-value">${renderMetricSkeleton()}</div>
                    <div id="stat-goroutines" class="operator-metric-sub">${renderMetricSubSkeleton()}</div>
                </div>
                <div class="operator-metric-item">
                    <div class="operator-metric-label">Heap Memory</div>
                    <div id="stat-memory" class="operator-metric-value">${renderMetricSkeleton()}</div>
                    <div id="stat-memory-sys" class="operator-metric-sub">${renderMetricSubSkeleton()}</div>
                </div>
                <div class="operator-metric-item">
                    <div class="operator-metric-label">Garbage Collection</div>
                    <div id="stat-gc" class="operator-metric-value">${renderMetricSkeleton()}</div>
                    <div id="stat-gc-pause" class="operator-metric-sub">${renderMetricSubSkeleton()}</div>
                </div>
                <div class="operator-metric-item">
                    <div class="operator-metric-label">Process Uptime</div>
                    <div id="stat-uptime" class="operator-metric-value">${renderMetricSkeleton()}</div>
                    <div id="stat-uptime-sec" class="operator-metric-sub">${renderMetricSubSkeleton()}</div>
                </div>
                <div class="operator-metric-item">
                    <div class="operator-metric-label">Platform</div>
                    <div id="stat-host" class="operator-metric-value">${renderMetricSkeleton()}</div>
                    <div id="stat-go-version" class="operator-metric-sub">${renderMetricSubSkeleton()}</div>
                </div>
            </div>

            <div class="system-health-main-grid">
                <section class="operator-section system-health-section">
                    <div class="operator-section-head">
                        <div>
                            <h3>Memory Usage History</h3>
                        </div>
                    </div>
                    <div id="system-memory-timeline" class="system-health-chart-panel">
                        ${renderChartSkeleton(16)}
                    </div>
                </section>

                <section class="operator-section system-health-section">
                    <div class="operator-section-head">
                        <div>
                            <h3>Resource Breakdown</h3>
                        </div>
                    </div>
                    <div class="system-health-row-list">
                        <div class="system-health-row"><span>CPU Cores</span><strong id="sys-cores">${renderTextSkeleton('45px')}</strong></div>
                        <div class="system-health-row"><span>Goroutines (Active Tasks)</span><strong id="sys-goroutines">${renderTextSkeleton('55px')}</strong></div>
                        <div class="system-health-row"><span>Heap In Use</span><strong id="sys-heap-inuse">${renderTextSkeleton('65px')}</strong></div>
                        <div class="system-health-row"><span>Heap Idle</span><strong id="sys-heap-idle">${renderTextSkeleton('65px')}</strong></div>
                        <div class="system-health-row"><span>Heap Allocated</span><strong id="sys-heap-alloc">${renderTextSkeleton('65px')}</strong></div>
                        <div class="system-health-row"><span>OS Reserved (Sys)</span><strong id="sys-memory-sys">${renderTextSkeleton('65px')}</strong></div>
                        <div class="system-health-row"><span>Cumulative Allocated</span><strong id="sys-total-alloc">${renderTextSkeleton('75px')}</strong></div>
                        <div class="system-health-row"><span>Live Heap Objects</span><strong id="sys-objects">${renderTextSkeleton('65px')}</strong></div>
                        <div class="system-health-row"><span>GC Cycles</span><strong id="sys-gc-cycles">${renderTextSkeleton('50px')}</strong></div>
                        <div class="system-health-row"><span>GC Total Pause</span><strong id="sys-gc-pause">${renderTextSkeleton('60px')}</strong></div>
                        <div class="system-health-row"><span>Last GC Run</span><strong id="sys-last-gc">${renderTextSkeleton('80px')}</strong></div>
                    </div>
                </section>
            </div>

            <section class="operator-section system-health-section" style="margin-top: 18px;">
                <div class="operator-section-head">
                    <div>
                        <h3>Services & Engine Status</h3>
                    </div>
                </div>
                <div id="system-services-list" class="system-health-row-list">${renderSystemServicesSkeleton(4)}</div>
            </section>
        </div>
    </div>
`;

/**
 * Load System Dashboard data
 */
export function loadSystemDashboard(): Promise<void> {
    bindSystemDashboardInteractions();

    return Promise.all([
        fetch('/api/system').then(r => r.json() as Promise<SystemDashboardResponse>).catch(() => null),
        api.get('health').catch(() => null)
    ]).then(([sysData, health]: [SystemDashboardResponse | null, unknown]) => {
        updateServicesSummary(health as HealthResponse | null);

        if (!sysData) {
            updateSystemMetricsUnavailable();
            return;
        }

        const heapMB = sysData.heap_alloc_mb || sysData.memory_mb || 0;
        const sysMB = sysData.memory_sys_mb || 0;

        // Metrics strip
        setText('stat-cpu-cores', `${sysData.num_cpu || 0} Cores`);
        setText('stat-goroutines', `${sysData.goroutines || 0} active goroutines`);
        setHTML('stat-memory', `${heapMB} <span class="text-small">MB</span>`);
        setText('stat-memory-sys', `OS Reserved: ${sysMB} MB`);
        setText('stat-gc', `${sysData.num_gc || 0} cycles`);
        setText('stat-gc-pause', `Pause: ${formatGCPause(sysData.gc_pause_total_ms)}`);
        setText('stat-uptime', sysData.uptime || '-');
        setText('stat-uptime-sec', `${formatNumber(sysData.uptime_seconds || 0)}s total`);
        setText('stat-host', `${sysData.os || '-'}/${sysData.arch || '-'}`);
        setText('stat-go-version', (sysData.go_version as string) || 'Go runtime');

        // Resource details
        setText('sys-cores', String(sysData.num_cpu || '—'));
        setText('sys-goroutines', formatNumber(sysData.goroutines || 0));
        setText('sys-heap-inuse', formatMegabytes(sysData.heap_inuse_mb));
        setText('sys-heap-idle', formatMegabytes(sysData.heap_idle_mb));
        setText('sys-heap-alloc', formatMegabytes(heapMB));
        setText('sys-memory-sys', formatMegabytes(sysMB));
        setText('sys-total-alloc', formatMegabytes(sysData.total_alloc_mb));
        setText('sys-objects', formatNumber(sysData.heap_objects || 0));
        setText('sys-gc-cycles', formatNumber(sysData.num_gc || 0));
        setText('sys-gc-pause', formatGCPause(sysData.gc_pause_total_ms));
        setText('sys-last-gc', formatLastGCAge(sysData.last_gc_unix));

        // Memory timeline chart
        updateMemoryTimeline(heapMB);
    }).catch(err => console.error('System dashboard error:', err));
}

function updateServicesSummary(health?: HealthResponse | null): void {
    const list = AdminDOM.getById('system-services-list');
    if (!list) return;

    const checks = Array.isArray(health?.checks) ? health.checks : [];
    if (!checks.length) {
        list.innerHTML = `
            <div class="system-health-row">
                <span>Core Traffic Engine</span>
                <strong style="color: var(--success, #22c55e);">Operational</strong>
            </div>`;
        return;
    }

    list.innerHTML = checks.map(check => {
        const isHealthy = (check.status || '').toLowerCase() === 'healthy';
        const statusColor = isHealthy ? 'var(--success, #22c55e)' : 'var(--warning, #f59e0b)';
        const statusLabel = isHealthy ? 'Operational' : (check.status || 'Attention');
        const name = escapeSystemHTML(check.name || 'Component');
        const msg = check.message ? `<small style="display: block; color: var(--text-muted); font-size: 11px; font-weight: normal; margin-top: 2px;">${escapeSystemHTML(check.message)}</small>` : '';
        return `
            <div class="system-health-row">
                <span><strong>${name}</strong>${msg}</span>
                <strong style="color: ${statusColor};">${statusLabel}</strong>
            </div>`;
    }).join('');
}

function metricNumber(value: unknown): number | null {
    return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;
}

function formatMegabytes(value: unknown): string {
    const megabytes = metricNumber(value);
    return megabytes === null ? 'Not reported' : `${formatNumber(Math.round(megabytes))} MB`;
}

function formatRuntimeRatio(value: number): string {
    return value >= 10 ? formatNumber(Math.round(value)) : value.toFixed(1).replace(/\.0$/, '');
}

function formatGCPause(value: unknown): string {
    const milliseconds = metricNumber(value);
    if (milliseconds === null) return '0 ms';
    return milliseconds >= 1000
        ? `${formatRuntimeRatio(milliseconds / 1000)} s`
        : `${formatNumber(Math.round(milliseconds))} ms`;
}

function formatLastGCAge(value: unknown): string {
    const timestamp = metricNumber(value);
    if (!timestamp) return 'No completed GC';

    const elapsedSeconds = Math.max(0, Math.floor(Date.now() / 1000 - timestamp));
    if (elapsedSeconds < 5) return 'Just now';
    if (elapsedSeconds < 60) return `${elapsedSeconds}s ago`;
    if (elapsedSeconds < 3600) return `${Math.floor(elapsedSeconds / 60)}m ago`;
    if (elapsedSeconds < 86400) return `${Math.floor(elapsedSeconds / 3600)}h ago`;
    return `${Math.floor(elapsedSeconds / 86400)}d ago`;
}

function updateSystemMetricsUnavailable(): void {
    setText('stat-cpu-cores', '—');
    setText('stat-goroutines', 'Not available');
    setText('stat-memory', '—');
    setText('stat-memory-sys', 'Not available');
    setText('stat-gc', '—');
    setText('stat-gc-pause', 'Not available');
    setText('stat-uptime', '—');
    setText('stat-uptime-sec', 'Not available');
    setText('stat-host', '—');
    setText('stat-go-version', 'Not available');

    setText('sys-cores', '—');
    setText('sys-goroutines', '—');
    setText('sys-heap-inuse', 'Not available');
    setText('sys-heap-idle', 'Not available');
    setText('sys-heap-alloc', '—');
    setText('sys-memory-sys', 'Not available');
    setText('sys-total-alloc', 'Not available');
    setText('sys-objects', '—');
    setText('sys-gc-cycles', '—');
    setText('sys-gc-pause', 'Not available');
    setText('sys-last-gc', 'Not available');
}

/**
 * Update memory timeline chart with new data point
 */
function updateMemoryTimeline(memoryMB: number): void {
    const now = new Date();
    memoryHistory.push({
        time: now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        value: memoryMB
    });

    if (memoryHistory.length > MAX_MEMORY_POINTS) {
        memoryHistory.shift();
    }

    initMemoryTimelineChart();
}

function getMemoryTimelineSummary(values: number[]): { latest: number; trend: string } {
    const latest = values[values.length - 1] || 0;
    const first = values[0] || latest;
    const delta = latest - first;
    const trend = values.length < 2
        ? 'Collecting samples.'
        : delta === 0
            ? 'Memory is stable.'
            : `${delta > 0 ? '+' : ''}${formatNumber(delta)} MB from start.`;
    return { latest, trend };
}

/**
 * Render the memory history SVG chart
 */
function initMemoryTimelineChart(): void {
    const panel = AdminDOM.getById('system-memory-timeline');
    if (!panel) return;
    const values = memoryHistory.map(point => point.value);
    if (!values.length) {
        panel.innerHTML = '<div class="system-health-chart-empty">Collecting memory data…</div>';
        return;
    }

    const { latest, trend } = getMemoryTimelineSummary(values);
    const chartWidth = 720;
    const chartHeight = 248;
    const plotLeft = 32;
    const plotRight = 710;
    const plotTop = 8;
    const plotBottom = 214;
    const plotHeight = plotBottom - plotTop;
    const maximum = Math.max(...values, 1);
    const slotWidth = memoryHistory.length > 1 ? (plotRight - plotLeft) / (memoryHistory.length - 1) : 0;
    const points = memoryHistory.map((point, index) => ({
        x: memoryHistory.length === 1 ? (plotLeft + plotRight) / 2 : plotLeft + (slotWidth * index),
        y: plotBottom - ((point.value / maximum) * plotHeight),
        time: point.time,
        value: point.value
    }));
    const line = points.map((point, index) => `${index ? 'L' : 'M'} ${point.x} ${point.y}`).join(' ');
    const first = points[0];
    const last = points[points.length - 1];
    const area = `${line} L ${last.x} ${plotBottom} L ${first.x} ${plotBottom} Z`;
    const labelEvery = Math.max(1, Math.ceil((points.length - 1) / 3));
    const labels = points.map((point, index) => {
        if (index !== 0 && index !== points.length - 1 && index % labelEvery !== 0) return '';
        if (index < points.length - 1 && point.time === points[points.length - 1].time) return '';
        const anchor = index === 0 ? 'start' : index === points.length - 1 ? 'end' : 'middle';
        return `<text class="system-health-timeline-label" x="${point.x}" y="${chartHeight - 6}" text-anchor="${anchor}">${escapeSystemHTML(point.time)}</text>`;
    }).join('');
    const grid = [0, .5, 1].map(fraction => {
        const y = plotBottom - (plotHeight * fraction);
        const label = fraction === 0 ? '0' : formatNumber(Math.round(maximum * fraction));
        return `<line class="system-health-timeline-grid" x1="${plotLeft}" y1="${y}" x2="${plotRight}" y2="${y}" /><text class="system-health-timeline-value" x="${plotLeft - 8}" y="${y + 4}" text-anchor="end">${label}</text>`;
    }).join('');
    const pointData = escapeSystemHTML(JSON.stringify(points));
    panel.innerHTML = `<svg class="system-health-timeline-svg" data-system-memory-points="${pointData}" viewBox="0 0 ${chartWidth} ${chartHeight}" preserveAspectRatio="none" role="img" aria-label="Memory timeline. Latest: ${formatNumber(latest)} MB. ${escapeSystemHTML(trend)}">${grid}<path class="system-health-timeline-area" d="${area}" /><path class="system-health-timeline-line" d="${line}" />${points.map(point => `<circle class="system-health-timeline-point" cx="${point.x}" cy="${point.y}" r="3" />`).join('')}<rect class="system-health-timeline-hitbox" x="${plotLeft}" y="${plotTop}" width="${plotRight - plotLeft}" height="${plotHeight}" />${labels}</svg><div class="system-health-timeline-tooltip" hidden></div>`;
    bindMemoryTimelineHover(panel);
}

function escapeSystemHTML(value: unknown): string {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function bindMemoryTimelineHover(panel: HTMLElement): void {
    const chart = panel.querySelector<SVGSVGElement>('.system-health-timeline-svg');
    const tooltip = panel.querySelector<HTMLElement>('.system-health-timeline-tooltip');
    if (!chart || !tooltip) return;
    let points: Array<{ x: number; time: string; value: number }> = [];
    try {
        points = JSON.parse(chart.dataset.systemMemoryPoints || '[]');
    } catch {
        return;
    }
    if (!points.length) return;
    chart.addEventListener('pointermove', event => {
        const rect = chart.getBoundingClientRect();
        if (!rect.width) return;
        const chartX = ((event.clientX - rect.left) / rect.width) * 720;
        const point = points.reduce((nearest, candidate) => Math.abs(candidate.x - chartX) < Math.abs(nearest.x - chartX) ? candidate : nearest);
        tooltip.innerHTML = `<strong>${escapeSystemHTML(point.time)}</strong><span>${formatNumber(point.value)} MB</span>`;
        tooltip.hidden = false;
        const panelRect = panel.getBoundingClientRect();
        const pointerX = event.clientX - panelRect.left;
        const pointerY = event.clientY - panelRect.top;
        tooltip.style.left = `${Math.max(8, Math.min(pointerX + 14, panel.clientWidth - tooltip.offsetWidth - 8))}px`;
        tooltip.style.top = `${Math.max(8, Math.min(pointerY - tooltip.offsetHeight - 12, panel.clientHeight - tooltip.offsetHeight - 8))}px`;
    });
    chart.addEventListener('pointerleave', () => { tooltip.hidden = true; });
}

function bindSystemDashboardInteractions(): void {
    if (systemDashboardInteractionsBound) return;
    systemDashboardInteractionsBound = true;

    document.addEventListener('click', event => {
        if (!(event.target instanceof Element)) return;
        const refresh = event.target.closest<HTMLButtonElement>('[data-system-dashboard-action="refresh"]');
        if (!refresh || refresh.disabled) return;
        event.preventDefault();
        setSystemDashboardRefreshState(refresh, true);
        void loadSystemDashboard().finally(() => setSystemDashboardRefreshState(refresh, false));
    });
}

function setSystemDashboardRefreshState(button: HTMLButtonElement, refreshing: boolean): void {
    button.disabled = refreshing;
    button.setAttribute('aria-busy', String(refreshing));
    button.textContent = refreshing ? 'Refreshing…' : 'Refresh';
}
