import * as AdminDOM from './dom.js';
const chartRegistry = new Set();
const actionPalette = {
    block: '#ef4444',
    detect: '#64748b',
    error: '#94a3b8',
    challenge: '#f97316',
    ratelimit: '#f97316',
    rate_limit: '#f97316',
    allow: '#10b981',
    log: '#64748b',
    redirect: '#8b5cf6',
    mitigated: '#ef4444',
    origin: '#10b981',
    served: '#0ea5e9'
};
let resizeBound = false;
export function renderEventTimelineChart(elementId, points, options = {}) {
    const element = chartElementById(elementId);
    if (!element)
        return;
    const chart = createEChart(element);
    if (!chart) {
        renderChartFallback(element, points);
        return;
    }
    const theme = readChartTheme();
    chart.setOption({
        animation: true,
        animationDuration: 420,
        backgroundColor: 'transparent',
        color: [actionPalette.mitigated, actionPalette.origin, actionPalette.served],
        grid: { top: 22, right: 18, bottom: 28, left: 42, containLabel: true },
        tooltip: {
            trigger: 'axis',
            axisPointer: { type: 'line', lineStyle: { color: theme.axisPointer, width: 1 } },
            backgroundColor: theme.tooltipBg,
            borderColor: theme.tooltipBorder,
            borderWidth: 1,
            padding: [8, 10],
            textStyle: { color: theme.text, fontFamily: theme.font, fontSize: 12 },
            valueFormatter: (value) => formatChartNumber(Number(value || 0))
        },
        legend: {
            top: 0,
            right: 0,
            itemWidth: 10,
            itemHeight: 10,
            textStyle: { color: theme.muted, fontFamily: theme.font, fontSize: 11, fontWeight: 600 }
        },
        xAxis: {
            type: 'category',
            boundaryGap: false,
            data: points.map(point => point.label),
            axisLine: { lineStyle: { color: theme.axis } },
            axisTick: { show: false },
            axisLabel: { color: theme.muted, fontFamily: theme.font, fontSize: 11, hideOverlap: true },
            splitLine: { show: false }
        },
        yAxis: {
            type: 'value',
            minInterval: 1,
            axisLabel: {
                color: theme.muted,
                fontFamily: theme.font,
                fontSize: 11,
                formatter: (value) => formatChartNumber(value)
            },
            splitLine: { lineStyle: { color: theme.grid } }
        },
        series: [
            timelineSeries('Mitigated', points.map(point => point.mitigated || 0), actionPalette.mitigated),
            timelineSeries('Origin', points.map(point => point.origin || 0), actionPalette.origin),
            timelineSeries('Observed', points.map(point => point.served || 0), actionPalette.served)
        ]
    });
    if (options.onBucketClick) {
        chart.on('click', params => {
            const index = typeof params.dataIndex === 'number' ? params.dataIndex : -1;
            const bucket = points[index]?.bucket;
            if (bucket)
                options.onBucketClick?.(bucket);
        });
    }
}
export function disposeEChart(elementId) {
    const element = chartElementById(elementId);
    if (!element?._aegisEChart)
        return;
    element._aegisEChart.dispose();
    delete element._aegisEChart;
    chartRegistry.delete(element);
}
export function renderActionMixStackedBarChart(elementId, items, options = {}) {
    const element = chartElementById(elementId);
    if (!element)
        return;
    const visible = items.filter(item => item.count > 0);
    if (!visible.length) {
        disposeEChart(elementId);
        renderChartMessage(element, 'No action data');
        return;
    }
    const chart = createEChart(element);
    if (!chart) {
        renderChartMessage(element, 'Chart unavailable');
        return;
    }
    const theme = readChartTheme();
    const labelToKey = new Map(visible.map(item => [item.label, item.key]));
    chart.setOption({
        animation: true,
        animationDuration: 360,
        backgroundColor: 'transparent',
        color: visible.map(item => colorForAction(item.key)),
        grid: { top: 8, right: 0, bottom: 8, left: 0, containLabel: false },
        tooltip: {
            trigger: 'item',
            backgroundColor: theme.tooltipBg,
            borderColor: theme.tooltipBorder,
            borderWidth: 1,
            padding: [8, 10],
            textStyle: { color: theme.text, fontFamily: theme.font, fontSize: 12 },
            valueFormatter: (value) => formatChartNumber(Number(value || 0))
        },
        legend: { show: false },
        xAxis: {
            type: 'value',
            min: 0,
            max: visible.reduce((sum, item) => sum + item.count, 0),
            show: false
        },
        yAxis: {
            type: 'category',
            data: [''],
            show: false
        },
        series: visible.map(item => ({
            name: item.label,
            type: 'bar',
            stack: 'actions',
            barWidth: 18,
            itemStyle: { color: colorForAction(item.key), borderRadius: 3 },
            emphasis: { focus: 'series' },
            data: [item.count]
        }))
    });
    if (options.onActionClick) {
        chart.on('click', params => {
            const key = params.seriesName ? labelToKey.get(params.seriesName) : '';
            if (key)
                options.onActionClick?.(key);
        });
    }
}
function createEChart(element) {
    if (!window.echarts)
        return null;
    if (!element._aegisEChart) {
        element._aegisEChart = window.echarts.init(element, undefined, { renderer: 'canvas' });
        chartRegistry.add(element);
        bindResizeHandler();
    }
    return element._aegisEChart;
}
function timelineSeries(name, data, color) {
    return {
        name,
        type: 'line',
        stack: 'events',
        smooth: true,
        symbol: 'circle',
        symbolSize: 5,
        showSymbol: false,
        emphasis: { focus: 'series' },
        lineStyle: { width: 2, color },
        areaStyle: { color, opacity: 0.13 },
        itemStyle: { color },
        data
    };
}
function chartElementById(id) {
    const element = AdminDOM.getById(id);
    return element instanceof HTMLElement ? element : null;
}
function readChartTheme() {
    const root = document.documentElement;
    const styles = getComputedStyle(root);
    const dark = root.dataset.theme === 'dark';
    return {
        font: styles.getPropertyValue('--font-main').trim() || 'Inter, system-ui, sans-serif',
        text: styles.getPropertyValue('--text-main').trim() || (dark ? '#f8fafc' : '#101214'),
        muted: styles.getPropertyValue('--text-muted').trim() || (dark ? '#94a3b8' : '#64748b'),
        grid: dark ? 'rgba(148, 163, 184, 0.12)' : 'rgba(100, 116, 139, 0.14)',
        axis: dark ? 'rgba(148, 163, 184, 0.18)' : 'rgba(100, 116, 139, 0.18)',
        axisPointer: dark ? 'rgba(226, 232, 240, 0.34)' : 'rgba(71, 85, 105, 0.28)',
        shadow: dark ? 'rgba(148, 163, 184, 0.08)' : 'rgba(15, 23, 42, 0.05)',
        tooltipBg: dark ? 'rgba(15, 23, 42, 0.96)' : 'rgba(255, 255, 255, 0.98)',
        tooltipBorder: dark ? 'rgba(148, 163, 184, 0.22)' : 'rgba(15, 23, 42, 0.12)'
    };
}
function renderChartFallback(element, points) {
    element.innerHTML = points.length
        ? '<div class="security-events-chart-fallback">Chart unavailable</div>'
        : '<div class="security-events-chart-fallback">No timeline data</div>';
}
function renderChartMessage(element, message) {
    element.innerHTML = `<div class="security-events-chart-fallback">${message}</div>`;
}
function bindResizeHandler() {
    if (resizeBound)
        return;
    resizeBound = true;
    window.addEventListener('resize', () => {
        chartRegistry.forEach(element => element._aegisEChart?.resize());
    });
}
function formatChartNumber(value) {
    return new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 })
        .format(value || 0)
        .replace(/([KMBT])$/i, match => match.toUpperCase());
}
function colorForAction(action) {
    return actionPalette[action] || actionPalette.log;
}
