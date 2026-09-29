/**
 * Reusable Skeleton Loading System for Dashboards & Analytics
 * Source of truth: web/admin/src/dashboards/skeletons.ts
 */
/**
 * Renders a large metric value skeleton (e.g. for card stat values like '14,289', '99.4%')
 */
export function renderMetricSkeleton(width = '74px', height = '28px') {
    return `<span class="skeleton skeleton-metric-val" style="width: ${width}; height: ${height};" aria-hidden="true"></span>`;
}
/**
 * Renders a metric sub-note skeleton (e.g. for subtitles like 'Last 24h', 'Enforced blocks')
 */
export function renderMetricSubSkeleton(width = '96px', height = '12px') {
    return `<span class="skeleton skeleton-metric-sub" style="width: ${width}; height: ${height};" aria-hidden="true"></span>`;
}
/**
 * Renders a text line skeleton
 */
export function renderTextSkeleton(width = '100%', height = '13px') {
    return `<span class="skeleton skeleton-text" style="width: ${width}; height: ${height};" aria-hidden="true"></span>`;
}
/**
 * Renders a badge / pill skeleton
 */
export function renderBadgeSkeleton(width = '52px', height = '20px') {
    return `<span class="skeleton skeleton-badge" style="width: ${width}; height: ${height};" aria-hidden="true"></span>`;
}
/**
 * Renders a timeline / activity chart skeleton with simulated multi-height bars and axis
 */
export function renderChartSkeleton(barCount = 18) {
    const heights = [
        32, 54, 42, 68, 48, 85, 62, 38, 58, 76,
        45, 70, 88, 52, 64, 82, 40, 60, 75, 50,
        92, 66, 44, 78
    ];
    const bars = Array.from({ length: barCount }, (_, index) => {
        const h = heights[index % heights.length];
        return `<div class="skeleton skeleton-chart-col" style="height: ${h}%;" aria-hidden="true"></div>`;
    }).join('');
    return `
    <div class="skeleton-chart-container" aria-label="Loading chart data…">
      <div class="skeleton-chart-bars">
        ${bars}
      </div>
      <div class="skeleton-chart-axis">
        <span class="skeleton skeleton-text" style="width: 38px; height: 10px;"></span>
        <span class="skeleton skeleton-text" style="width: 48px; height: 10px;"></span>
        <span class="skeleton skeleton-text" style="width: 48px; height: 10px;"></span>
        <span class="skeleton skeleton-text" style="width: 38px; height: 10px;"></span>
      </div>
    </div>
  `;
}
/**
 * Renders a stack of breakdown progress rows (e.g. for posture, top paths, or sources)
 */
export function renderBreakdownSkeleton(rowCount = 5) {
    const labelWidths = ['45%', '60%', '35%', '50%', '40%', '55%'];
    const barWidths = ['78%', '52%', '88%', '34%', '64%', '42%'];
    const countWidths = ['28px', '34px', '24px', '32px', '30px', '26px'];
    const rows = Array.from({ length: rowCount }, (_, index) => {
        const lw = labelWidths[index % labelWidths.length];
        const bw = barWidths[index % barWidths.length];
        const cw = countWidths[index % countWidths.length];
        return `
      <div class="skeleton-breakdown-row" aria-hidden="true">
        <div class="skeleton-breakdown-label">
          <span class="skeleton skeleton-text" style="width: ${lw};"></span>
        </div>
        <div class="skeleton-breakdown-track">
          <span class="skeleton skeleton-bar" style="width: ${bw}; height: 6px;"></span>
        </div>
        <div class="skeleton-breakdown-count">
          <span class="skeleton skeleton-text" style="width: ${cw};"></span>
        </div>
      </div>
    `;
    }).join('');
    return `<div class="skeleton-breakdown-list">${rows}</div>`;
}
/**
 * Renders a grid of analytic metric cards (e.g. for protection analytics / control activity)
 */
export function renderProtectionCardsSkeleton(cardCount = 4) {
    const cards = Array.from({ length: cardCount }, () => `
    <div class="skeleton-analytic-card" aria-hidden="true">
      <div class="skeleton skeleton-title" style="width: 58%; height: 15px;"></div>
      <div class="skeleton skeleton-metric-val" style="width: 48%; height: 24px; margin: 6px 0;"></div>
      <div style="display: flex; flex-direction: column; gap: 8px; margin-top: 6px;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <span class="skeleton skeleton-text" style="width: 40%; height: 11px;"></span>
          <span class="skeleton skeleton-text" style="width: 24px; height: 11px;"></span>
        </div>
        <span class="skeleton skeleton-bar" style="width: 100%; height: 5px;"></span>
      </div>
    </div>
  `).join('');
    return `<div class="waf-dashboard-section-analytics-cards">${cards}</div>`;
}
/**
 * Renders skeleton rows for tables (events, decisions, rules)
 */
export function renderTableSkeleton(columnCount = 8, rowCount = 6) {
    const widthsByCol = {
        0: ['68px', '72px', '65px', '70px', '74px', '66px'],
        1: ['46px', '52px', '48px', '56px', '46px', '50px'],
        2: ['160px', '210px', '140px', '180px', '230px', '150px'],
        3: ['120px', '140px', '110px', '130px', '150px', '115px'],
        4: ['62px', '70px', '58px', '66px', '64px', '60px'],
        5: ['100px', '115px', '95px', '108px', '120px', '98px'],
        6: ['34px', '38px', '32px', '36px', '34px', '40px'],
        7: ['22px', '22px', '22px', '22px', '22px', '22px']
    };
    return Array.from({ length: rowCount }, (_, rowIndex) => {
        const cells = Array.from({ length: columnCount }, (_, colIndex) => {
            const colWidths = widthsByCol[colIndex] || ['80px'];
            const w = colWidths[rowIndex % colWidths.length];
            const isRight = colIndex >= columnCount - 2;
            const isBadge = colIndex === 1 || colIndex === 4 || colIndex === columnCount - 2;
            const isCircle = colIndex === columnCount - 1;
            if (isCircle) {
                return `<td class="${isRight ? 'text-right' : ''}"><span class="skeleton skeleton-badge" style="width: ${w}; height: 22px; border-radius: 50%;"></span></td>`;
            }
            if (isBadge) {
                return `<td class="${isRight ? 'text-right' : ''}"><span class="skeleton skeleton-badge" style="width: ${w}; height: 20px;"></span></td>`;
            }
            return `<td class="${isRight ? 'text-right' : ''}"><span class="skeleton skeleton-text" style="width: ${w};"></span></td>`;
        }).join('');
        return `<tr class="skeleton-table-row" aria-hidden="true">${cells}</tr>`;
    }).join('');
}
/**
 * Renders skeleton rows for System Health services
 */
export function renderSystemServicesSkeleton(rowCount = 4) {
    const names = ['80px', '110px', '95px', '125px'];
    const descs = ['180px', '220px', '160px', '200px'];
    return Array.from({ length: rowCount }, (_, index) => `
    <div class="system-health-row skeleton-service-row" aria-hidden="true" style="padding: 10px 0; border-bottom: 1px solid var(--waf-dashboard-soft-line, rgba(255,255,255,0.06)); display: flex; align-items: center; justify-content: space-between;">
      <div style="display: flex; align-items: center; gap: 12px;">
        <span class="skeleton skeleton-badge" style="width: 58px; height: 20px;"></span>
        <span class="skeleton skeleton-text" style="width: ${names[index % names.length]}; height: 14px;"></span>
      </div>
      <span class="skeleton skeleton-text" style="width: ${descs[index % descs.length]}; height: 12px;"></span>
    </div>
  `).join('');
}
/**
 * Renders the full Security Analytics (Traffic Events) page skeleton
 */
export function renderSecurityAnalyticsSkeleton() {
    return `
    <div class="security-analytics-shell security-events-explorer security-events-operator-explorer">
      <div class="operator-metric-strip security-events-metrics">
        <div class="operator-metric-item">
          <div class="operator-metric-label">Total Events</div>
          <div class="operator-metric-value">${renderMetricSkeleton()}</div>
          <div class="operator-metric-sub">${renderMetricSubSkeleton()}</div>
        </div>
        <div class="operator-metric-item">
          <div class="operator-metric-label">Enforced Blocks</div>
          <div class="operator-metric-value">${renderMetricSkeleton()}</div>
          <div class="operator-metric-sub">${renderMetricSubSkeleton()}</div>
        </div>
        <div class="operator-metric-item">
          <div class="operator-metric-label">Observations</div>
          <div class="operator-metric-value">${renderMetricSkeleton()}</div>
          <div class="operator-metric-sub">${renderMetricSubSkeleton()}</div>
        </div>
        <div class="operator-metric-item">
          <div class="operator-metric-label">Active Challenges</div>
          <div class="operator-metric-value">${renderMetricSkeleton()}</div>
          <div class="operator-metric-sub">${renderMetricSubSkeleton()}</div>
        </div>
        <div class="operator-metric-item">
          <div class="operator-metric-label">Active Sources</div>
          <div class="operator-metric-value">${renderMetricSkeleton()}</div>
          <div class="operator-metric-sub">${renderMetricSubSkeleton()}</div>
        </div>
      </div>

      <div class="security-events-analysis-grid">
        <section class="operator-section system-health-section security-events-timeline-panel">
          <div class="operator-section-head">
            <div><h3>Traffic overview</h3></div>
          </div>
          <div class="waf-dashboard-timeline-shell" style="min-height: 240px;">
            ${renderChartSkeleton(16)}
          </div>
        </section>
        <section class="operator-section system-health-section security-events-action-mix-panel">
          <div class="operator-section-head">
            <div><h3>Action distribution</h3></div>
          </div>
          <div style="padding: 16px;">
            ${renderBreakdownSkeleton(4)}
          </div>
        </section>
      </div>

      <section class="operator-section waf-dashboard-section waf-dashboard-events-section" style="margin-top: 16px;">
        <div class="operator-section-head">
          <div><h3>Live Traffic Events</h3></div>
        </div>
        <div class="config-table-wrap security-events-routing-table-wrap">
          <table class="config-enterprise-table security-events-routing-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Method</th>
                <th>Path</th>
                <th>Rule / Reason</th>
                <th>Decision</th>
                <th>Source</th>
                <th class="text-right">Score</th>
                <th class="text-right"><span class="sr-only">Details</span></th>
              </tr>
            </thead>
            <tbody>
              ${renderTableSkeleton(8, 8)}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  `;
}
