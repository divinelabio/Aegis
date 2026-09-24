import * as AdminDOM from './dom.js';
export function setText(elementId, text) {
    const element = AdminDOM.getById(elementId);
    if (element)
        element.textContent = String(text);
}
export function setHTML(elementId, html) {
    const element = AdminDOM.getById(elementId);
    if (element)
        element.innerHTML = html;
}
export function escapeDashboardHTML(value) {
    return value
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}
export function formatNumber(value) {
    if (value === null || value === undefined || Number.isNaN(Number(value)))
        return '0';
    const numeric = Number(value);
    if (numeric >= 1000000000) {
        const formatted = numeric / 1000000000;
        return formatted % 1 === 0 ? `${formatted}B` : `${formatted.toFixed(1)}B`;
    }
    if (numeric >= 1000000) {
        const formatted = numeric / 1000000;
        return formatted % 1 === 0 ? `${formatted}M` : `${formatted.toFixed(1)}M`;
    }
    if (numeric >= 1000) {
        const formatted = numeric / 1000;
        return formatted % 1 === 0 ? `${formatted}K` : `${formatted.toFixed(1)}K`;
    }
    return Math.round(numeric).toString();
}
export function dashboardEmptyRow(columns, title, detail = '') {
    const detailHTML = detail
        ? `<div class="dashboard-empty-detail">${escapeDashboardHTML(detail)}</div>`
        : '';
    return `
    <tr>
      <td colspan="${columns}" class="table-empty dashboard-empty-cell">
        <div class="dashboard-empty-state">
          <div class="dashboard-empty-icon" aria-hidden="true">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M8 12h8"/></svg>
          </div>
          <div class="dashboard-empty-title">${escapeDashboardHTML(title)}</div>
          ${detailHTML}
        </div>
      </td>
    </tr>
  `;
}
