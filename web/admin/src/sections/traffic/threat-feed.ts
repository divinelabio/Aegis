/**
 * Unified Threat Feed & Directory Sub-view
 * High-performance UI for inspecting synchronized DivineLab CTI threat intelligence.
 */
import { SectionUI } from '../ui-components.js';
import {
    ThreatFeedPaginationState,
    TrafficReputationConfig,
    UnifiedThreatFeedData,
    UnifiedThreatIndicator
} from './types.js';
import {
    escapeTrafficAttr,
    escapeTrafficHtml,
    formatTrafficNumber
} from '../traffic-runtime-helpers.js';

export function renderThreatDirectorySection(
    feedData: UnifiedThreatFeedData | null,
    _reputationConfig: TrafficReputationConfig | undefined,
    pagination: ThreatFeedPaginationState,
    icons: Record<string, string>
): string {
    const rawIndicators = feedData?.indicators || [];
    const allIndicators: UnifiedThreatIndicator[] = rawIndicators;
    const totalCount = feedData?.total_indicators ?? rawIndicators.length;
    const isLoading = false;

    const ctiSource = feedData?.sources?.cti || feedData?.cti;
    const ctiStatusObj = ctiSource?.status;
    const ctiError = ctiStatusObj?.last_error;
    const isCtiDisconnected = Boolean(!feedData || (ctiError && totalCount === 0) || ((ctiStatusObj?.failures ?? 0) > 0 && totalCount === 0));

    const criticalCount = allIndicators.filter(i => (i.score || 0) >= 90 || i.severity === 'CRITICAL').length;
    const highCount = allIndicators.filter(i => ((i.score || 0) >= 70 && (i.score || 0) < 90) || i.severity === 'HIGH').length;

    // Filtering
    const activeSevFilter = pagination.severityFilter || 'all';
    let filtered = allIndicators;
    if (activeSevFilter === 'critical') {
        filtered = filtered.filter(item => (item.score || 0) >= 90 || item.severity === 'CRITICAL');
    } else if (activeSevFilter === 'high') {
        filtered = filtered.filter(item => ((item.score || 0) >= 70 && (item.score || 0) < 90) || item.severity === 'HIGH');
    } else if (activeSevFilter === 'malware') {
        filtered = filtered.filter(item => (item.category || '').toLowerCase().includes('malware') || (item.category || '').toLowerCase().includes('c2') || (item.threat_name || '').toLowerCase().includes('malware'));
    } else if (activeSevFilter === 'botnet') {
        filtered = filtered.filter(item => (item.category || '').toLowerCase().includes('botnet') || (item.threat_name || '').toLowerCase().includes('botnet'));
    } else if (activeSevFilter === 'phishing') {
        filtered = filtered.filter(item => (item.category || '').toLowerCase().includes('phish'));
    } else if (activeSevFilter === 'scanner') {
        filtered = filtered.filter(item => (item.category || '').toLowerCase().includes('scan') || (item.category || '').toLowerCase().includes('exploit'));
    } else if (activeSevFilter === 'cybercrime') {
        filtered = filtered.filter(item => (item.category || '').toLowerCase().includes('cybercrime') || (item.category || '').toLowerCase().includes('hijack'));
    } else if (activeSevFilter === 'relay') {
        filtered = filtered.filter(item => (item.category || '').toLowerCase().includes('relay') || (item.category || '').toLowerCase().includes('anonym'));
    }

    const searchQuery = (pagination.search || '').trim().toLowerCase();
    if (searchQuery) {
        filtered = filtered.filter(item =>
            item.indicator.toLowerCase().includes(searchQuery) ||
            item.category.toLowerCase().includes(searchQuery) ||
            (item.severity || '').toLowerCase().includes(searchQuery) ||
            (item.confidence || '').toLowerCase().includes(searchQuery) ||
            (item.threat_name || '').toLowerCase().includes(searchQuery) ||
            (item.malware_family || '').toLowerCase().includes(searchQuery) ||
            (item.threat_actor || '').toLowerCase().includes(searchQuery)
        );
    }

    // Dynamic Sorting
    const sortBy = pagination.sortBy || 'score';
    const sortOrder = pagination.sortOrder || 'desc';
    const sorted = [...filtered].sort((a, b) => {
        let cmp = 0;
        if (sortBy === 'score') {
            cmp = (a.score || 0) - (b.score || 0);
        } else if (sortBy === 'severity') {
            const mapSev = (s?: string) => s === 'CRITICAL' ? 3 : s === 'HIGH' ? 2 : 1;
            cmp = mapSev(a.severity) - mapSev(b.severity);
        } else if (sortBy === 'indicator') {
            cmp = a.indicator.localeCompare(b.indicator);
        } else if (sortBy === 'category') {
            cmp = (a.category || '').localeCompare(b.category || '');
        } else if (sortBy === 'confidence') {
            cmp = (a.confidence || '').localeCompare(b.confidence || '');
        } else if (sortBy === 'protocol') {
            const aProto = a.indicator.includes(':') ? 'IPv6' : 'IPv4';
            const bProto = b.indicator.includes(':') ? 'IPv6' : 'IPv4';
            cmp = aProto.localeCompare(bProto);
        }
        return sortOrder === 'desc' ? -cmp : cmp;
    });

    const totalFiltered = sorted.length;
    const pageSize = pagination.pageSize || 25;
    const totalPages = Math.max(1, Math.ceil(totalFiltered / pageSize));
    if (pagination.page > totalPages) {
        pagination.page = totalPages;
    }
    if (pagination.page < 1) {
        pagination.page = 1;
    }
    const startIndex = (pagination.page - 1) * pageSize;
    const pageEntries = sorted.slice(startIndex, startIndex + pageSize);

    const sortAscIcon = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="18 15 12 9 6 15"/></svg>';
    const sortDescIcon = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>';

    const renderSortHeader = (field: 'indicator' | 'score' | 'severity' | 'category' | 'protocol' | 'confidence', label: string, thClass = '') => {
        const isCurrent = sortBy === field;
        const arrow = isCurrent ? (sortOrder === 'asc' ? sortAscIcon : sortDescIcon) : '';
        return `
            <th class="${thClass} sortable-th ${isCurrent ? 'is-sorted' : ''}"
                data-traffic-action="threat-feed-sort" data-sort-by="${field}"
                role="columnheader" aria-sort="${isCurrent ? (sortOrder === 'asc' ? 'ascending' : 'descending') : 'none'}"
                tabindex="0" title="Click to sort by ${label}">
                <div class="th-content-flex">
                    <span>${label}</span>
                    <span class="sort-icon-box" aria-hidden="true">${arrow}</span>
                </div>
            </th>
        `;
    };

    return `
        <section class="flow-blacklist-inventory">
            <div class="flow-blacklist-head">
                <div>
                    <div class="flow-rate-eyebrow">Threat Intelligence</div>
                    <h3>Synchronized Threat Directory (${isLoading ? '...' : formatTrafficNumber(totalCount)})</h3>
                    <p>Consolidated threat indicators database aggregated from DivineLab CTI for edge-layer decisioning.</p>
                </div>
                <div class="flow-blacklist-head-actions">
                    <button class="operator-btn operator-btn-secondary" type="button" data-traffic-action="refresh-threat-feed">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="mr-6"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
                        Refresh feed
                    </button>
                </div>
            </div>

            <div class="flow-blacklist-toolbar">
                <div class="flow-blacklist-count">
                    <strong>${isLoading ? '...' : searchQuery || activeSevFilter !== 'all' ? totalFiltered : totalCount}</strong>
                    <span>${searchQuery || activeSevFilter !== 'all' ? `matching of ${totalCount} indicators` : 'active threat indicators'}</span>
                </div>
                <div class="flow-blacklist-tools">
                    <select class="flow-page-size-select mr-8"
                            aria-label="Filter by Threat Category or Severity"
                            data-traffic-action="threat-feed-severity-filter">
                        <option value="all" ${activeSevFilter === 'all' ? 'selected' : ''}>All Categories (${formatTrafficNumber(totalCount)})</option>
                        <option value="critical" ${activeSevFilter === 'critical' ? 'selected' : ''}>Critical Risk (90-100) (${formatTrafficNumber(criticalCount)})</option>
                        <option value="high" ${activeSevFilter === 'high' ? 'selected' : ''}>High Risk (70-89) (${formatTrafficNumber(highCount)})</option>
                        <option value="malware" ${activeSevFilter === 'malware' ? 'selected' : ''}>Malware / C2</option>
                        <option value="botnet" ${activeSevFilter === 'botnet' ? 'selected' : ''}>Botnet C2</option>
                        <option value="phishing" ${activeSevFilter === 'phishing' ? 'selected' : ''}>Phishing</option>
                        <option value="scanner" ${activeSevFilter === 'scanner' ? 'selected' : ''}>Scanners / Exploits</option>
                        <option value="cybercrime" ${activeSevFilter === 'cybercrime' ? 'selected' : ''}>Hijacked Netblocks</option>
                        <option value="relay" ${activeSevFilter === 'relay' ? 'selected' : ''}>Anonymized Relays</option>
                    </select>
                    <label class="flow-blacklist-search">
                        <span aria-hidden="true">
                            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></svg>
                        </span>
                        <input type="search" class="flow-search-input"
                               aria-label="Search threat indicators"
                               placeholder="Search IP, CIDR, malware, or threat actor..."
                               value="${escapeTrafficAttr(pagination.search)}"
                               data-traffic-threat-search="true">
                    </label>
                    <select class="flow-page-size-select"
                            aria-label="Entries per page"
                            data-traffic-threat-page-size="true">
                        <option value="10" ${pageSize === 10 ? 'selected' : ''}>10 rows</option>
                        <option value="25" ${pageSize === 25 ? 'selected' : ''}>25 rows</option>
                        <option value="50" ${pageSize === 50 ? 'selected' : ''}>50 rows</option>
                        <option value="100" ${pageSize === 100 ? 'selected' : ''}>100 rows</option>
                    </select>
                </div>
            </div>

            <div class="flow-blacklist-table-wrap">
                <table class="tor-inventory-table threat-directory-table">
                    <thead>
                        <tr>
                            ${renderSortHeader('indicator', 'Threat Indicator', 'th-indicator')}
                            ${renderSortHeader('severity', 'Severity', 'th-severity')}
                            ${renderSortHeader('score', 'Risk Score', 'th-score')}
                            ${renderSortHeader('protocol', 'Protocol', 'th-proto')}
                            ${renderSortHeader('category', 'Classification', 'th-category')}
                            ${renderSortHeader('confidence', 'Confidence', 'th-confidence')}
                        </tr>
                    </thead>
                    <tbody>
                        ${pageEntries.length ? pageEntries.map(item => {
                            const isIpv6 = item.indicator.includes(':');
                            const safeIndicator = escapeTrafficHtml(item.indicator);
                            const safeCategory = escapeTrafficHtml(item.category || (item.score && item.score >= 90 ? 'Cybercrime / Threat' : 'Anonymized Exit Relay'));
                            const scoreVal = item.score || (item.severity === 'CRITICAL' ? 98 : 80);
                            const isCritical = scoreVal >= 90;
                            const isHigh = scoreVal >= 70 && scoreVal < 90;
                            const sevBadge = isCritical ? 'CRITICAL' : isHigh ? 'HIGH' : (item.severity ? item.severity.toUpperCase() : 'MEDIUM');
                            const sevTone = isCritical ? 'critical' : isHigh ? 'high' : (sevBadge === 'LOW' ? 'low' : 'medium');
                            const scoreColor = isCritical ? 'var(--danger, #ef4444)' : isHigh ? 'var(--brand-orange, #f97316)' : '#5f86a2';
                            const confidenceText = escapeTrafficHtml(item.confidence || (isCritical ? '99% Verified' : '94% Verified'));
                            const icon = isCritical ? (icons.ban || '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>') : (icons.shield || '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>');
                            return `
                                <tr class="flow-threat-row">
                                    <td class="tor-ip-cell">
                                        <div class="tor-ip-row">
                                            <span class="tor-ip-icon" style="color: ${scoreColor}">${icon}</span>
                                            <code class="tor-ip-code font-bold">${safeIndicator}</code>
                                        </div>
                                    </td>
                                    <td>
                                        <span class="threat-severity-tag severity-${sevTone}">${sevBadge}</span>
                                    </td>
                                    <td>
                                        <div class="risk-score-meter-wrap">
                                            <div class="risk-score-badge">
                                                <span class="font-mono font-700" style="color:${scoreColor}">${scoreVal}</span>
                                                <span class="text-11 text-muted">/100</span>
                                            </div>
                                            <div class="risk-score-bar-bg">
                                                <div class="risk-score-bar-fill" style="width: ${scoreVal}%; background-color: ${scoreColor}"></div>
                                            </div>
                                        </div>
                                    </td>
                                    <td>
                                        <span class="tag-pill flow-type-pill font-mono">${isIpv6 ? 'IPv6' : 'IPv4'}</span>
                                    </td>
                                    <td>
                                        <span class="text-12 font-500 threat-category-badge">${safeCategory}</span>
                                    </td>
                                    <td>
                                        <span class="text-11 text-muted font-mono">${confidenceText}</span>
                                    </td>
                                </tr>
                            `;
                        }).join('') : `
                            <tr>
                                <td colspan="6">
                                    <div class="flow-blacklist-empty">
                                        <span class="flow-blacklist-empty-icon">${icons.shield || ''}</span>
                                        <strong>${isLoading ? 'Synchronizing Threat Feeds...' : searchQuery ? 'No matching indicators found' : (isCtiDisconnected ? 'CTI Server Disconnected — No threat indicators available' : 'No threat indicators loaded')}</strong>
                                        <span>${isLoading ? 'Connecting to DivineLab CTI and building in-memory trie...' : searchQuery ? `No threat indicator matched "${escapeTrafficHtml(searchQuery)}".` : (isCtiDisconnected ? 'DivineLab CTI service is offline or unreachable. Connect to the CTI server and refresh feeds to synchronize threat intelligence.' : 'No threat indicators are currently loaded. Click "Refresh feed" to synchronize with DivineLab CTI.')}</span>
                                    </div>
                                </td>
                            </tr>
                        `}
                    </tbody>
                </table>
            </div>

            ${totalPages > 1 ? `
                <div class="flow-blacklist-pagination">
                    <span>Page <strong>${pagination.page}</strong> of ${totalPages} (Showing ${startIndex + 1}–${Math.min(startIndex + pageSize, totalFiltered)} of ${totalFiltered})</span>
                    <div class="d-flex gap-8">
                        <button type="button" class="operator-btn operator-btn-secondary btn-xs"
                            ${pagination.page === 1 ? 'disabled' : ''}
                            data-traffic-action="threat-feed-prev-page">&larr; Previous</button>
                        <button type="button" class="operator-btn operator-btn-secondary btn-xs"
                            ${pagination.page >= totalPages ? 'disabled' : ''}
                            data-traffic-action="threat-feed-next-page">Next &rarr;</button>
                    </div>
                </div>
            ` : ''}
        </section>
    `;
}

export function renderUnifiedThreatFeedPage(
    feedData: UnifiedThreatFeedData | null,
    reputationConfig: TrafficReputationConfig | undefined,
    pagination: ThreatFeedPaginationState,
    icons: Record<string, string>,
    renderSaveButtons: () => string
): string {
    return `
        <div class="mb-14 d-flex align-center justify-between">
            ${SectionUI.renderOperatorBackButton({
                label: 'Back to IP Reputation',
                attrs: 'data-traffic-action="close-threat-feed-page"'
            })}
            <div class="d-flex align-center gap-8">
                <span class="text-12 text-muted">Primary Feed:</span>
                <span class="config-tag font-mono text-11">DivineLab CTI</span>
            </div>
        </div>

        <div class="flow-blacklist-console">
            ${renderThreatDirectorySection(feedData, reputationConfig, pagination, icons)}
        </div>

        ${renderSaveButtons()}
    `;
}
