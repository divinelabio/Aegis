/**
 * Traffic Control - IP Blacklist (Community)
 * IP/CIDR blocking, duration rules, bulk operations, and inventory management.
 */
import { buildTrafficBlacklistPageData, encodeTrafficValue, escapeTrafficAttr, escapeTrafficHtml } from '../traffic-runtime-helpers.js';
export function renderBlacklistTab(config, pagination, selectedTargets, renderStatusCard, icons, renderSaveButtons) {
    const pageData = buildTrafficBlacklistPageData(config, pagination.search, pagination.page, pagination.pageSize);
    const searchQuery = pagination.search.trim().toLowerCase();
    const totalCount = pageData.totalCount;
    const filteredCount = pageData.filteredCount;
    const totalPages = pageData.totalPages;
    pagination.page = pageData.page;
    const pageSize = pagination.pageSize;
    const pageEntries = pageData.pageEntries;
    const selectedCount = selectedTargets.size;
    const now = new Date();
    const allPageSelected = pageEntries.length > 0 && pageEntries.every(e => selectedTargets.has(e.target));
    return `
        <input id="traffic-blacklist-import" type="file" accept=".csv,text/csv" class="hidden" data-traffic-blacklist-import>

        ${renderStatusCard('IP Blacklist', 'Manage blocked IP addresses and CIDR ranges. Traffic is dropped at the edge.', 'ban', 'blacklist')}

        <div class="flow-blacklist-console">
            <section class="flow-blacklist-inventory">
                <div class="flow-blacklist-head">
                    <div>
                        <div class="flow-rate-eyebrow">Block inventory</div>
                        <h3>Blocked targets</h3>
                        <p>Review, search, and maintain the IP addresses and network ranges denied at the edge.</p>
                    </div>
                    <div class="flow-blacklist-head-actions">
                        <button class="operator-btn operator-btn-secondary" type="button" data-traffic-action="open-import-blacklist-csv">
                            <span aria-hidden="true">↓</span> Import CSV
                        </button>
                        <button class="operator-btn operator-btn-primary" type="button" data-traffic-action="open-add-ip-modal">
                            <span aria-hidden="true">+</span> Add entry
                        </button>
                    </div>
                </div>

                ${selectedCount > 0 ? `
                    <div class="flow-blacklist-selection" role="status">
                        <span><strong>${selectedCount}</strong> ${selectedCount === 1 ? 'target' : 'targets'} selected</span>
                        <div>
                            <button class="operator-btn operator-btn-secondary btn-xs" type="button"
                                data-traffic-action="clear-blacklist-selection">Clear selection</button>
                            <button class="operator-btn operator-btn-danger btn-xs" type="button"
                                data-traffic-action="delete-selected-blacklist">Delete selected</button>
                        </div>
                    </div>
                ` : ''}

                <div class="flow-blacklist-toolbar">
                    <div class="flow-blacklist-count">
                        <strong>${searchQuery ? filteredCount : totalCount}</strong>
                        <span>${searchQuery ? `matching ${filteredCount === 1 ? 'entry' : 'entries'} of ${totalCount}` : totalCount === 1 ? 'entry' : 'entries'}</span>
                    </div>
                    <div class="flow-blacklist-tools">
                        <label class="flow-blacklist-search">
                            <span aria-hidden="true">
                                <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></svg>
                            </span>
                            <input type="search" class="flow-search-input"
                                aria-label="Search blocked targets"
                                placeholder="Search IP or CIDR"
                                value="${escapeTrafficAttr(pagination.search)}"
                                data-traffic-pagination-search="true">
                        </label>
                        <select class="flow-page-size-select"
                                aria-label="Entries per page"
                                data-traffic-parent="blacklistPagination" data-traffic-field="pageSize" data-traffic-value-type="number">
                            <option value="10" ${pageSize === 10 ? 'selected' : ''}>10 rows</option>
                            <option value="25" ${pageSize === 25 ? 'selected' : ''}>25 rows</option>
                            <option value="100" ${pageSize === 100 ? 'selected' : ''}>100 rows</option>
                        </select>
                    </div>
                </div>

                <div class="flow-blacklist-table-wrap">
                    <table class="flow-blacklist-table">
                        <thead>
                            <tr>
                                <th class="flow-check-cell">
                                    <input type="checkbox" ${allPageSelected ? 'checked' : ''}
                                        data-traffic-blacklist-select-all="true" title="Select all on page"
                                        aria-label="Select all visible targets">
                                </th>
                                <th>Target</th>
                                <th>Type</th>
                                <th>Expiration</th>
                                <th class="flow-blacklist-actions-head">Actions</th>
                            </tr>
                        </thead>
                        <tbody id="blacklist-table-body">
                            ${pageEntries.length ? pageEntries.map((entry) => {
        const isCidr = entry.target.includes('/');
        const expiresAt = entry.expires_at ? new Date(entry.expires_at) : null;
        const isExpired = Boolean(expiresAt && expiresAt < now);
        const expiresLabel = expiresAt
            ? expiresAt.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
            : 'Permanent';
        const isSelected = selectedTargets.has(entry.target);
        const safeTarget = escapeTrafficHtml(entry.target);
        return `
                                <tr class="section-blacklist-row ${isExpired ? 'is-expired' : ''} ${isSelected ? 'is-selected' : ''}">
                                    <td class="flow-check-cell">
                                        <input type="checkbox" ${isSelected ? 'checked' : ''}
                                            data-traffic-blacklist-select="${encodeTrafficValue(entry.target)}"
                                            aria-label="Select ${escapeTrafficAttr(entry.target)}">
                                    </td>
                                    <td>
                                        <div class="flow-target-cell">
                                            <span class="flow-target-icon ${isExpired ? 'is-muted' : ''}">${icons.ban || ''}</span>
                                            <div class="flow-target-copy">
                                                <span class="flow-target-value">${safeTarget}</span>
                                                <small>${isCidr ? 'Network range' : 'Single address'}</small>
                                            </div>
                                        </div>
                                    </td>
                                    <td>
                                        <span class="tag-pill flow-type-pill">
                                            ${isCidr ? 'CIDR' : 'IP'}
                                        </span>
                                    </td>
                                    <td>
                                        <span class="flow-expiry-pill ${isExpired ? 'is-expired' : ''}">
                                            ${isExpired ? 'EXPIRED' : expiresLabel}
                                        </span>
                                    </td>
                                    <td class="flow-blacklist-actions">
                                        <div class="flow-blacklist-row-actions">
                                            <button class="flow-blacklist-row-action" type="button"
                                                data-traffic-action="open-add-ip-modal"
                                                data-traffic-value="${encodeTrafficValue(entry.target)}">Edit</button>
                                            <button class="flow-blacklist-row-action is-danger" type="button"
                                                data-traffic-action="remove-ip"
                                                data-traffic-value="${encodeTrafficValue(entry.target)}">Delete</button>
                                        </div>
                                    </td>
                                </tr>`;
    }).join('') : `
                                <tr>
                                    <td colspan="5">
                                        <div class="flow-blacklist-empty">
                                            <span class="flow-blacklist-empty-icon">
                                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                                <circle cx="12" cy="12" r="10"/>
                                                <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
                                                </svg>
                                            </span>
                                            <strong>${searchQuery ? 'No matching targets' : 'No blocks active'}</strong>
                                            <span>${searchQuery ? 'Try a different IP address or network range.' : 'Add an IP address or CIDR range to deny traffic at the edge.'}</span>
                                            ${searchQuery ? '' : `
                                                <button class="operator-btn operator-btn-primary" type="button" data-traffic-action="open-add-ip-modal">
                                                    <span aria-hidden="true">+</span> Add first entry
                                                </button>
                                            `}
                                        </div>
                                    </td>
                                </tr>`}
                        </tbody>
                    </table>
                </div>

                ${totalPages > 1 ? `
                    <div class="flow-blacklist-pagination">
                        <span>Page <strong>${pagination.page}</strong> of ${totalPages}</span>
                        <div>
                            <button type="button" class="operator-btn operator-btn-secondary btn-xs"
                                ${pagination.page === 1 ? 'disabled' : ''}
                                data-traffic-action="blacklist-prev-page">&larr; Previous</button>
                            <button type="button" class="operator-btn operator-btn-secondary btn-xs"
                                ${pagination.page >= totalPages ? 'disabled' : ''}
                                data-traffic-action="blacklist-next-page">Next &rarr;</button>
                        </div>
                    </div>
                ` : ''}
            </section>
        </div>
        
        ${renderSaveButtons()}
    `;
}
