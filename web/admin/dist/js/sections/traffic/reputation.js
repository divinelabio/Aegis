import { SectionUI } from '../ui-components.js';
import { renderUnifiedThreatFeedPage } from './threat-feed.js';
import { escapeTrafficAttr, escapeTrafficHtml, formatTrafficNumber } from '../traffic-runtime-helpers.js';
export function renderReputationTab(reputationConfig, renderStatusCard, icons, renderSaveButtons, threatFeedActive = false, feedData = null, pagination = { page: 1, pageSize: 25, search: '', sourceFilter: 'all' }) {
    if (threatFeedActive) {
        return renderUnifiedThreatFeedPage(feedData, reputationConfig, pagination, icons, renderSaveButtons);
    }
    const rep = reputationConfig || {};
    const isEnabled = rep.enabled !== false;
    const currentAction = rep.action || 'block';
    const sensitivityValue = Math.max(0, Math.min(100, Number(rep.sensitivity ?? 80)));
    const cacheTtlValue = rep.cache_ttl || '1h';
    const rules = rep.rules || [];
    const blockTor = rep.block_tor === true;
    const blockDatacenter = rep.block_datacenter === true;
    const ctiEnabled = rep.cti?.enabled !== false;
    const isStrictBlock = currentAction === 'block';
    const isSmartChallenge = currentAction === 'challenge' || currentAction === 'captcha' || currentAction === 'js';
    const actionLabel = isSmartChallenge ? 'challenged' : 'blocked';
    const totalCount = feedData?.total_indicators ?? (feedData?.indicators?.length || 0);
    const criticalCount = (feedData?.indicators || []).filter(i => (i.score || 0) >= 90 || i.severity === 'CRITICAL').length;
    const ctiSource = feedData?.sources?.cti || feedData?.cti;
    const ctiStatusObj = ctiSource?.status;
    const ctiError = ctiStatusObj?.last_error;
    const isCtiDisconnected = Boolean(!feedData || (ctiError && totalCount === 0) || ((ctiStatusObj?.failures ?? 0) > 0 && totalCount === 0));
    const isSynced = feedData?.status === 'ok' || totalCount > 0;
    return `
        ${renderStatusCard('IP Reputation Policy', 'Score client IP risk in real time against threat intelligence feeds.', 'database', 'reputation')}

        <div class="reputation-operator-stack">
            <!-- Metric Strip -->
            ${SectionUI.renderOperatorMetricStrip([
        {
            label: 'Threat Indicators',
            value: Number(totalCount).toLocaleString(),
            sub: isCtiDisconnected ? 'CTI offline' : (totalCount > 0 ? 'Live feeds' : 'No indicators synced'),
            tone: 'neutral'
        },
        {
            label: 'Critical Risk',
            value: Number(criticalCount).toLocaleString(),
            sub: 'Score 90–100',
            tone: 'neutral'
        },
        {
            label: 'Engine Status',
            value: isEnabled ? 'Operational' : 'Disabled',
            sub: isEnabled ? 'Active edge mitigation' : 'Bypass mode',
            tone: isEnabled ? 'active' : 'neutral'
        },
        {
            label: 'DivineLab CTI Status',
            value: isCtiDisconnected ? 'Disconnected' : (isSynced ? 'Connected' : 'Standby'),
            sub: isCtiDisconnected ? 'Connection refused / offline' : 'Real-time sync',
            tone: isCtiDisconnected ? 'danger' : 'neutral'
        }
    ], 'reputation-metric-strip mb-20')}

            <!-- Section 1: Protection Policies & Controls -->
            ${SectionUI.renderOperatorSection('Protection Policies & Controls', `
                <div class="reputation-control-list operator-control-list">
                    ${SectionUI.renderOperatorControlRow({
        title: 'Tor Exit Node Blocking',
        description: 'Automatically identify and block incoming requests routed through Tor anonymity relays and exit nodes.',
        icon: icons.slash || '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>',
        enabled: blockTor,
        actions: `
                            <label class="section-switch">
                                <input type="checkbox" ${blockTor ? 'checked' : ''} data-traffic-parent="reputation" data-traffic-field="block_tor" data-traffic-value-type="checkbox" aria-label="Toggle Tor Exit Node Blocking">
                                <span class="switch-slider"></span>
                            </label>
                        `
    })}
                    ${SectionUI.renderOperatorControlRow({
        title: 'Datacenter Traffic Filtering',
        description: 'Inspect and challenge requests originating from commercial hosting providers, cloud compute, and proxy farms.',
        icon: icons.server || '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>',
        enabled: blockDatacenter,
        actions: `
                            <label class="section-switch">
                                <input type="checkbox" ${blockDatacenter ? 'checked' : ''} data-traffic-parent="reputation" data-traffic-field="block_datacenter" data-traffic-value-type="checkbox" aria-label="Toggle Datacenter Traffic Filtering">
                                <span class="switch-slider"></span>
                            </label>
                        `
    })}
                    ${SectionUI.renderOperatorControlRow({
        title: 'DivineLab CTI Threat Intelligence Sync',
        description: 'Continuously ingest high-confidence threat intelligence feeds and zero-day indicators into edge memory.',
        icon: icons.database || '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>',
        enabled: ctiEnabled,
        actions: `
                            <label class="section-switch">
                                <input type="checkbox" ${ctiEnabled ? 'checked' : ''} data-traffic-parent="reputation" data-traffic-field="cti.enabled" data-traffic-value-type="checkbox" aria-label="Toggle DivineLab CTI Threat Intelligence Sync">
                                <span class="switch-slider"></span>
                            </label>
                        `
    })}
                </div>
            `, {
        subtitle: 'Granular threat categories and autonomous engine enforcement policies.',
        className: 'mb-20'
    })}

            <!-- Section 2: Decision Policy -->
            ${SectionUI.renderOperatorSection('Decision Policy', `
                <div class="reputation-decision-grid">
                    <div class="reputation-card reputation-threshold-card">
                        <div class="reputation-control-head">
                            <div>
                                <span class="reputation-control-label">
                                    Minimum Trust Score
                                    ${SectionUI.renderInfoTooltip('Requests with a trust score below this value trigger the selected edge mitigation action.')}
                                </span>
                            </div>
                            <div class="reputation-score-box">
                                <strong id="reputation-sensitivity-display">${sensitivityValue}</strong>
                                <span>/100</span>
                            </div>
                        </div>

                        <div class="flow-reputation-scale" aria-hidden="true">
                            <span>High Risk (&lt; 50)</span>
                            <span>Review (50–79)</span>
                            <span>Trusted (&ge; 80)</span>
                        </div>
                        <div class="flow-reputation-track">
                            <span id="reputation-threshold-fill" class="flow-reputation-track-fill" style="width:${sensitivityValue}%"></span>
                            <span id="reputation-threshold-marker" class="flow-reputation-track-marker" style="left:${sensitivityValue}%"></span>
                        </div>
                        <input type="range" min="0" max="100" step="5" value="${sensitivityValue}"
                                class="flow-reputation-range"
                                aria-label="Minimum IP trust score"
                                data-traffic-parent="reputation"
                                data-traffic-field="sensitivity"
                                data-traffic-value-type="number"
                                data-traffic-sync-target="reputation-sensitivity-display"
                                data-traffic-sensitivity-display="true">
                        <div class="flow-reputation-scale-values" aria-hidden="true">
                            <span>0</span><span>50</span><span>100</span>
                        </div>
                        <div id="reputation-sensitivity-text" class="flow-reputation-decision-note mt-12">
                            Requests scoring below <strong>${sensitivityValue}</strong> will be <strong>${actionLabel}</strong> at the edge.
                        </div>

                        <div class="mt-20 pt-16" style="border-top: 1px solid var(--border, rgba(255, 255, 255, 0.08));">
                            <label class="reputation-control-label mb-8" for="reputation-cache-ttl">
                                Cache Expiration TTL
                                ${SectionUI.renderInfoTooltip('Duration to retain reputation scoring results in edge cache before re-evaluating.')}
                            </label>
                            <input id="reputation-cache-ttl" type="text" class="section-input"
                                   value="${escapeTrafficAttr(cacheTtlValue)}"
                                   placeholder="1h"
                                   data-traffic-parent="reputation"
                                   data-traffic-field="cache_ttl"
                                   aria-label="Cache Expiration TTL">
                            <span class="text-11 text-muted mt-4 d-block">Valid Go duration string (e.g. 15m, 1h, 24h). Default is 1h.</span>
                        </div>
                    </div>

                    <div class="reputation-card reputation-actions-card" role="radiogroup" aria-label="Low trust response">
                        <button type="button" class="flow-reputation-action ${isStrictBlock ? 'is-active' : ''}"
                            data-traffic-action="set-nested-field"
                            data-traffic-parent="reputation"
                            data-traffic-field="action"
                            data-traffic-value="block"
                            data-traffic-render="true"
                            role="radio"
                            aria-checked="${isStrictBlock}">
                            <span class="flow-reputation-action-icon">${icons.ban || '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>'}</span>
                            <span class="flow-reputation-action-copy">
                                <strong>Strict Edge Block</strong>
                                <small>Reject low-trust and malicious requests immediately with HTTP 403 or TCP reset.</small>
                            </span>
                            <span class="flow-reputation-action-check" aria-hidden="true"></span>
                        </button>

                        <button type="button" class="flow-reputation-action ${isSmartChallenge ? 'is-active' : ''}"
                            data-traffic-action="set-nested-field"
                            data-traffic-parent="reputation"
                            data-traffic-field="action"
                            data-traffic-value="challenge"
                            data-traffic-render="true"
                            role="radio"
                            aria-checked="${isSmartChallenge}">
                            <span class="flow-reputation-action-icon">${icons.shield || '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>'}</span>
                            <span class="flow-reputation-action-copy">
                                <strong>Smart Challenge</strong>
                                <small>Present a cryptographic Proof-of-Work challenge to verify legitimate human browsers.</small>
                            </span>
                            <span class="flow-reputation-action-check" aria-hidden="true"></span>
                        </button>
                    </div>
                </div>
            `, {
        subtitle: 'Configure the minimum acceptable trust score and edge mitigation response for suspicious clients.',
        className: 'mb-20'
    })}

            <!-- Section 3: Policy Exceptions & Custom IP Overrides -->
            ${SectionUI.renderOperatorSection('Policy Exceptions & Custom IP Overrides', `
                <div class="reputation-card reputation-table-card">
                    <table class="flow-reputation-rules-table" aria-label="Reputation override rules">
                        <thead>
                            <tr>
                                <th class="th-rule-target">IP / CIDR Block</th>
                                <th class="th-rule-action">Action Override</th>
                                <th class="th-rule-score">Trust Score</th>
                                <th class="th-rule-desc">Description</th>
                                <th class="th-rule-actions text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${rules.length ? rules.map(r => `
                                <tr>
                                    <td><span class="font-mono font-600 text-13">${escapeTrafficHtml(r.ip_or_cidr)}</span></td>
                                    <td><span class="flow-reputation-action-badge action-${escapeTrafficAttr((r.action || 'allow').toLowerCase())}">${escapeTrafficHtml((r.action || 'allow').toUpperCase())}</span></td>
                                    <td><span class="font-mono text-13">${r.score ?? '—'}</span></td>
                                    <td class="text-secondary text-13">${escapeTrafficHtml(r.comment || '—')}</td>
                                    <td class="text-right">
                                        <button type="button" class="btn-delete-rule" data-traffic-action="delete-reputation-rule" data-traffic-value="${escapeTrafficAttr(r.id)}">Delete</button>
                                    </td>
                                </tr>
                            `).join('') : `
                                <tr>
                                    <td colspan="5" class="text-center text-muted p-24">
                                        No custom IP score overrides configured. Add a rule to explicitly whitelist partner subnets or block known hostile CIDRs.
                                    </td>
                                </tr>
                            `}
                        </tbody>
                    </table>
                </div>
            `, {
        subtitle: 'Define granular bypass or strict blocking rules for specific IP addresses or subnets.',
        actions: `
                    <button type="button" class="operator-btn operator-btn-primary btn-sm" data-traffic-action="open-add-reputation-rule">
                        <span aria-hidden="true">+</span> Add Override Rule
                    </button>
                `,
        className: 'mb-20'
    })}

            <!-- Section 4: Threat Intelligence Feed Source & Module Link -->
            ${SectionUI.renderOperatorSection('DivineLab CTI Intelligence Feed', `
                <div class="reputation-control-list operator-control-list">
                    ${SectionUI.renderOperatorControlRow({
        title: 'DivineLab CTI Threat Intelligence Directory',
        description: 'Real-time threat feeds and IP indicators are collected and synchronized by the IP Reputation Module.',
        icon: icons.database || '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>',
        enabled: isSynced,
        actions: `
                            <button class="operator-btn operator-btn-primary btn-sm" type="button" data-traffic-action="open-reputation-module">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="mr-6"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                                View in IP Reputation Module (${formatTrafficNumber(totalCount)}) &rarr;
                            </button>
                        `,
        className: 'flow-provider-row'
    })}
                </div>
            `, {
        subtitle: 'Real-time threat feeds and IP indicators are collected and synchronized by the IP Reputation Module.',
        className: 'mb-20'
    })}
        </div>

        ${renderSaveButtons()}
    `;
}
