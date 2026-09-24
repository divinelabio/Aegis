/**
 * Traffic Control - Application Flood / DDoS Protection
 * HTTP flood thresholds, in-flight connection ceilings, browser verification challenges, and protected objects.
 */
import { encodeTrafficValue, escapeTrafficAttr, escapeTrafficHtml, formatTrafficNumber } from '../traffic-runtime-helpers.js';
import { SectionUI } from '../ui-components.js';
import { TrafficDDoSConfig } from './types.js';

export function renderDDoSTab(
    ddosConfig: TrafficDDoSConfig | undefined,
    _challengeConfig: { enabled?: boolean; mode?: string } | undefined,
    renderStatusCard: (title: string, desc: string, icon: string, key: string) => string,
    icons: Record<string, string>,
    renderSaveButtons: () => string
): string {
    const cfg: Record<string, any> = ddosConfig || {};
    const action = cfg.action || 'challenge';
    const maxRps = cfg.max_rps ?? cfg.maxrps ?? 100;
    const maxConnections = cfg.max_connections ?? cfg.maxconnections ?? 50;
    const burstMultiplier = cfg.burst_multiplier ?? cfg.burstmultiplier ?? 2.0;
    const autoBan = cfg.auto_ban ?? cfg.autoban ?? false;
    const banDuration = cfg.ban_duration ?? cfg.banduration ?? 60;
    const objects: any[] = cfg.objects || [];

    return `
        ${renderStatusCard('Application Flood Protection', 'Detect and mitigate HTTP request floods and high in-flight load.', 'shield', 'ddos')}

        <div class="flow-ddos-console">
            <!-- Section 1: Default Flood Limits & Thresholds -->
            <section class="flow-ddos-section">
                <div class="flow-ddos-section-head">
                    <div>
                        <div class="flow-rate-eyebrow">Thresholds</div>
                        <h3>Default flood limits</h3>
                        <p>Baseline request rate and concurrent load ceilings applied to unmatched endpoints before taking mitigation action.</p>
                    </div>
                </div>

                <div class="flow-ddos-threshold-grid">
                    <div class="flow-ddos-threshold">
                        <div class="flow-ddos-control-head">
                            <div>
                                <strong style="font-size: 12px; font-weight: 700; display: inline-flex; align-items: center;">
                                    HTTP flood threshold
                                    ${SectionUI.renderInfoTooltip('Maximum requests per second allowed from a single client IP.')}
                                </strong>
                            </div>
                            <div class="flow-ddos-value">
                                <input type="number" id="ddos-max-rps-input" value="${maxRps}" min="10" max="5000" step="10"
                                    data-traffic-parent="application_flood" data-traffic-field="max_rps" data-traffic-value-type="number"
                                    data-traffic-sync-target="ddos-max-rps-range" aria-label="HTTP flood threshold in requests per second">
                                <span>req/s</span>
                            </div>
                        </div>
                        <input type="range" id="ddos-max-rps-range" class="flow-ddos-range" value="${maxRps}" min="10" max="5000" step="10"
                            data-traffic-parent="application_flood" data-traffic-field="max_rps" data-traffic-value-type="number"
                            data-traffic-sync-target="ddos-max-rps-input" aria-label="HTTP flood threshold slider">
                        <div class="flow-ddos-range-scale" aria-hidden="true">
                            <span>10 req/s</span><span>1,000</span><span>2,500</span><span>5,000 req/s</span>
                        </div>
                    </div>

                    <div class="flow-ddos-threshold">
                        <div class="flow-ddos-control-head">
                            <div>
                                <strong style="font-size: 12px; font-weight: 700; display: inline-flex; align-items: center;">
                                    In-flight connection ceiling
                                    ${SectionUI.renderInfoTooltip('Maximum simultaneous concurrent HTTP requests allowed from a single client IP.')}
                                </strong>
                            </div>
                            <div class="flow-ddos-value">
                                <input type="number" id="ddos-max-conn-input" value="${maxConnections}" min="5" max="1000" step="5"
                                    data-traffic-parent="application_flood" data-traffic-field="max_connections" data-traffic-value-type="number"
                                    data-traffic-sync-target="ddos-max-conn-range" aria-label="In-flight connection ceiling">
                                <span>in-flight</span>
                            </div>
                        </div>
                        <input type="range" id="ddos-max-conn-range" class="flow-ddos-range" value="${maxConnections}" min="5" max="1000" step="5"
                            data-traffic-parent="application_flood" data-traffic-field="max_connections" data-traffic-value-type="number"
                            data-traffic-sync-target="ddos-max-conn-input" aria-label="In-flight connection ceiling slider">
                        <div class="flow-ddos-range-scale" aria-hidden="true">
                            <span>5 in-flight</span><span>250</span><span>500</span><span>1,000 in-flight</span>
                        </div>
                    </div>
                </div>

                <div class="flow-ddos-default-tuning">
                    <label class="flow-ddos-field">
                        <strong style="font-size: 12px; font-weight: 700; display: inline-flex; align-items: center;">
                            Burst capacity multiplier
                            ${SectionUI.renderInfoTooltip('Spike headroom factor above the base rate threshold before rate-limiting activates.')}
                        </strong>
                        <div>
                            <input type="number" value="${burstMultiplier}" min="1" max="10" step="0.1"
                                data-traffic-parent="application_flood" data-traffic-field="burst_multiplier" data-traffic-value-type="float"
                                aria-label="Burst capacity multiplier">
                            <b>&times; rate</b>
                        </div>
                    </label>

                    <div class="flow-ddos-field">
                        <div style="display: flex; align-items: center; justify-content: space-between; width: 100%; border: none; background: transparent; padding: 0;">
                            <div>
                                <strong style="font-size: 12px; font-weight: 700; display: inline-flex; align-items: center;">
                                    Temporarily ban limit breaches
                                    ${SectionUI.renderInfoTooltip('Block offending client IPs after exceeding rate or in-flight limits.')}
                                </strong>
                            </div>
                            <label class="section-switch">
                                <input type="checkbox" aria-label="Temporarily ban limit breaches" ${autoBan ? 'checked' : ''}
                                    data-traffic-parent="application_flood" data-traffic-field="auto_ban"
                                    data-traffic-value-type="checkbox" data-traffic-render="true">
                                <span class="switch-slider"></span>
                            </label>
                        </div>
                        ${autoBan ? `
                            <div style="margin-top: 8px;">
                                <input type="number" value="${banDuration}" min="1" max="1440" step="1"
                                    data-traffic-parent="application_flood" data-traffic-field="ban_duration" data-traffic-value-type="number"
                                    aria-label="Ban duration in minutes">
                                <b>minutes</b>
                            </div>
                        ` : ''}
                    </div>
                </div>
            </section>

            <!-- Section 2: Response Strategy -->
            <section class="flow-ddos-section">
                <div class="flow-ddos-section-head">
                    <div>
                        <div class="flow-rate-eyebrow">Response strategy</div>
                        <h3>Default mitigation action</h3>
                        <p>Choose how unmatched requests are handled when request rate or in-flight connection limits are breached.</p>
                    </div>
                </div>
                <div class="flow-ddos-response-grid">
                    <div class="flow-ddos-actions" role="radiogroup" aria-label="Primary DDoS mitigation">
                        ${([
                            { value: 'challenge', title: 'Browser challenge', desc: 'Verify likely browsers before allowing traffic.', icon: icons.shield || '' },
                            { value: 'block', title: 'Immediate block', desc: 'Reject abusive requests with a forbidden response.', icon: icons.ban || '' },
                            { value: 'http_reject', title: 'HTTP service rejection', desc: 'Return an explicit temporary-unavailable response. No TCP drop is attempted.', icon: icons.zap || '' }
                        ] as const).map(option => `
                            <button type="button" class="flow-ddos-action ${action === option.value ? 'is-active' : ''}"
                                data-traffic-action="set-nested-field" data-traffic-parent="application_flood"
                                data-traffic-field="action" data-traffic-value="${option.value}" data-traffic-render="true"
                                role="radio" aria-checked="${action === option.value}">
                                <span class="flow-ddos-action-icon">${option.icon}</span>
                                <span><strong>${option.title}</strong><small>${option.desc}</small></span>
                                <i aria-hidden="true"></i>
                            </button>
                        `).join('')}
                    </div>
                </div>
            </section>

            <section class="flow-ddos-section">
                <div class="flow-ddos-section-head">
                    <div>
                        <div class="flow-rate-eyebrow">Scoped enforcement</div>
                        <h3 style="display: inline-flex; align-items: center;">
                            Protected HTTP objects
                            ${SectionUI.renderInfoTooltip('Named objects replace the default limits and response when their host, method, and path match. Unmatched requests retain the default policy.')}
                        </h3>
                    </div>
                    <button class="operator-btn operator-btn-primary" type="button" data-traffic-action="open-add-flood-object"><span aria-hidden="true">+</span> Add object</button>
                </div>
                <div class="flow-priority-list">
                    ${objects.length ? objects.map(object => `
                        <div class="flow-priority-row">
                            <div class="flow-priority-source"><span class="flow-priority-source-icon">${icons.shield || ''}</span><span class="flow-priority-source-copy"><strong>${escapeTrafficHtml(object.id)}</strong><small>${escapeTrafficHtml(`${(object.methods || ['ANY']).join(', ')} ${object.path_match || 'prefix'} ${object.path || '/'}`)}</small></span></div>
                            <span class="flow-priority-type">${formatTrafficNumber(object.max_rps || 100)} req/s</span>
                            <span class="flow-priority-state"><i></i>${formatTrafficNumber(object.max_concurrency || 50)} in-flight</span>
                            <button class="flow-priority-remove" type="button" data-traffic-action="remove-flood-object" data-traffic-value="${encodeTrafficValue(object.id)}" aria-label="Remove protected object ${escapeTrafficAttr(object.id)}">Remove</button>
                        </div>`).join('') : `<div class="flow-priority-empty"><span class="flow-priority-empty-icon">${icons.shield || ''}</span><strong>Default policy applies to all requests</strong><span>Add a protected object only when an endpoint needs stricter limits than the default.</span></div>`}
                </div>
            </section>
        </div>

        ${renderSaveButtons()}
    `;
}
