/**
 * Traffic Control - Trusted Traffic Exceptions / QoS Priority
 * Scoped bypass rules for Rate Limiting and Application Flood, and bandwidth prioritization.
 */
import { encodeTrafficValue, escapeTrafficAttr, escapeTrafficHtml } from '../traffic-runtime-helpers.js';
export function renderPriorityTab(trustedExceptions, renderSectionHeader, icons, renderSaveButtons) {
    const exceptions = trustedExceptions || [];
    return `
        ${renderSectionHeader('star', 'Trusted Traffic Exceptions', 'Manage sources that bypass Application Flood Protection and Rate Limiting.')}

        <div class="flow-priority-console">
            <section class="flow-priority-inventory">
                <div class="flow-priority-head">
                    <div>
                        <div class="flow-rate-eyebrow">Least-privilege exceptions</div>
                        <h3>Trusted traffic exceptions</h3>
                        <p>${exceptions.length ? `${exceptions.length} scoped ${exceptions.length === 1 ? 'exception is' : 'exceptions are'} active.` : 'Add a source with a deliberately limited flood and rate scope.'}</p>
                    </div>
                    <button class="operator-btn operator-btn-primary" type="button" data-traffic-action="open-add-vip-modal">
                        <span aria-hidden="true">+</span> Add trusted source
                    </button>
                </div>

                <div class="flow-priority-list">
                    ${exceptions.length ? exceptions.map((exception) => {
        const targets = exception.targets || [];
        const target = targets.join(', ');
        const isCidr = targets.some((value) => value.includes('/'));
        const controls = (exception.controls || []).join(', ');
        return `
                        <div class="flow-priority-row">
                            <div class="flow-priority-source">
                                <span class="flow-priority-source-icon">${icons.check || ''}</span>
                                <span class="flow-priority-source-copy">
                                    <strong>${escapeTrafficHtml(target)}</strong>
                                    <small>${escapeTrafficHtml(controls || 'no scope')}</small>
                                </span>
                            </div>
                            <span class="flow-priority-type">${isCidr ? 'CIDR' : 'IP'}</span>
                            <span class="flow-priority-state"><i></i>Scoped active</span>
                            <button class="flow-priority-remove" type="button"
                                data-traffic-action="remove-vip"
                                data-traffic-value="${encodeTrafficValue(exception.id)}"
                                aria-label="Remove trusted exception ${escapeTrafficAttr(exception.id)}">Remove</button>
                        </div>
                        `;
    }).join('') : `
                        <div class="flow-priority-empty">
                            <span class="flow-priority-empty-icon">${icons.star || ''}</span>
                            <strong>No trusted exceptions configured</strong>
                            <span>All clients follow the standard policy. Blacklist is never bypassable.</span>
                            <button class="operator-btn operator-btn-primary" type="button" data-traffic-action="open-add-vip-modal">
                                <span aria-hidden="true">+</span> Add first source
                            </button>
                        </div>
                    `}
                </div>
            </section>
        </div>

        ${renderSaveButtons()}
    `;
}
