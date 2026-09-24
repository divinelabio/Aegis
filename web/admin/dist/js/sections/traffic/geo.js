/**
 * Traffic Control - Geo-Blocking
 * Country/region based access control, interactive world map integration, and continent grouping.
 */
import { encodeTrafficValue, escapeTrafficAttr, escapeTrafficHtml, trafficCountryFlag } from '../traffic-runtime-helpers.js';
export function renderGeoTab(geoConfig, countriesMap, regionsMap, getGeoPolicyCountries, getGeoPolicyGroups, renderStatusCard, icons, renderSaveButtons, initGeoMap) {
    const cfg = geoConfig || {};
    const isBlock = (cfg.allow_countries || []).length === 0 && (cfg.mode || 'blocklist') === 'blocklist';
    const selectedCountries = getGeoPolicyCountries(cfg);
    const selectedGroups = getGeoPolicyGroups(cfg);
    const totalActive = selectedCountries.length + selectedGroups.length;
    // Initialize once the freshly rendered panel has measurable dimensions.
    if (typeof initGeoMap === 'function') {
        requestAnimationFrame(() => requestAnimationFrame(() => void initGeoMap()));
    }
    return `
        ${renderStatusCard('Geographic Access Control', 'Restrict traffic by country code or region.', 'globe', 'geo')}
        <div class="flow-operator-layout flow-geo-layout">
            <div class="operator-map-panel geo-map-panel" aria-label="Interactive geographic policy map">
                <div id="jvm-map" class="map-frame geo-map-canvas"></div>
                <div id="geo-map-state" class="geo-map-state" role="status">
                    <span class="geo-map-spinner" aria-hidden="true"></span>
                    <span>Loading world map…</span>
                </div>
                <div class="geo-map-legend">
                    <span class="geo-map-legend-swatch ${isBlock ? 'is-block' : 'is-allow'}"></span>
                    <span>Highlighted zones are ${isBlock ? 'blocked' : 'allowed'}</span>
                </div>
            </div>

            <div class="flow-operator-side">
                <section class="geo-console-panel geo-policy-panel">
                    <div class="geo-console-head">
                        <div>
                            <div class="flow-rate-eyebrow">Enforcement</div>
                            <h3>Geographic policy</h3>
                            <p>Choose how the selected countries and regions are handled.</p>
                        </div>
                    </div>
                    <div class="geo-fencing-state">
                        <div class="operator-choice-grid">
                            <button class="operator-choice-card ${isBlock ? 'is-active is-block' : ''}"
                                type="button" data-traffic-action="set-geo-mode" data-traffic-value="blocklist"
                                aria-pressed="${isBlock}">
                                <span class="geo-mode-card-head">
                                    <span class="section-geo-mode-icon">${icons.ban || ''}</span>
                                    <span class="section-geo-mode-title">Block selected</span>
                                </span>
                            </button>
                            <button class="operator-choice-card ${!isBlock ? 'is-active is-allow' : ''}"
                                type="button" data-traffic-action="set-geo-mode" data-traffic-value="allowlist"
                                aria-pressed="${!isBlock}">
                                <span class="geo-mode-card-head">
                                    <span class="section-geo-mode-icon">${icons.check || ''}</span>
                                    <span class="section-geo-mode-title">Allow selected only</span>
                                </span>
                            </button>
                        </div>
                    </div>
                </section>

                <section class="geo-console-panel geo-zones-panel">
                    <div class="geo-console-head geo-zones-head">
                        <div>
                            <div class="flow-rate-eyebrow">Scope</div>
                            <h3>Selected zones</h3>
                            <p>${totalActive === 0 ? 'No geographic scope configured.' : `${totalActive} ${totalActive === 1 ? 'zone' : 'zones'} currently selected.`}</p>
                        </div>
                        <button class="operator-btn operator-btn-secondary btn-outline btn-xs" type="button" data-traffic-action="open-geo-modal">
                            <span aria-hidden="true">+</span> Manage zones
                        </button>
                    </div>
                    <div class="geo-zones-table">
                        <div class="geo-zones-table-head">
                            <span>Zone</span>
                            <span>Type</span>
                            <span class="sr-only">Actions</span>
                        </div>
                        <div class="section-selection-list">
                            ${(totalActive > 0) ? `
                                ${selectedGroups.map(code => `
                                    <div class="section-selection-row section-selection-row-region">
                                        <div class="geo-zone-identity">
                                            <span class="code-chip font-700">${escapeTrafficHtml(code)}</span>
                                            <span class="text-13 font-600">${escapeTrafficHtml(regionsMap[code] || code)}</span>
                                        </div>
                                        <span class="geo-zone-type">Region</span>
                                        <button class="geo-zone-remove" type="button" aria-label="Remove ${escapeTrafficAttr(regionsMap[code] || code)}"
                                            data-traffic-action="remove-region" data-traffic-value="${encodeTrafficValue(code)}">&times;</button>
                                    </div>
                                `).join('')}
                                ${selectedCountries.map(code => `
                                    <div class="section-selection-row">
                                        <div class="geo-zone-identity">
                                            <span class="country-flag" role="img" aria-label="${escapeTrafficAttr(countriesMap[code] || code)} flag" title="${escapeTrafficAttr(code)}">${trafficCountryFlag(code)}</span>
                                            <span class="text-13">${escapeTrafficHtml(countriesMap[code] || code)}</span>
                                        </div>
                                        <span class="geo-zone-type">Country</span>
                                        <button class="geo-zone-remove" type="button" aria-label="Remove ${escapeTrafficAttr(countriesMap[code] || code)}"
                                            data-traffic-action="remove-country" data-traffic-value="${encodeTrafficValue(code)}">&times;</button>
                                    </div>
                                `).join('')}
                            ` : `
                                <div class="geo-zones-empty">
                                    <span class="geo-zones-empty-icon">${icons.globe || ''}</span>
                                    <strong>No zones selected</strong>
                                    <span>Use Manage zones or click countries on the map.</span>
                                </div>
                            `}
                        </div>
                    </div>
                </section>
            </div>
        </div>
        ${renderSaveButtons()}
    `;
}
