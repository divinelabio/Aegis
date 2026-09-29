import type { AntibotConfigState } from './antibots-config-shared.js';

type EscapeHtmlFn = (value: unknown) => string;
type EscapeAttrFn = (value: unknown) => string;
type GetBotIconCharFn = (botName: string) => string;
type RenderSaveButtonFn = () => string;
type RenderSectionHeaderFn = (icon: string, title: string, desc: string, toggleField?: string | null, toggleValue?: boolean) => string;

type ClassificationRenderDeps = {
    escapeHTML: EscapeHtmlFn;
    escapeAttr: EscapeAttrFn;
    getBotIconChar: GetBotIconCharFn;
    renderSaveButton: RenderSaveButtonFn;
    renderSectionHeader: RenderSectionHeaderFn;
};

function renderClassificationPolicyItem(
    title: string,
    desc: string,
    fieldPath: string,
    checked: boolean,
    isLast = false
): string {
    return `
            <div class="section-class-policy-item ${isLast ? 'last' : ''}">
                <div class="section-class-policy-item-main">
                    <div class="section-class-policy-item-title">${title}</div>
                    <div class="section-class-policy-item-desc">${desc}</div>
                </div>
                <label class="section-switch">
                    <input type="checkbox" ${checked ? 'checked' : ''} data-antibot-field-path="${fieldPath}" data-antibot-value-type="checkbox">
                    <span class="switch-slider"></span>
                </label>
            </div>
        `;
}

function renderGoodBotsModal(
    bots: string[],
    config: AntibotConfigState,
    isGoodBotModalOpen: boolean,
    goodBotFilter: string,
    deps: Omit<ClassificationRenderDeps, 'renderSaveButton'>
): string {
    if (!isGoodBotModalOpen) return '';

    const c = config.classification || {};
    const rules = c.good_bot_rules || {};
    const isGlobalEnabled = c.allow_good_bots !== false;

    const filter = goodBotFilter || '';
    const normalizedFilter = filter.trim().toLowerCase();
    const safeFilter = deps.escapeHTML(filter);
    const filterValue = deps.escapeAttr(filter);
    const filteredBots = bots.filter((b: string) => b.toLowerCase().includes(normalizedFilter));
    const disabledCount = Object.values(rules).filter((value) => value.action === 'disabled').length;
    const activeCount = bots.length - disabledCount;

    return `
    <div class="section-modal-overlay section-modal-overlay-padded section-modal-overlay-soft open is-visible" data-antibot-action="close-self-if-overlay" data-antibot-close-action="close-good-bots-modal">
        <div class="section-modal-panel section-goodbot-panel" role="dialog" aria-modal="true" aria-labelledby="goodbot-modal-title">
            <div class="section-modal-head section-goodbot-head">
                <div>
                    <h3 class="section-modal-title" id="goodbot-modal-title">Manage Access List</h3>
                    <div class="section-modal-sub">Allow or disable recognized crawlers without changing scoring rules.</div>
                </div>
                <button type="button" class="section-modal-close section-goodbot-close" data-antibot-action="close-good-bots-modal" aria-label="Close access list">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>
                </button>
            </div>

            ${!isGlobalEnabled ? `
                <div class="section-goodbot-global-warning">
                    <span>Global "Enable Good Bot Recognition" is OFF. These settings will be ignored until it is enabled.</span>
                </div>` : ''}

            <div class="section-modal-body section-goodbot-body ${!isGlobalEnabled ? 'disabled' : ''}">
                <div class="section-goodbot-toolbar">
                    <input type="text" placeholder="Search verified bots..." value="${filterValue}"
                        data-antibot-input-action="filter-good-bots"
                        class="section-goodbot-search section-search-input" aria-label="Search verified bots" autofocus>
                    <div class="section-goodbot-toolbar-count">${activeCount} of ${bots.length} allowed</div>
                </div>

                ${filteredBots.length === 0 ?
            `<div class="section-goodbot-empty">
                    No bots found matching "${safeFilter}"
                 </div>` :
            `<div class="section-goodbot-grid">
                    ${filteredBots.map((bot: string) => {
                const isDisabled = rules[bot]?.action === 'disabled';
                const visualActive = isGlobalEnabled && !isDisabled;

                return `
                        <label class="section-goodbot-card ${visualActive ? 'active' : ''}">
                            <div class="section-goodbot-icon">
                                ${deps.getBotIconChar(bot)}
                            </div>
                            <span class="section-goodbot-name">${deps.escapeHTML(bot)}</span>
                            <span class="section-switch">
                                <input type="checkbox" ${visualActive ? 'checked' : ''} data-antibot-action="toggle-good-bot" data-antibot-value="${deps.escapeAttr(bot)}" data-antibot-value-type="checkbox">
                                <span class="switch-slider"></span>
                            </span>
                        </label>`;
            }).join('')}
                </div>`}
            </div>

            <div class="section-modal-footer section-goodbot-footer">
                <button type="button" class="btn btn-outline" data-antibot-action="close-good-bots-modal">Done</button>
            </div>
        </div>
    </div>
    `;
}

export function renderAntibotClassificationTab(
    config: AntibotConfigState,
    goodBots: string[],
    goodBotFilter: string,
    isGoodBotModalOpen: boolean,
    deps: ClassificationRenderDeps
): string {
    const c = config.classification || {};

    const totalGoodBots = goodBots.length;
    const rules = c.good_bot_rules || {};
    const areGoodBotsAllowed = c.allow_good_bots !== false;

    const previewLimit = 8;
    const previewBots = goodBots.slice(0, previewLimit).map((bot: string) => {
        const isDisabled = rules[bot]?.action === 'disabled';
        return `
                <span class="section-class-preview-bot ${isDisabled ? 'disabled' : ''}">
                    ${deps.escapeHTML(bot)}
                </span>`;
    }).join('');

    return `
            ${deps.renderSectionHeader('tag', 'Crawler Classification', 'Manage how known entities are treated. Define policies for Verified Search Engines, Commercial Crawlers, and Bad Bots.')}

            <div class="section-classification-grid">
                <div class="card section-class-verified-card">
                    <div class="section-class-card-head">
                        <div>
                            <h4 class="section-class-title">Verified Bot Access</h4>
                            <p class="section-class-sub">Google, Bing, LinkedIn, and authorized services.</p>
                        </div>
                        <label class="section-switch">
                            <input type="checkbox" ${areGoodBotsAllowed ? 'checked' : ''} data-antibot-field-path="classification.allow_good_bots" data-antibot-value-type="checkbox">
                            <span class="switch-slider"></span>
                        </label>
                    </div>

                    <div class="section-class-verified-body">
                        <div class="section-class-preview-grid ${areGoodBotsAllowed ? '' : 'dimmed'}">
                            ${previewBots}
                            <button type="button" class="section-class-preview-more" data-antibot-action="show-good-bots-modal">
                                +${totalGoodBots - previewLimit} more
                            </button>
                        </div>

                        <button type="button" class="btn btn-outline section-class-manage-btn" data-antibot-action="show-good-bots-modal">
                            Manage Access List
                        </button>
                    </div>
                </div>

                <div class="card section-class-policy-card">
                    <div class="section-class-card-head">
                        <div>
                            <h4 class="section-class-title">Defense Policies</h4>
                            <p class="section-class-sub">Configure active protection measures.</p>
                        </div>
                    </div>

                    <div class="section-class-policy-list">
                        ${renderClassificationPolicyItem(
                            'Block Known Scrapers',
                            'Instantly block automated scraping frameworks and reconnaissance tools.',
                            'classification.block_bad_bots',
                            c.block_bad_bots !== false
                        )}
                        ${renderClassificationPolicyItem(
                            'Reverse DNS Verification',
                            'Verify legitimate search engine crawlers via reverse DNS and forward lookup.',
                            'classification.verify_search_engines',
                            c.verify_search_engines !== false
                        )}
                        ${renderClassificationPolicyItem(
                            'Strict Mode',
                            'Treat clients with empty or unrecognized User-Agent headers as bots.',
                            'classification.treat_unknown_as_bot',
                            c.treat_unknown_as_bot === true,
                            true
                        )}
                    </div>
                </div>
            </div>

            ${deps.renderSaveButton()}
            ${renderGoodBotsModal(goodBots, config, isGoodBotModalOpen, goodBotFilter, deps)}
`;
}
