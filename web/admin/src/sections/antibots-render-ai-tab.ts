import type { AntibotConfigState } from './antibots-config-shared.js';

type EscapeHtmlFn = (value: unknown) => string;
type EscapeAttrFn = (value: unknown) => string;
type GetBotLogoFn = (botName: string) => string;
type RenderSaveButtonFn = () => string;
type RenderSectionHeaderFn = (icon: string, title: string, desc: string, toggleField?: string | null, toggleValue?: boolean) => string;

const AI_BOTS: Array<{ name: string; category: string }> = [
    { name: 'GPTBot', category: 'OpenAI' },
    { name: 'ChatGPT-User', category: 'OpenAI' },
    { name: 'Claude-Web', category: 'Anthropic' },
    { name: 'Anthropic-AI', category: 'Anthropic' },
    { name: 'Google-Extended', category: 'Google' },
    { name: 'Applebot', category: 'Apple' },
    { name: 'PerplexityBot', category: 'Perplexity' },
    { name: 'CCBot', category: 'Common Crawl' },
    { name: 'Bytespider', category: 'ByteDance' },
    { name: 'FacebookBot', category: 'Meta' },
    { name: 'Amazonbot', category: 'Amazon' },
    { name: 'Omgilibot', category: 'Webz.io' },
    { name: 'Diffbot', category: 'Diffbot' },
    { name: 'Cohere', category: 'Cohere' },
    { name: 'YouBot', category: 'You.com' }
];

export function renderAntibotAiCrawlersTab(
    config: AntibotConfigState,
    deps: {
        escapeHTML: EscapeHtmlFn;
        escapeAttr: EscapeAttrFn;
        getBotLogo: GetBotLogoFn;
        renderSaveButton: RenderSaveButtonFn;
        renderSectionHeader: RenderSectionHeaderFn;
    }
): string {
    const ai = config.ai_crawlers || {};
    const rules = ai.rules || {};

    return `
            ${deps.renderSectionHeader('bot', 'AI Crawler Policies', 'Control access for AI training bots and web scrapers.')}

    <div class="card section-ai-card">
        <h4 class="section-ai-card-title">Bot Access Rules</h4>
        <p class="section-ai-card-sub">Set individual policies for each AI crawler. Changes require save.</p>

        <div class="section-ai-grid">
            ${AI_BOTS.map((bot) => {
        const ruleAction = rules[bot.name]?.action || 'challenge';
        return `
                        <div class="section-ai-bot-card">
                            <div class="section-ai-bot-head">
                                <div class="section-ai-bot-main">
                                    ${deps.getBotLogo(bot.name)}
                                    <div>
                                        <div class="section-ai-bot-name">${deps.escapeHTML(bot.name)}</div>
                                        <div class="section-ai-bot-category">${deps.escapeHTML(bot.category)}</div>
                                    </div>
                                </div>
                            </div>
                            <div class="section-ai-toggle-group" role="group" aria-label="${deps.escapeAttr(bot.name)} access policy">
                                ${['allow', 'challenge', 'block'].map((opt) => {
            const isActive = ruleAction === opt;
            return `<button type="button" class="section-ai-toggle-btn ${opt} ${isActive ? 'active' : ''}" data-antibot-action="set-ai-rule" data-antibot-bot="${deps.escapeAttr(bot.name)}" data-antibot-value="${opt}" aria-pressed="${isActive ? 'true' : 'false'}">${opt.charAt(0).toUpperCase() + opt.slice(1)}</button>`;
        }).join('')}
                            </div>
                        </div>
                    `;
    }).join('')}
        </div>
    </div>

            ${deps.renderSaveButton()}
`;
}
