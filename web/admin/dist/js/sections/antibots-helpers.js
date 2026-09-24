const ANTIBOT_BRANDS = {
    GPTBot: {
        bg: 'linear-gradient(135deg, #10a37f 0%, #0d8a6a 100%)',
        icon: '<svg viewBox="0 0 24 24" fill="white" width="16" height="16"><path d="M22.28 9.77a.56.56 0 0 0-.16-.68 11.23 11.23 0 0 0-3.64-2.18l-.55-.22a10.9 10.9 0 0 0-4.48-.68h-.12a11 11 0 0 0-3.69.94l-.3.12a11.16 11.16 0 0 0-3.5 2.5.56.56 0 0 0 .15.89 3.55 3.55 0 0 1 1.76 2.37A3.56 3.56 0 0 1 7.15 16l.17.47a11.21 11.21 0 0 0 3.19 4 11 11 0 0 0 3.79 1.83 11 11 0 0 0 3.58.07l.38-.06a11.11 11.11 0 0 0 4.14-1.66.56.56 0 0 0 .17-.68 3.56 3.56 0 0 1-.94-2.79 3.57 3.57 0 0 1 1.63-2.61.56.56 0 0 0 0-.91ZM12 17.56a5.56 5.56 0 1 1 5.56-5.56A5.57 5.57 0 0 1 12 17.56Z"/></svg>'
    },
    'ChatGPT-User': {
        bg: 'linear-gradient(135deg, #10a37f 0%, #0d8a6a 100%)',
        icon: '<svg viewBox="0 0 24 24" fill="white" width="16" height="16"><path d="M22.28 9.77a.56.56 0 0 0-.16-.68 11.23 11.23 0 0 0-3.64-2.18l-.55-.22a10.9 10.9 0 0 0-4.48-.68h-.12a11 11 0 0 0-3.69.94l-.3.12a11.16 11.16 0 0 0-3.5 2.5.56.56 0 0 0 .15.89 3.55 3.55 0 0 1 1.76 2.37A3.56 3.56 0 0 1 7.15 16l.17.47a11.21 11.21 0 0 0 3.19 4 11 11 0 0 0 3.79 1.83 11 11 0 0 0 3.58.07l.38-.06a11.11 11.11 0 0 0 4.14-1.66.56.56 0 0 0 .17-.68 3.56 3.56 0 0 1-.94-2.79 3.57 3.57 0 0 1 1.63-2.61.56.56 0 0 0 0-.91ZM12 17.56a5.56 5.56 0 1 1 5.56-5.56A5.57 5.57 0 0 1 12 17.56Z"/></svg>'
    },
    'Claude-Web': { bg: 'linear-gradient(135deg, #d97757 0%, #c16045 100%)', icon: 'Cl' },
    'Anthropic-AI': { bg: 'linear-gradient(135deg, #d97757 0%, #c16045 100%)', icon: 'An' },
    'Google-Extended': {
        bg: 'linear-gradient(135deg, #4285f4 0%, #34a853 50%, #fbbc05 100%)',
        icon: '<svg viewBox="0 0 24 24" fill="white" width="16" height="16"><path d="M12.48 10.92v3.28h7.84c-.24 1.84-.853 3.187-1.787 4.133-1.147 1.147-2.933 2.4-6.053 2.4-4.827 0-8.6-3.893-8.6-8.72s3.773-8.72 8.6-8.72c2.6 0 4.507 1.027 5.907 2.347l2.307-2.307C18.747 1.44 16.133 0 12.48 0 5.867 0 .533 5.347.533 12s5.333 12 11.947 12c3.48 0 6.147-1.147 7.213-3.08 1.48-2.653 1.307-6.04-1.853-9.147h-5.36z"/></svg>'
    },
    FacebookBot: {
        bg: 'linear-gradient(135deg, #0668e1 0%, #0081fb 100%)',
        icon: '<svg viewBox="0 0 24 24" fill="white" width="16" height="16"><path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"/></svg>'
    },
    CCBot: { bg: 'linear-gradient(135deg, #ef4444 0%, #b91c1c 100%)', icon: 'CC' },
    Bytespider: {
        bg: 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)',
        icon: '<svg viewBox="0 0 24 24" fill="white" width="16" height="16"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8z"/></svg>'
    },
    Applebot: {
        bg: 'linear-gradient(135deg, #555555 0%, #333333 100%)',
        icon: '<svg viewBox="0 0 24 24" fill="white" width="16" height="16"><path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83z"/></svg>'
    },
    PerplexityBot: { bg: 'linear-gradient(135deg, #20b2aa 0%, #1a9090 100%)', icon: 'Px' },
    Amazonbot: {
        bg: 'linear-gradient(135deg, #ff9900 0%, #cc7a00 100%)',
        icon: '<svg viewBox="0 0 24 24" fill="white" width="16" height="16"><path d="M.045 18.02c.072-.116.187-.124.348-.022 3.636 2.11 7.594 3.166 11.87 3.166 2.852 0 5.668-.533 8.447-1.595.47-.189.873-.395 1.21-.618.226-.15.44-.15.64.01.195.155.234.37.115.63-.285.63-.853 1.14-1.7 1.53-2.53 1.16-5.335 1.74-8.415 1.74-4.61 0-8.78-1.24-12.51-3.72-.247-.166-.327-.4-.24-.685l.045-.116.19-.32z"/></svg>'
    },
    Omgilibot: { bg: 'linear-gradient(135deg, #9333ea 0%, #7e22ce 100%)', icon: 'Om' },
    Diffbot: { bg: 'linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)', icon: 'Df' },
    Cohere: { bg: 'linear-gradient(135deg, #6b7280 0%, #4b5563 100%)', icon: 'Co' },
    YouBot: { bg: 'linear-gradient(135deg, #22c55e 0%, #16a34a 100%)', icon: 'You' }
};
export const AntibotsHelpers = {
    escapeHTML(value) {
        if (value === null || value === undefined)
            return '';
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    },
    escapeAttr(value) {
        if (value === null || value === undefined)
            return '';
        return String(value)
            .replace(/\\/g, '\\\\')
            .replace(/'/g, "\\'");
    },
    getBotLogo(botName) {
        const fallbackName = botName || '';
        const brand = ANTIBOT_BRANDS[botName] || {
            bg: 'var(--bg-elevated)',
            icon: fallbackName.substring(0, 2)
        };
        const iconContent = brand.icon.includes('<')
            ? brand.icon
            : `<span class="section-logo-text">${this.escapeHTML(brand.icon)}</span>`;
        const encodedBg = encodeURIComponent(brand.bg);
        return `<div class="section-logo" data-logo-bg="${encodedBg}">${iconContent}</div>`;
    }
};
