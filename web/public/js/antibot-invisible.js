void runInvisibleChallenge();
async function runInvisibleChallenge() {
    const config = window.__AEGIS_INVISIBLE__;
    if (!config?.salt)
        return;
    const difficulty = Number.isFinite(config.difficulty) ? Number(config.difficulty) : 2;
    const endpoint = config.endpoint || window.location.href;
    const nonce = await solveProof(config.salt, difficulty);
    const payload = {
        challenge_type: 'invisible_challenge',
        pow_salt: config.salt,
        pow_nonce: nonce,
        signals: JSON.stringify({
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            language: navigator.language,
            languages: Array.isArray(navigator.languages) ? navigator.languages.slice(0, 6) : [],
            webdriver: !!navigator.webdriver,
            screen: `${screen.width}x${screen.height}x${screen.colorDepth}`,
            viewport: `${window.innerWidth}x${window.innerHeight}|${window.outerWidth}x${window.outerHeight}`
        })
    };
    await fetch(endpoint, {
        method: 'POST',
        body: buildFormData(payload),
        credentials: 'same-origin'
    });
}
async function solveProof(salt, difficulty) {
    const encoder = new TextEncoder();
    const prefix = '0'.repeat(Math.max(difficulty, 1));
    let nonce = 0;
    while (true) {
        const digest = await crypto.subtle.digest('SHA-256', encoder.encode(`${salt}${nonce}`));
        const hash = Array.from(new Uint8Array(digest)).map((value) => value.toString(16).padStart(2, '0')).join('');
        if (hash.startsWith(prefix))
            return String(nonce);
        nonce += 1;
    }
}
function buildFormData(payload) {
    const form = new FormData();
    form.append('challenge_type', payload.challenge_type);
    form.append('pow_salt', payload.pow_salt);
    form.append('pow_nonce', payload.pow_nonce);
    form.append('signals', payload.signals);
    return form;
}
export {};
