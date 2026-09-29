"use strict";
const CONFIG_ENDPOINT = '/aegis/fp/config';
const INGEST_ENDPOINT = '/_aegis/fingerprint';
const SDK_VERSION = '3.0.0';
const SESSION_KEY = '__aegis_bot_session__';
const CONFIG_REQUEST_TIMEOUT_MS = 3000;
const BehaviorTracker = (() => {
    const mousePoints = [];
    const keyIntervals = [];
    let lastKeyTime = 0;
    let clicks = 0;
    let scrollDepth = 0;
    const startedAt = Date.now();
    function init() {
        let lastMoveAt = 0;
        document.addEventListener('mousemove', (event) => {
            const now = Date.now();
            if (now - lastMoveAt < 40)
                return;
            lastMoveAt = now;
            if (mousePoints.length < 48) {
                mousePoints.push({ x: event.clientX, y: event.clientY, t: now - startedAt });
            }
        }, { passive: true });
        document.addEventListener('keydown', () => {
            const now = Date.now();
            if (lastKeyTime > 0 && keyIntervals.length < 24) {
                keyIntervals.push(now - lastKeyTime);
            }
            lastKeyTime = now;
        }, { passive: true });
        document.addEventListener('click', () => {
            clicks += 1;
        }, { passive: true });
        document.addEventListener('scroll', () => {
            const root = document.documentElement;
            const maxScroll = Math.max(root.scrollHeight - root.clientHeight, 1);
            scrollDepth = Math.max(scrollDepth, Math.round((window.scrollY / maxScroll) * 100));
        }, { passive: true });
    }
    function getVector() {
        const distanceChanges = countDirectionChanges(mousePoints);
        const entropy = mousePoints.length > 1 ? distanceChanges / Math.max(mousePoints.length - 1, 1) : 0;
        const avgKeyFlight = keyIntervals.length > 0
            ? Math.round(keyIntervals.reduce((sum, value) => sum + value, 0) / keyIntervals.length)
            : 0;
        return {
            m_entropy: Number(entropy.toFixed(2)),
            m_moves: mousePoints.length,
            k_flight: avgKeyFlight,
            k_count: keyIntervals.length,
            s_depth: scrollDepth,
            clicks,
            time: Math.round((Date.now() - startedAt) / 1000)
        };
    }
    return { init, getVector };
})();
void init();
async function init() {
    try {
        const config = await fetchConfig();
        if (!config.enabled)
            return;
        if (config.collect_behavior) {
            BehaviorTracker.init();
            await sleep(600);
        }
        const payload = await collectSignals(config);
        await transmitPayload(payload);
    }
    catch (error) {
        console.error('[Aegis Bot SDK] init failed', error);
    }
}
async function fetchConfig() {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), CONFIG_REQUEST_TIMEOUT_MS);
    try {
        const response = await fetch(CONFIG_ENDPOINT, { credentials: 'same-origin', signal: controller.signal });
        if (response.ok) {
            const config = await response.json();
            if (isValidFingerprintConfig(config))
                return config;
        }
    }
    catch (_error) {
    }
    finally {
        window.clearTimeout(timeout);
    }
    return {
        contract_version: 1,
        enabled: false,
        mode: 'privacy',
        sdk_version: SDK_VERSION,
        session_nonce: '',
        config_expires_at: 0,
        nonce_expires_at: 0,
        collect_canvas: false,
        collect_webgl: false,
        collect_audio: false,
        collect_fonts: false,
        collect_behavior: false,
        check_headless: false,
        token_ttl: 0
    };
}
function isValidFingerprintConfig(value) {
    if (!value || typeof value !== 'object')
        return false;
    const config = value;
    const now = Math.floor(Date.now() / 1000);
    const validMode = config.mode === 'balanced';
    const validFlags = [
        config.collect_canvas,
        config.collect_webgl,
        config.collect_audio,
        config.collect_fonts,
        config.collect_behavior,
        config.check_headless
    ].every((flag) => typeof flag === 'boolean');
    if (config.contract_version !== 1 || config.sdk_version !== SDK_VERSION ||
        typeof config.enabled !== 'boolean' || !validMode || !validFlags ||
        typeof config.config_expires_at !== 'number' || config.config_expires_at <= now ||
        typeof config.nonce_expires_at !== 'number' || typeof config.token_ttl !== 'number') {
        return false;
    }
    if (!config.enabled)
        return true;
    return typeof config.session_nonce === 'string' && config.session_nonce.length >= 32 &&
        config.session_nonce.length <= 128 && config.nonce_expires_at > now &&
        config.token_ttl === 3600;
}
async function collectSignals(config) {
    const payload = {
        sdk_version: config.sdk_version || SDK_VERSION,
        session_id: getSessionId(),
        session_nonce: config.session_nonce || ''
    };
    const tasks = [];
    if (config.collect_canvas) {
        tasks.push(sha256Hex(readCanvasFingerprint()).then((hash) => { payload.fp_canvas_hash = hash; }));
    }
    if (config.collect_webgl) {
        const webglFingerprint = readWebGLFingerprint();
        payload.webgl_renderer = webglFingerprint.renderer;
        tasks.push(sha256Hex(webglFingerprint.fingerprint).then((hash) => { payload.fp_webgl_hash = hash; }));
    }
    if (config.collect_audio) {
        tasks.push(readAudioFingerprint().then(sha256Hex).then((hash) => { payload.fp_audio_hash = hash; }));
    }
    if (config.collect_fonts) {
        tasks.push(sha256Hex(readFontFingerprint()).then((hash) => { payload.fp_fonts_hash = hash; }));
    }
    if (config.check_headless) {
        payload.headless = await collectRuntimeSignals();
    }
    if (config.collect_behavior) {
        payload.behavior = BehaviorTracker.getVector();
    }
    await Promise.all(tasks);
    return payload;
}
async function transmitPayload(payload) {
    const body = JSON.stringify(payload);
    const headers = {
        'Content-Type': 'application/json',
        'X-Sec-Client-Ver': payload.sdk_version || SDK_VERSION
    };
    try {
        if (navigator.sendBeacon && body.length < 60000) {
            const blob = new Blob([body], { type: 'application/json' });
            const sent = navigator.sendBeacon(INGEST_ENDPOINT, blob);
            if (sent)
                return;
        }
    }
    catch (_error) {
    }
    await fetch(INGEST_ENDPOINT, {
        method: 'POST',
        credentials: 'same-origin',
        headers,
        body,
        keepalive: true
    });
}
async function collectRuntimeSignals() {
    const permissionsState = await readPermissionsState();
    const notificationPermission = typeof Notification !== 'undefined' ? Notification.permission : 'unsupported';
    const webdriverDescriptor = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(navigator), 'webdriver');
    return {
        webdriver: !!navigator.webdriver,
        webdriver_lie: (navigator.webdriver === false || navigator.webdriver === undefined) && webdriverDescriptor !== undefined,
        chrome_runtime_missing: /Chrome|Edg/.test(navigator.userAgent) && !window.chrome?.runtime,
        notification_inconsistent: notificationPermission === 'denied' && permissionsState === 'prompt',
        permissions_inconsistent: permissionsState === 'denied' && notificationPermission === 'granted',
        outer_window_zero: window.outerWidth === 0 || window.outerHeight === 0,
        touch_inconsistent: navigator.maxTouchPoints > 0 && !(window.matchMedia && window.matchMedia('(pointer: coarse)').matches)
    };
}
function readCanvasFingerprint() {
    try {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        if (!ctx)
            return 'no_canvas';
        canvas.width = 220;
        canvas.height = 60;
        ctx.textBaseline = 'alphabetic';
        ctx.font = '14px "Arial"';
        ctx.fillStyle = '#f60';
        ctx.fillRect(120, 1, 62, 20);
        ctx.fillStyle = '#069';
        ctx.fillText('Aegis Bot SDK', 4, 18);
        ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
        ctx.fillText('Aegis Bot SDK', 6, 20);
        return canvas.toDataURL();
    }
    catch (_error) {
        return 'canvas_error';
    }
}
function readWebGLFingerprint() {
    try {
        const canvas = document.createElement('canvas');
        const gl = (canvas.getContext('webgl') || canvas.getContext('experimental-webgl'));
        if (!gl)
            return { fingerprint: 'no_webgl', renderer: 'no_webgl' };
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        const vendor = debugInfo ? String(gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL)) : 'unknown';
        const renderer = debugInfo ? String(gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)) : 'unknown';
        const params = [
            gl.getParameter(gl.VERSION),
            gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
            gl.getParameter(gl.MAX_TEXTURE_SIZE),
            gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
            gl.getParameter(gl.MAX_VERTEX_ATTRIBS),
            gl.getParameter(gl.ALIASED_LINE_WIDTH_RANGE)?.toString?.() || 'range'
        ].join('|');
        return { fingerprint: `${vendor}|${renderer}|${params}`, renderer };
    }
    catch (_error) {
        return { fingerprint: 'webgl_error', renderer: 'webgl_error' };
    }
}
function readFontFingerprint() {
    const fonts = ['Arial', 'Courier New', 'Georgia', 'Helvetica', 'Times New Roman', 'Trebuchet MS', 'Verdana', 'Monaco'];
    const base = ['monospace', 'sans-serif', 'serif'];
    try {
        const probe = document.createElement('span');
        probe.textContent = 'mmmmmmmmmmlli';
        probe.style.position = 'absolute';
        probe.style.left = '-9999px';
        probe.style.fontSize = '72px';
        document.body.appendChild(probe);
        const baseline = Object.fromEntries(base.map((family) => {
            probe.style.fontFamily = family;
            return [family, `${probe.offsetWidth}x${probe.offsetHeight}`];
        }));
        const metrics = fonts.map((font) => base.map((fallback) => {
            probe.style.fontFamily = `"${font}",${fallback}`;
            return `${font}:${fallback}:${probe.offsetWidth}x${probe.offsetHeight}:${baseline[fallback]}`;
        }).join('|')).join('||');
        document.body.removeChild(probe);
        return metrics;
    }
    catch (_error) {
        return 'font_probe_error';
    }
}
async function readAudioFingerprint() {
    try {
        const AudioContextCtor = window.OfflineAudioContext || window.webkitOfflineAudioContext;
        if (!AudioContextCtor)
            return 'no_audio';
        const context = new AudioContextCtor(1, 44100, 44100);
        const oscillator = context.createOscillator();
        oscillator.type = 'triangle';
        oscillator.frequency.value = 10000;
        const compressor = context.createDynamicsCompressor();
        oscillator.connect(compressor);
        compressor.connect(context.destination);
        oscillator.start(0);
        const buffer = await context.startRendering();
        const data = buffer.getChannelData(0);
        let sum = 0;
        for (let i = 0; i < data.length; i += 64) {
            sum += Math.abs(data[i]);
        }
        return `audio:${sum.toFixed(6)}`;
    }
    catch (_error) {
        return 'audio_error';
    }
}
async function readPermissionsState() {
    try {
        if (!navigator.permissions || !navigator.permissions.query)
            return 'unsupported';
        const status = await navigator.permissions.query({ name: 'notifications' });
        return status.state;
    }
    catch (_error) {
        return 'error';
    }
}
async function sha256Hex(input) {
    const encoded = new TextEncoder().encode(input);
    const digest = await crypto.subtle.digest('SHA-256', encoded);
    return Array.from(new Uint8Array(digest)).map((value) => value.toString(16).padStart(2, '0')).join('');
}
function getSessionId() {
    try {
        const current = window.sessionStorage.getItem(SESSION_KEY);
        if (current)
            return current;
        const generated = self.crypto?.randomUUID ? self.crypto.randomUUID() : `sess-${Date.now()}-${Math.random().toString(16).slice(2)}`;
        window.sessionStorage.setItem(SESSION_KEY, generated);
        return generated;
    }
    catch (_error) {
        return `sess-${Date.now()}`;
    }
}
function countDirectionChanges(points) {
    if (points.length < 3)
        return 0;
    let changes = 0;
    for (let index = 2; index < points.length; index += 1) {
        const a = points[index - 2];
        const b = points[index - 1];
        const c = points[index];
        const abx = b.x - a.x;
        const aby = b.y - a.y;
        const bcx = c.x - b.x;
        const bcy = c.y - b.y;
        const dot = abx * bcx + aby * bcy;
        if (dot < 0)
            changes += 1;
    }
    return changes;
}
function sleep(ms) {
    return new Promise((resolve) => window.setTimeout(resolve, ms));
}
