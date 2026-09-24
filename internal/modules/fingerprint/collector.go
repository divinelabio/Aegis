package fingerprint

import "strings"

// Collector handles generation of client-side fingerprinting scripts
type Collector struct {
	config Config
}

// Config holds configuration for the collector
type Config struct {
	CollectCanvas   bool
	CollectWebGL    bool
	CollectAudio    bool
	CollectBehavior bool
	CheckHeadless   bool
}

// NewCollector creates a new collector
func NewCollector(cfg Config) *Collector {
	return &Collector{config: cfg}
}

// GenerateScript returns the JavaScript code to collect browser signals.
// It intentionally stays dependency-free so challenge pages can run even in
// constrained browsers or when the full public SDK is not loaded.
func (c *Collector) GenerateScript() string {
	var script strings.Builder
	script.WriteString(`
	(function() {
		var startTime = Date.now();
		var mouseEvents = [];
		var keyEvents = [];
		var clicks = 0;
		var scrollDepth = 0;

		var fp = {
			screen: [screen.width, screen.height, screen.colorDepth].join('x'),
			viewport: {
				w: window.innerWidth || 0,
				h: window.innerHeight || 0,
				outerW: window.outerWidth || 0,
				outerH: window.outerHeight || 0
			},
			timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
			language: navigator.language || '',
			languages: navigator.languages ? navigator.languages.slice(0, 8) : [],
			platform: navigator.platform || '',
			hardwareConcurrency: navigator.hardwareConcurrency || 0,
			deviceMemory: navigator.deviceMemory || 0,
			vendor: navigator.vendor || '',
			userAgent: navigator.userAgent || '',
			webdriver: !!navigator.webdriver,
			plugins: Array.from(navigator.plugins || []).map(function(p) { return p.name; }).join(','),
			plugins_len: navigator.plugins ? navigator.plugins.length : 0,
			cookies_enabled: navigator.cookieEnabled,
			local_storage_enabled: storageAvailable('localStorage'),
			session_storage_enabled: storageAvailable('sessionStorage'),
			touch: navigator.maxTouchPoints > 0,
			pointer_coarse: window.matchMedia ? window.matchMedia('(pointer: coarse)').matches : false
		};
		// The lightweight challenge collector intentionally does not enumerate fonts.
		fp.fp_fonts_hash = 'not_collected';

		function hash(str) {
			var h = 0, i, chr;
			if (!str || str.length === 0) return h.toString(16);
			for (i = 0; i < str.length; i++) {
				chr = str.charCodeAt(i);
				h = ((h << 5) - h) + chr;
				h |= 0;
			}
			return h.toString(16);
		}

		function storageAvailable(type) {
			try {
				var storage = window[type];
				var probe = '__aegis_probe__';
				storage.setItem(probe, '1');
				storage.removeItem(probe);
				return true;
			} catch (e) {
				return false;
			}
		}

		function recordEvent(type, data) {
			if (mouseEvents.length + keyEvents.length >= 50) return;
			if (type === 'mouse') mouseEvents.push(data);
			if (type === 'key') keyEvents.push(data);
		}
	`)

	if c.config.CollectCanvas {
		script.WriteString(`
		try {
			var canvas = document.createElement('canvas');
			var ctx = canvas.getContext('2d');
			if (ctx) {
				ctx.textBaseline = 'alphabetic';
				ctx.font = '14px "Arial"';
				ctx.fillStyle = '#f60';
				ctx.fillRect(125, 1, 62, 20);
				ctx.fillStyle = '#069';
				ctx.fillText('Aegis-FP', 2, 15);
				ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
				ctx.fillText('Aegis-FP', 4, 17);
				fp.canvas = hash(canvas.toDataURL());
			} else {
				fp.canvas = 'no_canvas';
			}
		} catch (e) {
			fp.canvas = 'canvas_error';
		}
		`)
	}

	if c.config.CollectWebGL {
		script.WriteString(`
		try {
			var webglCanvas = document.createElement('canvas');
			var gl = webglCanvas.getContext('webgl') || webglCanvas.getContext('experimental-webgl');
			if (gl) {
				var debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
				var vendor = debugInfo ? String(gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL)) : 'unknown';
				var renderer = debugInfo ? String(gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)) : 'unknown';
				var params = [
					gl.getParameter(gl.VERSION),
					gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
					gl.getParameter(gl.MAX_TEXTURE_SIZE),
					gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
					gl.getParameter(gl.MAX_VERTEX_ATTRIBS)
				].join('|');
				fp.webgl_vendor = vendor;
				fp.webgl_renderer = renderer;
				fp.fp_webgl_hash = hash([vendor, renderer, params].join('|'));
			} else {
				fp.webgl_vendor = 'no_webgl';
				fp.webgl_renderer = 'no_webgl';
				fp.fp_webgl_hash = 'no_webgl';
			}
		} catch (e) {
			fp.webgl_vendor = 'webgl_error';
			fp.webgl_renderer = 'webgl_error';
			fp.fp_webgl_hash = 'webgl_error';
		}
		`)
	}

	if c.config.CollectAudio {
		script.WriteString(`
		try {
			fp.audio = 'audio_disabled_in_legacy_collector';
		} catch (e) {
			fp.audio = 'audio_error';
		}
		`)
	}

	if c.config.CheckHeadless {
		script.WriteString(`
		try {
			// A false webdriver property, including an own property, is not reliable evidence of automation.
			fp.webdriver_lie = false;
			fp.headless = {
				webdriver: !!navigator.webdriver,
				webdriver_lie: fp.webdriver_lie,
				// chrome.runtime is extension-only and Notification.permission may be denied by a real user.
				chrome_runtime_missing: false,
				notification_inconsistent: false,
				permissions_inconsistent: false,
				// Outer dimensions can be zero while a normal browser window is initializing.
				outer_window_zero: false,
				touch_inconsistent: navigator.maxTouchPoints > 0 && !(window.matchMedia && window.matchMedia('(pointer: coarse)').matches)
			};
		} catch (e) {
			fp.headless = {
				webdriver: !!navigator.webdriver,
				webdriver_lie: false,
				chrome_runtime_missing: false,
				notification_inconsistent: false,
				permissions_inconsistent: false,
				outer_window_zero: false,
				touch_inconsistent: false
			};
		}
		`)
	}

	if c.config.CollectBehavior {
		script.WriteString(`
		document.addEventListener('mousemove', function(e) {
			recordEvent('mouse', { x: e.clientX, y: e.clientY, t: Date.now() - startTime });
		}, { passive: true });

		document.addEventListener('keydown', function(e) {
			recordEvent('key', { k: e.key, t: Date.now() - startTime });
		}, { passive: true });

		document.addEventListener('click', function() {
			clicks += 1;
		}, { passive: true });

		document.addEventListener('scroll', function() {
			var root = document.documentElement || document.body;
			var maxScroll = Math.max((root.scrollHeight || 0) - (root.clientHeight || 0), 1);
			scrollDepth = Math.max(scrollDepth, Math.round(((window.scrollY || 0) / maxScroll) * 100));
		}, { passive: true });

		fp.behavior = {
			has_mouse: mouseEvents.length > 0,
			has_keyboard: keyEvents.length > 0,
			events: {
				mouse: mouseEvents,
				keys: keyEvents
			},
			m_moves: mouseEvents.length,
			k_count: keyEvents.length,
			clicks: clicks,
			s_depth: scrollDepth,
			time: 0
		};
		`)
	}

	script.WriteString(`
		if (fp.behavior) {
			fp.behavior.has_mouse = mouseEvents.length > 0;
			fp.behavior.has_keyboard = keyEvents.length > 0;
			fp.behavior.events.mouse = mouseEvents;
			fp.behavior.events.keys = keyEvents;
			fp.behavior.m_moves = mouseEvents.length;
			fp.behavior.k_count = keyEvents.length;
			fp.behavior.clicks = clicks;
			fp.behavior.s_depth = scrollDepth;
			fp.behavior.time = Math.max(1, Math.round((Date.now() - startTime) / 1000));
		}

		return JSON.stringify(fp);
	})();
	`)

	return script.String()
}
