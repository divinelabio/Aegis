package smartchallenge

import "fmt"

func renderInteractiveChallengeBody(actionURL string, issuedToken string) string {
	return fmt.Sprintf(`
	        <h1 id="challenge-title">One quick interaction</h1>
	        <p>Press and hold the verification control to continue.</p>
	        <form method="POST" action="%s" id="interactive-challenge-form" class="challenge-form">
	            <input type="hidden" name="aegis_challenge_submission" value="1">
	            <input type="hidden" name="challenge_type" value="interactive_challenge">
	            <input type="hidden" name="interactive_token" value="%s">
	            <input type="hidden" name="hold_duration" id="interactive-hold-duration" value="0">
	            <input type="hidden" name="signals" id="interactive-signals" value="">
            <button type="button" id="interactive-hold-button" class="challenge-hold-button" aria-label="Press and hold to verify">
                <span class="challenge-hold-mark" aria-hidden="true"></span>
                <span class="challenge-hold-copy">
                    <strong>Hold to verify</strong>
                    <small>Press and hold to continue</small>
                </span>
                <span class="challenge-hold-arrow" aria-hidden="true">›</span>
            </button>
        </form>
        <div id="status" class="status" role="status" aria-live="polite">Ready to verify</div>
        <script>
            (function() {
                const button = document.getElementById("interactive-hold-button");
                const form = document.getElementById("interactive-challenge-form");
	                const durationField = document.getElementById("interactive-hold-duration");
	                const signalsField = document.getElementById("interactive-signals");
	                const status = document.getElementById("status");
	                let startedAt = 0;
	                let pointerEvents = 0;
	                let pointerDistance = 0;
	                let lastPoint = null;
	                let pointerType = "unknown";
	                let startedVisible = false;
	                let visibilityChanges = 0;
	                const mouseEvents = [];
	                const maxEvents = 24;
	                const pageOpenedAt = Date.now();
	                let active = false;
	
	                document.addEventListener("visibilitychange", function() {
	                    visibilityChanges++;
	                });
	
	                function trackPoint(evt) {
	                    const point = evt.touches && evt.touches.length ? evt.touches[0] : evt.changedTouches && evt.changedTouches.length ? evt.changedTouches[0] : evt;
	                    if (!point) return;
	                    const x = Math.round(point.clientX || 0);
	                    const y = Math.round(point.clientY || 0);
	                    pointerEvents++;
	                    if (evt.pointerType) pointerType = evt.pointerType;
	                    if (evt.touches || evt.changedTouches) pointerType = "touch";
	                    if (lastPoint) {
	                        const dx = x - lastPoint.x;
	                        const dy = y - lastPoint.y;
	                        pointerDistance += Math.sqrt(dx * dx + dy * dy);
	                    }
	                    lastPoint = { x, y };
	                    if (mouseEvents.length < maxEvents) {
	                        mouseEvents.push({ x, y, t: Date.now() - pageOpenedAt });
	                    }
	                }
	
	                function collectSignals(held) {
	                    const completedVisible = document.visibilityState === "visible";
	                    const hasPointerEvidence = pointerEvents >= 2;
	                    return JSON.stringify({
	                        userAgent: navigator.userAgent,
	                        platform: navigator.platform,
	                        language: navigator.language || '',
	                        languages: navigator.languages ? navigator.languages.join(',') : '',
                        webdriver: !!navigator.webdriver,
	                        webdriver_lie: (navigator.webdriver === false || navigator.webdriver === undefined) && Object.getOwnPropertyDescriptor(navigator.__proto__, 'webdriver') !== undefined,
	                        plugins_len: navigator.plugins ? navigator.plugins.length : 0,
	                        screen: [screen.width, screen.height, screen.colorDepth, window.outerWidth, window.outerHeight].join('x'),
	                        headless: !!(navigator.webdriver || (window.chrome && window.chrome.runtime === undefined)),
	                        behavior: {
	                            has_mouse: hasPointerEvidence,
	                            m_moves: pointerEvents,
	                            clicks: 1,
	                            time: Math.max(1, Math.round(held / 1000)),
	                            events: { mouse: mouseEvents, keys: [] }
	                        },
	                        interaction: {
	                            hold_duration: held,
	                            event_count: pointerEvents,
	                            event_span: mouseEvents.length > 1 ? mouseEvents[mouseEvents.length - 1].t - mouseEvents[0].t : 0,
	                            pointer_distance: Math.round(pointerDistance),
	                            pointer_type: pointerType,
	                            focused: document.hasFocus(),
	                            started_visible: startedVisible,
	                            completed_visible: completedVisible,
	                            visibility_changes: visibilityChanges
	                        }
	                    });
	                }
	
	                function begin(event) {
	                    if (active) return;
	                    active = true;
	                    button.classList.add("is-pressed");
	                    trackPoint(event);
	                    startedAt = Date.now();
	                    startedVisible = document.visibilityState === "visible";
	                    status.innerText = "Keep holding...";
	                }
	
	                function finish(event) {
	                    if (!startedAt) return;
	                    active = false;
	                    button.classList.remove("is-pressed");
	                    trackPoint(event);
	                    const held = Date.now() - startedAt;
	                    startedAt = 0;
	                    durationField.value = String(held);
	                    signalsField.value = collectSignals(held);
	                    status.innerText = held >= 1500 ? "Verifying..." : "Hold a little longer...";
	                    if (held >= 1500) {
	                        form.submit();
	                    }
	                }
	
	                button.addEventListener("mousedown", begin);
	                button.addEventListener("touchstart", begin, { passive: true });
	                button.addEventListener("pointerdown", begin);
	                button.addEventListener("pointermove", trackPoint);
	                button.addEventListener("touchmove", trackPoint, { passive: true });
	                button.addEventListener("mouseup", finish);
	                button.addEventListener("mouseleave", finish);
	                button.addEventListener("touchend", finish, { passive: true });
	                button.addEventListener("pointerup", finish);
	            })();
	        </script>
	    `, actionURL, issuedToken)
}
