package smartchallenge

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"time"
)

type interactiveSymbol struct {
	Glyph string
	Name  string
}

var interactiveSymbolPool = []interactiveSymbol{
	{Glyph: "◆", Name: "filled diamond"},
	{Glyph: "●", Name: "filled circle"},
	{Glyph: "▲", Name: "filled triangle"},
	{Glyph: "■", Name: "filled square"},
	{Glyph: "★", Name: "star"},
	{Glyph: "✚", Name: "cross"},
	{Glyph: "⬟", Name: "pentagon"},
	{Glyph: "⬢", Name: "hexagon"},
	{Glyph: "◇", Name: "outline diamond"},
	{Glyph: "○", Name: "outline circle"},
	{Glyph: "△", Name: "outline triangle"},
	{Glyph: "□", Name: "outline square"},
}

func seededChallengeOrder(issuedToken string, purpose string, size int) []int {
	order := make([]int, size)
	for index := range order {
		order[index] = index
	}

	digest := sha256.Sum256([]byte(purpose + "\x00" + issuedToken))
	byteIndex := 0
	for index := size - 1; index > 0; index-- {
		swapIndex := int(digest[byteIndex%len(digest)]) % (index + 1)
		order[index], order[swapIndex] = order[swapIndex], order[index]
		byteIndex++
	}
	return order
}

func randomizedChallengeSeed(issuedToken string) string {
	entropy := make([]byte, 16)
	if _, err := rand.Read(entropy); err == nil {
		return issuedToken + "\x00" + string(entropy)
	}
	return fmt.Sprintf("%s\x00%d", issuedToken, time.Now().UnixNano())
}

func interactiveNumberChallenge(issuedToken string) ([3]int, [3]int) {
	challengeSeed := randomizedChallengeSeed(issuedToken)
	valueOrder := seededChallengeOrder(challengeSeed, "sequence-values", 10)
	numbers := [3]int{valueOrder[0], valueOrder[1], valueOrder[2]}
	if numbers == [3]int{1, 2, 3} {
		numbers[0], numbers[2] = numbers[2], numbers[0]
	}

	buttonOrder := seededChallengeOrder(challengeSeed, "sequence-buttons", len(numbers))
	return numbers, [3]int{buttonOrder[0], buttonOrder[1], buttonOrder[2]}
}

func interactiveSymbolChallenge(issuedToken string) ([3]interactiveSymbol, int, [3]int) {
	challengeSeed := randomizedChallengeSeed(issuedToken)
	symbolOrder := seededChallengeOrder(challengeSeed, "symbol-values", len(interactiveSymbolPool))
	symbols := [3]interactiveSymbol{
		interactiveSymbolPool[symbolOrder[0]],
		interactiveSymbolPool[symbolOrder[1]],
		interactiveSymbolPool[symbolOrder[2]],
	}
	targetOrder := seededChallengeOrder(challengeSeed, "symbol-target", len(symbols))
	buttonOrder := seededChallengeOrder(challengeSeed, "symbol-buttons", len(symbols))
	return symbols, targetOrder[0], [3]int{buttonOrder[0], buttonOrder[1], buttonOrder[2]}
}

func renderInteractiveChallengeByStyle(actionURL string, issuedToken string, style string) string {
	style = normalizeInteractiveStyle(style)
	if style == InteractiveStyleHold {
		return renderInteractiveChallengeBody(actionURL, issuedToken)
	}

	title, instruction, control := interactiveVariantContent(style, issuedToken)
	return fmt.Sprintf(`
	        <h1 id="challenge-title">%s</h1>
	        <p id="interactive-help">%s</p>
	        <form method="POST" action="%s" id="interactive-challenge-form" class="challenge-form">
	            <input type="hidden" name="aegis_challenge_submission" value="1">
	            <input type="hidden" name="challenge_type" value="interactive_challenge">
	            <input type="hidden" name="interactive_style" value="%s">
	            <input type="hidden" name="interactive_token" value="%s">
	            <input type="hidden" name="hold_duration" id="interactive-hold-duration" value="0">
	            <input type="hidden" name="signals" id="interactive-signals" value="">
	            %s
	        </form>
	        <div id="status" class="status" role="status" aria-live="polite">Ready to verify</div>
	        <script>
	            (function() {
	                const method = document.querySelector('input[name="interactive_style"]').value;
	                const form = document.getElementById("interactive-challenge-form");
	                const durationField = document.getElementById("interactive-hold-duration");
	                const signalsField = document.getElementById("interactive-signals");
	                const status = document.getElementById("status");
	                const pageOpenedAt = Date.now();
	                let interactionStartedAt = 0;
	                let pointerEvents = 0;
	                let pointerDistance = 0;
	                let pointerType = "unknown";
	                let lastPoint = null;
	                let startedVisible = document.visibilityState === "visible";
	                let visibilityChanges = 0;
	                let submitting = false;
	                const mouseEvents = [];
	                const keyEvents = [];
	                const maxEvents = 32;

	                document.addEventListener("visibilitychange", function() {
	                    visibilityChanges++;
	                });

	                function trackPoint(event) {
	                    const x = Math.round(event.clientX || 0);
	                    const y = Math.round(event.clientY || 0);
	                    pointerEvents++;
	                    if (event.pointerType) pointerType = event.pointerType;
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

	                function trackKey(event) {
	                    pointerType = "keyboard";
	                    pointerEvents++;
	                    if (keyEvents.length < maxEvents) {
	                        keyEvents.push({ key: event.key, t: Date.now() - pageOpenedAt });
	                    }
	                }

	                document.addEventListener("pointerdown", trackPoint, true);
	                document.addEventListener("pointermove", trackPoint, { passive: true, capture: true });
	                document.addEventListener("pointerup", trackPoint, true);
	                document.addEventListener("keydown", trackKey, true);
	                document.addEventListener("keyup", trackKey, true);

	                function beginInteraction() {
	                    if (!interactionStartedAt) interactionStartedAt = Date.now();
	                }

	                function collectSignals(duration, stepCount, completion) {
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
	                            has_mouse: pointerEvents > 0,
	                            m_moves: pointerEvents,
	                            clicks: stepCount,
	                            time: Math.max(1, Math.round(duration / 1000)),
	                            events: { mouse: mouseEvents, keys: keyEvents }
	                        },
	                        interaction: {
	                            method: method,
	                            completed: true,
	                            step_count: stepCount,
	                            completion: completion,
	                            hold_duration: duration,
	                            event_count: pointerEvents,
	                            event_span: mouseEvents.length > 1 ? mouseEvents[mouseEvents.length - 1].t - mouseEvents[0].t : duration,
	                            pointer_distance: Math.round(pointerDistance),
	                            pointer_type: pointerType,
	                            focused: document.hasFocus(),
	                            started_visible: startedVisible,
	                            completed_visible: document.visibilityState === "visible",
	                            visibility_changes: visibilityChanges
	                        }
	                    });
	                }

	                function submitProof(duration, stepCount, completion) {
	                    if (submitting) return;
	                    submitting = true;
	                    durationField.value = String(duration);
	                    signalsField.value = collectSignals(duration, stepCount, completion);
	                    status.innerText = "Verifying...";
	                    window.setTimeout(function() { form.submit(); }, 180);
	                }

	                if (method === "click") {
	                    const control = document.getElementById("interactive-click-button");
	                    control.addEventListener("click", function() {
	                        beginInteraction();
	                        const duration = Math.min(30000, Date.now() - pageOpenedAt);
	                        if (duration < 250) {
	                            status.innerText = "Take a moment, then try again.";
	                            return;
	                        }
	                        control.classList.add("is-complete");
	                        submitProof(duration, 1, 100);
	                    });
	                }

	                if (method === "slide") {
	                    const control = document.getElementById("interactive-slide-control");
	                    const thumb = control.querySelector(".challenge-slide-thumb");
	                    const fill = control.querySelector(".challenge-slide-fill");
	                    let sliding = false;
	                    let progress = 0;

	                    function renderProgress() {
	                        const available = Math.max(0, control.getBoundingClientRect().width - 50);
	                        thumb.style.transform = "translateX(" + Math.round(available * progress / 100) + "px)";
	                        fill.style.width = progress + "%%";
	                        control.setAttribute("aria-valuenow", String(Math.round(progress)));
	                    }

	                    function updateFromPointer(event) {
	                        const rect = control.getBoundingClientRect();
	                        const usable = Math.max(1, rect.width - 50);
	                        progress = Math.max(0, Math.min(100, ((event.clientX - rect.left - 25) / usable) * 100));
	                        renderProgress();
	                    }

	                    function resetSlide(message) {
	                        sliding = false;
	                        progress = 0;
	                        interactionStartedAt = 0;
	                        control.classList.remove("is-active");
	                        renderProgress();
	                        status.innerText = message;
	                    }

	                    thumb.addEventListener("pointerdown", function(event) {
	                        event.preventDefault();
	                        sliding = true;
	                        beginInteraction();
	                        control.classList.add("is-active");
	                        thumb.setPointerCapture(event.pointerId);
	                        status.innerText = "Slide to the end...";
	                    });
	                    thumb.addEventListener("pointermove", function(event) {
	                        if (sliding) updateFromPointer(event);
	                    });
	                    thumb.addEventListener("pointerup", function() {
	                        if (!sliding) return;
	                        const duration = Date.now() - interactionStartedAt;
	                        if (progress >= 95 && duration >= 400) {
	                            progress = 100;
	                            renderProgress();
	                            control.classList.add("is-complete");
	                            submitProof(duration, 1, 100);
	                        } else {
	                            resetSlide(progress >= 95 ? "Slide a little more steadily." : "Slide all the way to continue.");
	                        }
	                    });
	                    thumb.addEventListener("pointercancel", function() {
	                        resetSlide("Ready to verify");
	                    });
	                    control.addEventListener("keydown", function(event) {
	                        if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
	                        event.preventDefault();
	                        beginInteraction();
	                        if (event.key === "Home") progress = 0;
	                        if (event.key === "End") progress = 100;
	                        if (event.key === "ArrowLeft") progress = Math.max(0, progress - 10);
	                        if (event.key === "ArrowRight") progress = Math.min(100, progress + 10);
	                        renderProgress();
	                        if (progress >= 100) {
	                            const duration = Date.now() - interactionStartedAt;
	                            if (duration >= 400) submitProof(duration, 1, 100);
	                        }
	                    });
	                }

	                if (method === "sequence") {
	                    const control = document.getElementById("interactive-sequence-control");
	                    const steps = Array.from(control.querySelectorAll("[data-step]"));
	                    const requiredValues = (control.dataset.sequence || "").split(",");
	                    let expected = 1;

	                    function resetSequence(message) {
	                        expected = 1;
	                        interactionStartedAt = 0;
	                        steps.forEach(function(step) { step.classList.remove("is-complete", "is-wrong"); });
	                        status.innerText = message;
	                    }

	                    steps.forEach(function(step) {
	                        step.addEventListener("click", function() {
	                            beginInteraction();
	                            const value = Number(step.dataset.step);
	                            if (value !== expected) {
	                                step.classList.add("is-wrong");
	                                window.setTimeout(function() { resetSequence("Start again with " + requiredValues[0] + "."); }, 260);
	                                return;
	                            }
	                            step.classList.add("is-complete");
	                            expected++;
	                            status.innerText = expected > steps.length ? "Sequence complete." : "Now select " + requiredValues[expected - 1] + ".";
	                            if (expected > steps.length) {
	                                const duration = Date.now() - interactionStartedAt;
	                                if (duration < 450) {
	                                    window.setTimeout(function() { resetSequence("Try the sequence a little more steadily."); }, 260);
	                                    return;
	                                }
	                                submitProof(duration, steps.length, 100);
	                            }
	                        });
	                    });
	                }

	                if (method === "match") {
	                    const control = document.getElementById("interactive-match-control");
	                    const options = Array.from(control.querySelectorAll("[data-match]"));
	                    options.forEach(function(option) {
	                        option.addEventListener("click", function() {
	                            beginInteraction();
	                            if (option.dataset.match !== "true") {
	                                option.classList.add("is-wrong");
	                                status.innerText = "Choose the matching symbol.";
	                                window.setTimeout(function() { option.classList.remove("is-wrong"); }, 300);
	                                return;
	                            }
	                            const duration = Math.min(30000, Date.now() - pageOpenedAt);
	                            if (duration < 250) {
	                                status.innerText = "Take a moment, then try again.";
	                                return;
	                            }
	                            option.classList.add("is-complete");
	                            submitProof(duration, 1, 100);
	                        });
	                    });
	                }
	            })();
	        </script>
	    `, title, instruction, actionURL, style, issuedToken, control)
}

func interactiveVariantContent(style string, issuedToken string) (string, string, string) {
	switch style {
	case InteractiveStyleClick:
		return "Confirm you are human",
			"Select the verification checkbox to continue.",
			`<button type="button" id="interactive-click-button" class="challenge-click-button" aria-describedby="interactive-help">
	                <span class="challenge-click-check" aria-hidden="true"></span>
	                <span class="challenge-click-copy">
	                    <strong>Verify you are human</strong>
	                    <small>Click to continue</small>
	                </span>
	                <span class="challenge-click-brand" aria-hidden="true">AEGIS</span>
	            </button>`
	case InteractiveStyleSlide:
		return "Complete the security check",
			"Move the slider all the way to the right.",
			`<div id="interactive-slide-control" class="challenge-slide-control" role="slider" tabindex="0" aria-label="Slide to verify" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0" aria-describedby="interactive-help">
	                <span class="challenge-slide-fill" aria-hidden="true"></span>
	                <span class="challenge-slide-thumb" aria-hidden="true">
	                    <svg viewBox="0 0 24 24"><path d="m9 6 6 6-6 6"></path></svg>
	                </span>
	                <span class="challenge-slide-copy">Slide to verify</span>
	                <span class="challenge-slide-end" aria-hidden="true">
	                    <svg viewBox="0 0 24 24"><path d="m7 12 3 3 7-7"></path></svg>
	                </span>
	            </div>`
	case InteractiveStyleSequence:
		numbers, buttonOrder := interactiveNumberChallenge(issuedToken)
		choices := ""
		for _, sequenceIndex := range buttonOrder {
			number := numbers[sequenceIndex]
			choices += fmt.Sprintf(
				`<button type="button" data-step="%d" data-value="%d" aria-label="Number %d, sequence step %d">%d</button>`,
				sequenceIndex+1,
				number,
				number,
				sequenceIndex+1,
				number,
			)
		}
		return "Complete the sequence",
			"Select the checkpoints in the order shown.",
			fmt.Sprintf(`<div id="interactive-sequence-control" class="challenge-sequence-control" data-sequence="%d,%d,%d" aria-describedby="interactive-help">
	                <span class="challenge-sequence-label">Select %d → %d → %d</span>
	                <span class="challenge-sequence-steps">
	                    %s
	                </span>
	            </div>`, numbers[0], numbers[1], numbers[2], numbers[0], numbers[1], numbers[2], choices)
	case InteractiveStyleMatch:
		symbols, targetIndex, buttonOrder := interactiveSymbolChallenge(issuedToken)
		choices := ""
		for _, symbolIndex := range buttonOrder {
			symbol := symbols[symbolIndex]
			choices += fmt.Sprintf(
				`<button type="button" data-match="%t" aria-label="Select %s">%s</button>`,
				symbolIndex == targetIndex,
				symbol.Name,
				symbol.Glyph,
			)
		}
		target := symbols[targetIndex]
		return "Match the symbol",
			"Select the symbol shown in the target.",
			fmt.Sprintf(`<div id="interactive-match-control" class="challenge-match-control" aria-describedby="interactive-help">
	                <span class="challenge-match-prompt">Target <strong aria-label="Target symbol: %s">%s</strong></span>
	                <span class="challenge-match-options">%s</span>
	            </div>`, target.Name, target.Glyph, choices)
	default:
		return "", "", ""
	}
}
