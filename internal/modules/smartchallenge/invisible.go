package smartchallenge

import "fmt"

func renderInvisibleChallengeBody(saltToken string, difficulty int) string {
	return fmt.Sprintf(`
        <div class="spinner"></div>
        <h1 id="challenge-title">Verifying your request</h1>
        <p>This check runs in the background and should finish in a moment.</p>
        <div id="status" class="status status-live" role="status" aria-live="polite">Running background verification</div>
        <script>
            (async function() {
                const salt = "%s";
                const difficulty = %d;
                const status = document.getElementById("status");

                function collectSignals() {
                    return JSON.stringify({
                        userAgent: navigator.userAgent,
                        platform: navigator.platform,
                        language: navigator.language || '',
                        languages: navigator.languages ? navigator.languages.join(',') : '',
                        webdriver: !!navigator.webdriver,
                        webdriver_lie: (navigator.webdriver === false || navigator.webdriver === undefined) && Object.getOwnPropertyDescriptor(navigator.__proto__, 'webdriver') !== undefined,
                        plugins_len: navigator.plugins ? navigator.plugins.length : 0,
                        screen: [screen.width, screen.height, screen.colorDepth, window.outerWidth, window.outerHeight].join('x'),
                        headless: !!(navigator.webdriver || (window.chrome && window.chrome.runtime === undefined))
                    });
                }

                async function solvePoW(boundSalt, diff) {
                    const encoder = new TextEncoder();
                    const prefix = "0".repeat(diff);
                    let nonce = 0;
                    while (true) {
                        const data = encoder.encode(boundSalt + nonce);
                        const hashBuf = await crypto.subtle.digest("SHA-256", data);
                        const hashArr = Array.from(new Uint8Array(hashBuf));
                        const hashHex = hashArr.map((b) => b.toString(16).padStart(2, '0')).join('');
                        if (hashHex.startsWith(prefix)) return String(nonce);
                        nonce += 1;
                        if (nonce %% 3000 === 0) {
                            await new Promise((resolve) => setTimeout(resolve, 0));
                        }
                    }
                }

	                try {
	                    const nonce = await solvePoW(salt, difficulty);
	                    const form = new FormData();
	                    form.append("aegis_challenge_submission", "1");
	                    form.append("challenge_type", "invisible_challenge");
                    form.append("pow_salt", salt);
                    form.append("pow_nonce", nonce);
                    form.append("signals", collectSignals());

                    const response = await fetch(window.location.href, {
                        method: "POST",
                        body: form
                    });

                    if (response.redirected) {
                        window.location.href = response.url;
                        return;
                    }
                    if (response.ok) {
                        window.location.reload();
                        return;
                    }
                    status.innerText = "Background verification failed. Please retry.";
                    status.classList.add("is-error");
                } catch (error) {
                    status.innerText = "Verification could not be completed. Please retry.";
                    status.classList.add("is-error");
                }
            })();
        </script>
    `, saltToken, difficulty)
}
