import { SectionUI } from '../ui-components.js';
import { renderHTTPSecuritySaveButtons } from '../httpsecurity-render-helpers.js';
import { escapeHTTPSecurityHtml } from '../httpsecurity-runtime-helpers.js';
import { HTTPSEC_COOKIE_PROFILES, HTTPSEC_RESPONSE_PROFILES } from './constants.js';
import { renderHeaderMapBuilder, renderHeaderRemoveBuilder } from './controls/header-builder.js';
import { renderCSPBuilder } from './controls/csp-builder.js';
import { renderPermissionsPolicyBuilder } from './controls/permissions-policy-builder.js';

type HTTPSecurityRenderRuntime = Record<string, any>;

function encodeHTTPSecurityValue(value: unknown): string {
    return encodeURIComponent(String(value));
}

function renderToggleCard(view: HTTPSecurityRenderRuntime, title: any, desc: any, active: any, path: any, icon: any): string {

        const iconSvg = view.icons[icon] || view.icons.shield;
        return SectionUI.renderOperatorControlRow({
            title,
            description: desc,
            icon: iconSvg,
            enabled: active,
            actions: `<label class="section-switch section-policy-toggle-switch" title="${active ? 'Disable' : 'Enable'} ${title}">
                    <input type="checkbox" ${active ? 'checked' : ''} data-httpsec-path="${path}" data-httpsec-value-type="checkbox" data-httpsec-render="true">
                    <span class="switch-slider"></span>
                </label>`,
            className: 'httpsec-inline-toggle'
        });
}

function renderSecurityTxtCard(view: HTTPSecurityRenderRuntime): string {
        const capability = view.capability?.('security_txt');
        const available = capability?.status === 'available' && capability?.runtime_implemented === true;
        if (!available) return '';

        const contact = view.viewModel?.responseProtection?.securityTxt?.contact || '';
        const hasContact = available && contact.trim() !== '';
		const verification = view.securityTxtVerification || {};
		const published = hasContact && verification.status === 'published';
		const checking = hasContact && verification.status === 'checking';
		const statusLabel = published ? 'Published' : checking ? 'Checking' : hasContact ? 'Needs attention' : 'Missing';
		const statusTone = published ? 'success' : checking ? 'warning' : 'danger';
        const contactPreview = hasContact ? contact.trim() : 'Not configured';
        return `
        <section class="operator-control-panel httpsec-securitytxt-card ${published ? 'is-active' : ''}">
            ${SectionUI.renderOperatorControlRow({
                title: 'Security.txt',
                description: 'RFC 9116 disclosure contact for vulnerability reporters.',
                icon: view.icons.file,
				enabled: published,
				actions: '<span class="httpsec-endpoint-chip text-mono">/.well-known/security.txt</span>',
                className: 'httpsec-control-head'
            })}

            <div class="operator-control-panel-body httpsec-securitytxt-body">
                <div class="httpsec-securitytxt-form">
					<label class="text-uc text-note font-600" for="httpsec-securitytxt-contact">Contact email or HTTPS URL</label>
                    <div class="httpsec-securitytxt-input-row">
						<input type="text"
                               id="httpsec-securitytxt-contact"
                               value="${escapeHTTPSecurityHtml(contact)}"
                               placeholder="security@example.com"
							   class="section-input text-mono"
							   inputmode="email"
							   autocomplete="email"
							   spellcheck="false"
							   aria-describedby="httpsec-securitytxt-help">
						<button type="button" class="operator-btn operator-btn-primary" data-httpsec-action="save-securitytxt">Save Changes</button>
                    </div>
					<div id="httpsec-securitytxt-help" class="text-xs text-note">Publishes an RFC 9116 contact at the standard public path. Clear the field and save to remove it.</div>
                </div>

				<div class="httpsec-securitytxt-preview" aria-live="polite">
                    <div class="httpsec-securitytxt-preview-row">
                        <span>Contact</span>
                        <strong class="text-mono">${escapeHTTPSecurityHtml(contactPreview)}</strong>
                    </div>
                    <div class="httpsec-securitytxt-preview-row">
						<span>Publication</span>
						<strong>${escapeHTTPSecurityHtml(String(verification.message || 'Verification has not run yet.'))}</strong>
                    </div>
					${hasContact && !checking ? `<button type="button" class="operator-btn operator-btn-secondary" data-httpsec-action="verify-securitytxt">Verify public file</button>` : ''}
                </div>
            </div>
        </section>
        `;
}

export function renderHTTPSecurityResponseProtection(runtime: HTTPSecurityRenderRuntime): string {
    const view = runtime;
        const responseProtection = view.viewModel?.responseProtection || {};
        const sh = responseProtection.securityHeaders || {};
        const ih = responseProtection.infoHiding || {};
        const ch = responseProtection.cookieHardener || {};
        const hm = responseProtection.headerManager || {};
        const hasHeaderManager = view.canConfigure('header_manager');
        const xfoCurrent = sh.x_frame_options || '';
        const hstsCurrent = sh.hsts || '';
        const sniffCurrent = sh.x_content_type_options || '';
        const referrerOptions = [
            { val: 'strict-origin-when-cross-origin', label: 'Balanced privacy' },
            { val: 'no-referrer', label: 'Maximum privacy' },
            { val: 'same-origin', label: 'Same-site only' },
            { val: 'origin', label: 'Share origin only' },
            { val: '', label: 'Do not enforce' }
        ];
        const referrerCurrent = sh.referrer_policy || '';
        const referrerLabel = referrerOptions.find((option: any) => option.val === referrerCurrent)?.label || 'Do not enforce';
        const sameSiteOptions = [
            { val: 'Lax', label: 'Lax', desc: 'Recommended default', color: 'var(--primary)' },
            { val: 'Strict', label: 'Strict', desc: 'Only same-site requests', color: 'var(--success)' },
            { val: 'None', label: 'None', desc: 'All requests (requires Secure)', color: 'var(--warning, #f97316)' },
            { val: '', label: "Don't force", desc: 'Use original cookie value', color: 'var(--text-muted)' }
        ];
        const sameSiteCurrent = ch.force_samesite ?? 'Lax';
        const responseProfile = view.getResponseProfile();
        const cookieProfile = view.getCookieProfile();
        const responseHeaderRules = hasHeaderManager ? Object.keys(hm.add_response_headers || {}).length + (hm.remove_response_headers || []).length : 0;
        const browserHeaderCount = [sh.x_frame_options, sh.hsts, sh.x_content_type_options, sh.csp, sh.permissions_policy, sh.referrer_policy].filter(Boolean).length;
        const cookieFlags = [ch.force_secure, ch.force_httponly, sameSiteCurrent].filter(Boolean).length;
        const hiddenHeaders = ih.strip_headers || [];
        const securityTxtAvailable = view.capability?.('security_txt')?.status === 'available' && view.capability?.('security_txt')?.runtime_implemented === true;
		const securityTxtReady = securityTxtAvailable && String(responseProtection.securityTxt?.contact || '').trim() !== '' && view.securityTxtVerification?.status === 'published';
        const modeCard = (active: any, title: any, desc: any, attrs: any) => `
            <button type="button" class="httpsec-mode-card ${active ? 'is-active' : ''}" ${attrs}>
                <span class="httpsec-choice-check">${view.icons.check}</span>
                <strong>${title}</strong>
                <small>${desc}</small>
            </button>`;
        const statusPill = (enabled: any, on: any = 'Active', off: any = 'Off') => `<span class="config-status-pill tone-${enabled ? 'success' : 'neutral'}">${enabled ? on : off}</span>`;
        const policyRow = (key: any, title: any, description: any, icon: any, enabled: any, content: any, titleHeadingLevel: 2 | 3 | 4 | 5 | 6 = 3) => SectionUI.renderOperatorControlRow({
            title,
            description,
            icon: view.icons[icon] || view.icons.shield,
            enabled,
            titleHeadingLevel,
            actions: `<label class="section-switch section-policy-toggle-switch" title="${enabled ? 'Disable' : 'Enable'} ${title}"><input type="checkbox" ${enabled ? 'checked' : ''} data-httpsec-path="${key}.enabled" data-httpsec-value-type="checkbox" data-httpsec-render="true"><span class="switch-slider"></span></label>`,
            content,
            className: 'httpsec-response-overview-row'
        });
        const browserContent = `
            <section class="httpsec-browser-posture">
                <div class="httpsec-browser-posture-copy">
                    <span class="httpsec-browser-posture-label">Active posture</span>
                    <strong>${HTTPSEC_RESPONSE_PROFILES[responseProfile.id]?.label || 'Custom'}</strong>
                    <small>${HTTPSEC_RESPONSE_PROFILES[responseProfile.id]?.note || 'Individual browser header settings are in use.'}</small>
                </div>
                <label class="httpsec-browser-profile-field">
                    <span>Protection posture</span>
                    <select data-httpsec-profile-select="response" aria-label="Browser protection posture">
                        ${Object.entries(HTTPSEC_RESPONSE_PROFILES).map(([id, profile]: [string, any]) => `<option value="${id}" ${responseProfile.id === id ? 'selected' : ''}>${profile.label}</option>`).join('')}
                    </select>
                </label>
            </section>
            <div class="httpsec-browser-policy-grid">
                <label class="httpsec-browser-policy-field">
                    <span>Frame protection</span>
                    <small>Mitigate clickjacking by restricting other websites from embedding your app in iframes.</small>
                    <select data-httpsec-path="security_headers.x_frame_options" data-httpsec-value-type="string" data-httpsec-render="true">
                        <option value="" ${xfoCurrent === '' ? 'selected' : ''}>Do not restrict framing</option>
                        <option value="SAMEORIGIN" ${xfoCurrent === 'SAMEORIGIN' ? 'selected' : ''}>Same-origin only</option>
                        <option value="DENY" ${xfoCurrent === 'DENY' ? 'selected' : ''}>Block all framing</option>
                    </select>
                </label>
                <label class="httpsec-browser-policy-field">
                    <span>HTTPS enforcement</span>
                    <small>Instruct browsers to strictly communicate over HTTPS for the specified duration (HSTS).</small>
                    <select data-httpsec-path="security_headers.hsts" data-httpsec-value-type="string" data-httpsec-render="true">
                        <option value="" ${hstsCurrent === '' ? 'selected' : ''}>Do not send HSTS</option>
                        <option value="max-age=31536000; includeSubDomains" ${hstsCurrent === 'max-age=31536000; includeSubDomains' ? 'selected' : ''}>Recommended — 1 year with subdomains (HTTPS only)</option>
                        <option value="max-age=63072000; includeSubDomains; preload" ${hstsCurrent === 'max-age=63072000; includeSubDomains; preload' ? 'selected' : ''}>Strict — preload ready (HTTPS only)</option>
                    </select>
                </label>
                ${SectionUI.renderOperatorControlRow({
                    title: 'MIME type protection',
                    description: 'Send X-Content-Type-Options: nosniff to prevent browsers from executing non-script MIME types as executable code.',
                    icon: view.icons.shield,
                    enabled: sniffCurrent === 'nosniff',
                    actions: `<select class="httpsec-browser-inline-select" data-httpsec-path="security_headers.x_content_type_options" data-httpsec-value-type="string" data-httpsec-render="true" aria-label="MIME type protection"><option value="" ${sniffCurrent === '' ? 'selected' : ''}>Allow browser guessing</option><option value="nosniff" ${sniffCurrent === 'nosniff' ? 'selected' : ''}>Block file guessing</option></select>`,
                    className: 'httpsec-browser-mime-row'
                })}
            </div>
            <details class="httpsec-advanced-details httpsec-browser-builders">
                <summary><span>Advanced browser policy builders</span><small>Configure resource origins and browser capabilities with structured controls.</small></summary>
                <div class="httpsec-browser-builder-grid">
                    ${renderCSPBuilder(sh.csp || '')}
                    ${renderPermissionsPolicyBuilder(sh.permissions_policy || '')}
                </div>
                <details class="httpsec-advanced-details httpsec-browser-raw-values">
                    <summary>Raw browser policy values</summary>
                    <div class="httpsec-response-field-grid httpsec-response-field-grid-2 mt-12">
                        <label class="bot-overview-field"><span>Raw CSP</span><textarea rows="3" data-httpsec-path="security_headers.csp" data-httpsec-value-type="string" data-httpsec-render="true">${escapeHTTPSecurityHtml(sh.csp || '')}</textarea></label>
                        <label class="bot-overview-field"><span>Raw Permissions Policy</span><textarea rows="3" data-httpsec-path="security_headers.permissions_policy" data-httpsec-value-type="string" data-httpsec-render="true">${escapeHTTPSecurityHtml(sh.permissions_policy || '')}</textarea></label>
                    </div>
                </details>
            </details>
        `;
        const privacyContent = `
            <div class="httpsec-privacy-workspace">
                <section class="httpsec-privacy-surface httpsec-privacy-disclosure-surface">
                    <div class="httpsec-privacy-surface-head">
                        <span class="operator-control-icon">${view.icons.globe}</span>
                        <div><strong>Outbound disclosure</strong><span>Control how much referring-page URL context browsers share with external origins.</span></div>
                    </div>
                    <div class="httpsec-privacy-disclosure-grid">
                        <label class="httpsec-privacy-policy-field">
                            <span>Referrer policy</span>
                            <small>Current posture: ${referrerLabel}</small>
                            <select data-httpsec-path="security_headers.referrer_policy" data-httpsec-value-type="string" data-httpsec-render="true">${referrerOptions.map((o: any) => `<option value="${o.val}" ${referrerCurrent === o.val ? 'selected' : ''}>${o.label}</option>`).join('')}</select>
                        </label>
                        <div class="httpsec-privacy-hidden-summary">
                            <span>Server disclosure</span>
                            <strong>${hiddenHeaders.length} header${hiddenHeaders.length === 1 ? '' : 's'} hidden</strong>
                            <small>${hiddenHeaders.length ? 'Identity headers are removed before responses leave the edge.' : 'No server identity headers are currently suppressed.'}</small>
                        </div>
                    </div>
                </section>
                <section class="httpsec-privacy-surface httpsec-privacy-headers-surface">
                    <div class="httpsec-privacy-surface-head">
                        <span class="operator-control-icon">${view.icons.eye}</span>
                        <div><strong>Server identity headers</strong><span>Remove technology fingerprinting headers (Server, X-Powered-By) to prevent infrastructure reconnaissance.</span></div>
                    </div>
                    <div class="httpsec-privacy-header-editor">
                        <div class="httpsec-extension-grid">
                            ${hiddenHeaders.map((h: any) => `<button class="httpsec-extension-chip" type="button" data-httpsec-action="remove-tag" data-httpsec-path="info_hiding.strip_headers" data-httpsec-value="${encodeHTTPSecurityValue(h)}"><span>${escapeHTTPSecurityHtml(h)}</span><span class="httpsec-extension-remove" aria-hidden="true">&times;</span></button>`).join('') || '<div class="httpsec-empty-note">No server identity headers are hidden yet.</div>'}
                        </div>
                        <div class="httpsec-privacy-add-row">
                            <label for="strip-hdr-input">Add a response header to suppress</label>
                            <div class="section-inline-form">
                                <input type="text" id="strip-hdr-input" placeholder="X-Powered-By" class="section-input text-mono" data-httpsec-enter-action="add-tag-from-input" data-httpsec-path="info_hiding.strip_headers">
              <button type="button" class="btn btn-outline btn-sm" data-httpsec-action="add-tag-from-input" data-httpsec-path="info_hiding.strip_headers" data-httpsec-input-id="strip-hdr-input">Add header</button>
                            </div>
                        </div>
              ${['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version', 'X-Generator'].filter((h: any) => !hiddenHeaders.includes(h)).length ? `<div class="httpsec-privacy-suggestions"><span>Common headers</span><div class="httpsec-response-chip-row">${['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version', 'X-Generator'].filter((h: any) => !hiddenHeaders.includes(h)).slice(0, 5).map((h: any) => `<button type="button" data-httpsec-action="add-tag" data-httpsec-path="info_hiding.strip_headers" data-httpsec-value="${encodeHTTPSecurityValue(h)}" class="btn btn-outline btn-xs text-mono">${h}</button>`).join('')}</div></div>` : ''}
                    </div>
                </section>
            </div>
        `;
        const cookieContent = `
            <div class="httpsec-mode-cards httpsec-mode-cards-4">
                ${modeCard(cookieProfile.id === 'balanced', HTTPSEC_COOKIE_PROFILES.balanced.label, HTTPSEC_COOKIE_PROFILES.balanced.note, 'data-httpsec-action="apply-cookie-profile" data-httpsec-value="balanced"')}
                ${modeCard(cookieProfile.id === 'strict', HTTPSEC_COOKIE_PROFILES.strict.label, HTTPSEC_COOKIE_PROFILES.strict.note, 'data-httpsec-action="apply-cookie-profile" data-httpsec-value="strict"')}
                ${modeCard(cookieProfile.id === 'preserve', HTTPSEC_COOKIE_PROFILES.preserve.label, HTTPSEC_COOKIE_PROFILES.preserve.note, 'data-httpsec-action="apply-cookie-profile" data-httpsec-value="preserve"')}
                ${modeCard(cookieProfile.id === 'custom', HTTPSEC_COOKIE_PROFILES.custom.label, HTTPSEC_COOKIE_PROFILES.custom.note, 'data-httpsec-action="apply-cookie-profile" data-httpsec-value="custom"')}
            </div>
            <div class="operator-control-list httpsec-response-inline-list">
                ${renderToggleCard(view, 'HTTPS-only cookies', 'Ensure cookies are transmitted only over encrypted TLS connections (Secure flag).', ch.force_secure === true, 'cookie_hardener.force_secure', 'shield')}
                ${renderToggleCard(view, 'Protect from scripts', 'Set the HttpOnly flag to prevent client-side JavaScript (XSS attacks) from reading sensitive session cookies.', ch.force_httponly === true, 'cookie_hardener.force_httponly', 'shield')}
            </div>
            <div class="httpsec-mode-cards httpsec-mode-cards-4">
                ${sameSiteOptions.map((o: any) => modeCard(sameSiteCurrent === o.val, o.label, o.desc, `data-httpsec-action="set-field" data-httpsec-path="cookie_hardener.force_samesite" data-httpsec-value="${encodeHTTPSecurityValue(o.val)}" data-httpsec-render="true"`)).join('')}
            </div>
        `;
        const responseHeaderContent = `
            <div class="httpsec-response-field-grid">
                ${renderHeaderMapBuilder('Add response headers', 'header_manager.add_response_headers', hm.add_response_headers || {}, 'resp-add-header')}
                ${renderHeaderRemoveBuilder('Remove response headers', 'header_manager.remove_response_headers', hm.remove_response_headers || [], 'rm-resp-hdr')}
            </div>
        `;
        const responseAreaRow = (id: string, title: string, description: string, icon: string, enabled: boolean) => SectionUI.renderOperatorControlRow({
            title,
            description,
            icon: view.icons[icon] || view.icons.shield,
            enabled,
            actions: statusPill(enabled),
            className: 'httpsec-response-area-row',
            attrs: `role="button" tabindex="0" data-httpsec-action="open-response-protection-page" data-httpsec-value="${id}"`
        });
        const responseAreas = `
            <div class="operator-control-list httpsec-response-area-list">
                ${responseAreaRow('browser', 'Browser safety', `${browserHeaderCount} configured browser header${browserHeaderCount === 1 ? '' : 's'}`, 'shield', sh.enabled === true)}
                ${responseAreaRow('privacy', 'Privacy controls', hiddenHeaders.length ? `${hiddenHeaders.length} hidden server header${hiddenHeaders.length === 1 ? '' : 's'}` : securityTxtReady ? 'Security.txt published' : 'No hidden headers configured', 'eye', ih.enabled === true)}
                ${responseAreaRow('cookies', 'Cookie safety', `${cookieFlags} cookie flag${cookieFlags === 1 ? '' : 's'} enforced`, 'cookie', ch.enabled === true)}
                ${hasHeaderManager ? responseAreaRow('headers', 'Response headers', responseHeaderRules ? `${responseHeaderRules} configured rule${responseHeaderRules === 1 ? '' : 's'}` : 'Responses are returned unchanged', 'sliders', hm.enabled === true) : ''}
            </div>`;
        const responseHeadersPage = hasHeaderManager ? SectionUI.renderOperatorSection('Response headers', `
            <div class="operator-control-list">${policyRow('header_manager', 'Response header policy', 'Custom changes for special application cases.', 'sliders', hm.enabled === true, responseHeaderContent, 4)}</div>
        `, {
            subtitle: 'Add or remove response headers after upstream responses return.'
        }) : '';
        const responsePages: Record<string, { content: string }> = {
            browser: {
                content: `<div class="operator-control-list">${policyRow('security_headers', 'Browser safety', 'Configure browser-facing security headers.', 'shield', sh.enabled === true, browserContent)}</div>`
            },
            privacy: {
                content: `<div class="operator-control-list">${policyRow('info_hiding', 'Privacy controls', 'Hide server details and limit referral information.', 'eye', ih.enabled === true, privacyContent)}</div>${renderSecurityTxtCard(view)}`
            },
            cookies: {
                content: `<div class="operator-control-list">${policyRow('cookie_hardener', 'Cookie safety', 'Apply protective flags to protected application cookies.', 'cookie', ch.enabled === true, cookieContent)}</div>`
            },
            headers: {
                content: responseHeadersPage
            }
        };
        const selectedPage = responsePages[String(runtime.responseProtectionPage || '')];
        return `
            <div class="httpsec-overview-stack httpsec-response-overview-stack">
                ${selectedPage ? `
                    <header class="httpsec-response-page-header">
                        ${SectionUI.renderOperatorBackButton({
                            label: 'Back to Response Protection',
                            attrs: 'data-httpsec-action="close-response-protection-page"',
                            className: 'httpsec-response-page-back'
                        })}
                    </header>
                    ${selectedPage.content}
                ` : SectionUI.renderOperatorSection('Response protection', responseAreas, {
                    subtitle: 'Choose an area to configure response protections.'
                })}
            </div>

            ${renderHTTPSecuritySaveButtons()}
        `;
}
