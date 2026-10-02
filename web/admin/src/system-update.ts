/**
 * System Software Update & Notification Engine
 * Source of truth: web/admin/src/system-update.ts
 * Runtime output: web/admin/dist/js/system-update.js
 */

import { api } from './api.js';
import * as AdminDOM from './core/dom.js';
import * as AdminEvents from './core/events.js';
import { SectionUI } from './sections/ui-components.js';

export interface SystemUpdateStatus {
  current_version: string;
  latest_version: string;
  update_available: boolean;
  notify: boolean;
  severity: 'critical' | 'recommended' | 'info';
  release_date?: string;
  title?: string;
  highlights?: string[];
  download_url?: string;
  changelog_url?: string;
  channel: string;
  current_channel?: string;
  target_tier?: string;
  is_tier_upgrade?: boolean;
  checked_at: string;
  updater_configured: boolean;
  error?: string;
}

const UPDATE_DISMISS_KEY = 'aegis-update-dismissed-ver';
let currentUpdateStatus: SystemUpdateStatus | null = null;
let updateBannerBound = false;

// Monochrome SVG icon definitions (strict zero-emoji & zero-color policy)
const updateIcons = {
  arrowUpCircle: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><polyline points="16 12 12 8 8 12"/><line x1="12" y1="16" x2="12" y2="8"/></svg>',
  shieldCheck: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>',
  check: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>',
  refreshCw: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>',
  externalLink: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>',
  x: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
  arrowRight: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>',
};

function escapeHtml(str: string): string {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Fetch update status from the backend API.
 */
export async function checkSystemUpdates(force = false): Promise<SystemUpdateStatus | null> {
  try {
    const url = force ? 'system/update/check?force=true' : 'system/update/check';
    const res = await api.get<SystemUpdateStatus>(url);
    if (res && res.current_version) {
      currentUpdateStatus = res;
      return res;
    }
  } catch (err) {
    console.debug('[SystemUpdate] Update check skipped or failed:', err);
  }
  return null;
}

/**
 * Initialize system update watcher on dashboard load.
 */
export async function initSystemUpdateChecker(): Promise<void> {
  bindUpdateBannerEvents();
  const status = await checkSystemUpdates();
  if (status) {
    renderUpdateBanner(status);
  }
}

/**
 * Render or hide the top notification banner.
 */
export function renderUpdateBanner(status: SystemUpdateStatus): void {
  const container = AdminDOM.getById('system-update-banner');
  if (!container) return;

  if (!status.update_available || !status.notify) {
    container.classList.add('hidden');
    container.innerHTML = '';
    return;
  }

  // Check if dismissed (unless severity is critical)
  const dismissedVer = localStorage.getItem(UPDATE_DISMISS_KEY);
  if (status.severity !== 'critical' && dismissedVer === `${status.channel}:${status.latest_version}`) {
    container.classList.add('hidden');
    return;
  }

  const isCritical = status.severity === 'critical';
  const isTierUpgrade = Boolean(status.is_tier_upgrade || (status.channel && status.current_channel && status.channel.toLowerCase() !== status.current_channel.toLowerCase()));
  const severityLabel = isTierUpgrade ? 'Edition Upgrade Ready' : (isCritical ? 'Critical Security Update' : 'Update Available');
  const severityPillClass = isCritical ? 'update-pill-critical' : 'update-pill-recommended';

  container.className = `system-update-banner ${isCritical ? 'is-critical' : ''}`;
  container.innerHTML = `
    <div class="update-banner-content">
      <div class="update-banner-left">
        <span class="update-banner-icon" aria-hidden="true">${updateIcons.arrowUpCircle}</span>
        <span class="update-banner-title">${severityLabel}:</span>
        <span class="update-banner-version">Aegis ${escapeHtml(status.latest_version)}</span>
        <span class="update-banner-pill ${severityPillClass}">${escapeHtml(status.channel)}</span>
      </div>
      <div class="update-banner-actions">
        <button type="button" class="btn btn-sm btn-primary update-action-btn" data-action="review-system-update">
          Review &amp; update
        </button>
        <button type="button" class="update-banner-dismiss" data-action="dismiss-system-update" title="Dismiss notification" aria-label="Dismiss notification">
          ${updateIcons.x}
        </button>
      </div>
    </div>
  `;
  container.classList.remove('hidden');
}

/**
 * Dismiss the update notification for this version.
 */
export function dismissSystemUpdate(): void {
  if (currentUpdateStatus?.latest_version) {
    localStorage.setItem(UPDATE_DISMISS_KEY, `${currentUpdateStatus.channel}:${currentUpdateStatus.latest_version}`);
  }
  const container = AdminDOM.getById('system-update-banner');
  if (container) {
    container.classList.add('hidden');
  }
}

/**
 * Open the dedicated Software Update modal.
 */
export function openSystemUpdateModal(overrideStatus?: SystemUpdateStatus): void {
  const status = overrideStatus || currentUpdateStatus;
  if (!status) {
    return;
  }

  const isTierUpgrade = Boolean(status.is_tier_upgrade || (status.channel && status.current_channel && status.channel.toLowerCase() !== status.current_channel.toLowerCase()));
  const isCommunity = !isTierUpgrade && (!status.channel || status.channel.toLowerCase() === 'community');

  const highlightsHtml = (status.highlights && status.highlights.length > 0)
    ? `<ul class="update-modal-highlights">
        ${status.highlights.map(h => `<li>${escapeHtml(h)}</li>`).join('')}
       </ul>`
    : `<p class="update-modal-desc">${isTierUpgrade ? 'Upgrade ready to activate commercial capabilities on this installation.' : 'This release includes stability, performance, and security enhancements.'}</p>`;

  const changelogLink = status.changelog_url
    ? `<a href="${escapeHtml(status.changelog_url)}" target="_blank" rel="noopener noreferrer" class="update-modal-link">
         View release details on GitHub <span class="link-icon">${updateIcons.externalLink}</span>
       </a>`
    : '';

  const modalHtml = `
    <div class="section-confirm-head update-modal-head">
      <div class="section-confirm-icon update-modal-icon">
        ${updateIcons.arrowUpCircle}
      </div>
      <div class="section-confirm-title-block">
        <h3 class="section-confirm-title">${isTierUpgrade ? 'Aegis Edition Upgrade' : 'Software Update'}</h3>
        <p class="section-confirm-sub">${isTierUpgrade ? 'Review licensed capabilities and transition this node to the commercial edition.' : 'Review release highlights and apply the update to this installation.'}</p>
      </div>
      <button type="button" class="section-confirm-close" data-section-action="close-modal" aria-label="Close dialog">${updateIcons.x}</button>
    </div>

    <div class="section-confirm-body update-modal-body">
      <!-- Version Matrix -->
      <div class="update-version-grid">
        <div class="update-version-card">
          <span class="update-version-label">${isTierUpgrade ? 'Current edition' : 'Current version'}</span>
          <span class="update-version-val">${escapeHtml(status.current_version)}</span>
          ${status.current_channel ? `<span class="update-version-tag">${escapeHtml(status.current_channel)}</span>` : ''}
        </div>
        <div class="update-version-arrow" aria-hidden="true">
          ${updateIcons.arrowRight}
        </div>
        <div class="update-version-card is-target">
          <span class="update-version-label">${isTierUpgrade ? 'Target edition' : 'Available version'}</span>
          <span class="update-version-val">${escapeHtml(status.latest_version)}</span>
          <span class="update-version-tag">${escapeHtml(status.channel || status.target_tier || 'commercial')}</span>
        </div>
      </div>

      <!-- Release Summary -->
      <div class="update-release-card">
        <div class="update-release-header">
          <span class="update-release-title">${escapeHtml(status.title || (isTierUpgrade ? `Aegis ${status.channel} Upgrade` : `Aegis ${status.latest_version}`))}</span>
          ${status.release_date ? `<span class="update-release-date">Released: ${escapeHtml(status.release_date)}</span>` : ''}
        </div>
        ${highlightsHtml}
        ${changelogLink}
      </div>

      <!-- Safety Checklist & Instructions -->
      <div class="update-safety-box">
        <div class="update-safety-title">${isCommunity ? 'Upgrade Instructions (Community Edition)' : (isTierUpgrade ? 'Commercial Tier Upgrade Guarantees' : 'Operational Guarantees')}</div>
        <div class="update-safety-item">
          <span class="update-safety-check">${updateIcons.check}</span>
          <span>${isCommunity ? 'Docker Deployments: Run <code>docker compose pull &amp;&amp; docker compose up -d</code>.' : 'Configuration (<code>/etc/aegis/config.yaml</code>) remains preserved and valid.'}</span>
        </div>
        <div class="update-safety-item">
          <span class="update-safety-check">${updateIcons.check}</span>
          <span>${isCommunity ? 'Linux Host Deployments: Download the release binary from GitHub and restart the <code>aegis</code> service.' : 'Custom WAF rules, SSL certificates, and threat data remain untouched.'}</span>
        </div>
        <div class="update-safety-item">
          <span class="update-safety-check">${updateIcons.check}</span>
          <span>${isCommunity ? 'Configurations (<code>/etc/aegis/config.yaml</code>), custom rules, and data remain preserved.' : 'Automatic rollback triggers if health validation fails on startup.'}</span>
        </div>
      </div>

      ${(!isCommunity && !status.updater_configured) ? `
        <div class="update-daemon-note" style="margin-top: 12px; padding: 10px 12px; border-radius: 6px; background: rgba(249, 115, 22, 0.08); border: 1px solid rgba(249, 115, 22, 0.25); font-size: 0.8rem; line-height: 1.4; color: var(--text-main, #f3f4f6);">
          <strong>Note:</strong> Automated updater daemon (<code>aegis-updater</code>) is not connected. To upgrade this installation:
          <ul style="margin: 6px 0 0 16px; padding: 0;">
            <li><strong>Docker:</strong> Update container image to the commercial release image (e.g. <code>aegis-${escapeHtml((status.channel || 'pro').toLowerCase())}:${escapeHtml(status.latest_version)}</code>) and run <code>docker compose up -d</code>.</li>
            <li><strong>Linux host:</strong> Replace the binary with the ${escapeHtml(status.channel || 'commercial')} release and run <code>systemctl restart aegis</code>.</li>
          </ul>
        </div>
      ` : ''}

      <!-- Progress area (hidden initially) -->
      <div id="update-progress-container" class="update-progress-container hidden">
        <div class="update-progress-spinner"></div>
        <div class="update-progress-status" id="update-progress-status">Dispatching update to aegis-updater...</div>
      </div>
    </div>

    <div class="section-confirm-footer update-modal-footer">
      <button type="button" class="btn btn-outline section-confirm-cancel" data-section-action="close-modal" id="update-cancel-btn">${isCommunity || !status.updater_configured ? 'Close' : 'Cancel'}</button>
      ${isCommunity
        ? `<a href="${escapeHtml(status.changelog_url || 'https://github.com/divinelabio/aegis/releases')}" target="_blank" rel="noopener noreferrer" class="btn btn-primary" id="update-github-link">
             View Release on GitHub <span class="link-icon">${updateIcons.externalLink}</span>
           </a>`
        : (status.updater_configured
            ? `<button type="button" class="btn btn-primary" id="update-apply-btn">
                 ${isTierUpgrade ? 'Upgrade &amp; restart Aegis' : 'Install &amp; restart Aegis'}
               </button>`
            : `<a href="${escapeHtml(status.changelog_url || 'https://github.com/divinelabio/aegis/releases')}" target="_blank" rel="noopener noreferrer" class="btn btn-primary" id="update-github-link">
                 View Release Artifacts <span class="link-icon">${updateIcons.externalLink}</span>
               </a>`
          )}
    </div>
  `;

  SectionUI.showModal(modalHtml, {
    panelClass: 'modal-content update-modal-panel',
    closeOnBackdrop: false,
  });

  const applyBtn = AdminDOM.getById<HTMLButtonElement>('update-apply-btn');
  const cancelBtn = AdminDOM.getById<HTMLButtonElement>('update-cancel-btn');
  if (applyBtn) {
    applyBtn.addEventListener('click', () => {
      void runSystemUpdateExecution(status, applyBtn, cancelBtn);
    });
  }
}

/**
 * Executes the update call to the backend and coordinates restart polling.
 */
async function runSystemUpdateExecution(
  status: SystemUpdateStatus,
  applyBtn: HTMLButtonElement,
  cancelBtn: HTMLButtonElement | null
): Promise<void> {
  const progressContainer = AdminDOM.getById('update-progress-container');
  const progressStatus = AdminDOM.getById('update-progress-status');

  applyBtn.disabled = true;
  if (cancelBtn) cancelBtn.disabled = true;
  if (progressContainer) progressContainer.classList.remove('hidden');

  if (progressStatus) {
    progressStatus.textContent = 'Connecting to aegis-updater daemon...';
  }

  try {
    const res = await api.post<{ ok: boolean; message?: string; error?: string; status?: { job_id?: string; state: string } }>('system/update/apply', {
      version: status.latest_version,
    });

    if (res && typeof res === 'object' && res.ok) {
      if (progressStatus) {
        progressStatus.textContent = 'Upgrade queued. Downloading and verifying the release...';
      }
      const jobId = res.status?.job_id;
      const deadline = Date.now() + 16 * 60 * 1000;
      while (Date.now() < deadline) {
        await new Promise(resolve => setTimeout(resolve, 2000));
        // A restart can interrupt polling. The job continues in the updater.
        let job: { available: boolean; status?: { job_id?: string; state: string; last_error?: string } } | null = null;
        try { job = await api.post('license/updater-status'); } catch { /* reconnect on the next poll */ }
        if (!job?.available || !job.status) {
          if (progressStatus) progressStatus.textContent = 'Aegis is restarting. Reconnecting...';
          continue;
        }
        if (jobId && job.status.job_id !== jobId) throw new Error('The updater job changed. Refresh the page to review its status.');
        if (job.status.state === 'active') {
          if (progressStatus) progressStatus.textContent = 'Upgrade verified successfully. Reloading...';
          window.location.reload();
          return;
        }
        if (['failed', 'rolled_back'].includes(job.status.state)) throw new Error(job.status.last_error || 'Upgrade failed; the previous release was restored.');
        if (progressStatus) progressStatus.textContent = `Upgrade in progress: ${job.status.state.replace(/_/g, ' ')}...`;
      }
      throw new Error('The updater is still busy or unreachable. Review its status before retrying.');
    } else {
      const errMsg = (res && typeof res === 'object') ? (res.error || res.message) : 'Update failed to apply.';
      throw new Error(errMsg || 'Update failed to apply.');
    }
  } catch (err: any) {
    if (progressStatus) {
      progressStatus.textContent = `${err?.message || 'Upgrade failed'}`;
      progressStatus.classList.add('text-danger');
    }
    applyBtn.disabled = false;
    if (cancelBtn) cancelBtn.disabled = false;
  }
}

/**
 * Event delegation for top banner actions.
 */
function bindUpdateBannerEvents(): void {
  if (updateBannerBound) return;
  updateBannerBound = true;

  AdminEvents.delegateEvent<HTMLElement>(document, 'click', '[data-action]', (e, target) => {
    const action = target.getAttribute('data-action');
    if (action === 'review-system-update') {
      e.preventDefault();
      openSystemUpdateModal();
    } else if (action === 'dismiss-system-update') {
      e.preventDefault();
      dismissSystemUpdate();
    }
  });
}
