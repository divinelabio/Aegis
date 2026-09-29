/**
 * License Activation Feedback Modals
 * Source of truth: web/admin/src/licensing-modal.ts
 */

import { SectionUI } from './sections/ui-components.js';
import { escapeSectionHtml } from './sections/section-runtime-helpers.js';

export interface LicenseModalDetails {
  expiresAt?: string;
  offlineUntil?: string;
  keyPrefix?: string;
  status?: string;
}

interface CapabilityItem {
  title: string;
  desc: string;
}

/**
 * Displays a clean, executive modal when a commercial license is successfully activated.
 * Follows Aegis app UI cleanly without drifting content, neon green, or glow effects.
 */
export function showLicenseCongratulationsModal(tier: string, details?: LicenseModalDetails): void {
  const normalizedTier = (tier || 'professional').toLowerCase();
  const isEnterprise = normalizedTier.includes('enterprise');
  const tierName = isEnterprise ? 'Enterprise' : 'Professional';
  const subtitleText = `Aegis ${tierName} Edition is now active and protecting your workloads.`;

  // Exact commercial capabilities (OWASP CRS is free/community, so omitted; no buzzwords/ML)
  const capabilities: CapabilityItem[] = isEnterprise ? [
    {
      title: 'API Security & Schema Guard',
      desc: 'OpenAPI schema validation and payload protection'
    },
    {
      title: 'Edge Access Control',
      desc: 'Zero-Trust edge identity and JWT enforcement'
    },
    {
      title: 'Enterprise Multi-User & RBAC',
      desc: 'Granular administrator roles and access permissions'
    },
    {
      title: 'Compliance Audit Logging',
      desc: 'Immutable security audit trail and event logging'
    },
    {
      title: 'Enterprise Analytics & Telemetry Export',
      desc: 'Long-term telemetry retention and deep forensic analysis'
    }
  ] : [
    {
      title: 'Anti-Bot Protection',
      desc: 'Client challenges and automated bot mitigation'
    },
    {
      title: 'IP Reputation & Threat Feeds',
      desc: 'Dynamic threat intelligence feeds and reputation-based scoring'
    },
    {
      title: 'Application Flood Protection',
      desc: 'Volumetric rate-shaping and DDoS mitigation'
    },
    {
      title: 'Data Leak Protection',
      desc: 'Outbound sensitive data and secret masking'
    },
    {
      title: 'Upload Protection & Quarantine',
      desc: 'Malicious payload inspection and file quarantine'
    },
    {
      title: 'Body Guard & Policy Rules',
      desc: 'Deep request payload buffering and advanced policies'
    }
  ];

  const content = `
    <div class="license-modal-container" style="text-align: center; padding: 24px 20px 20px; width: 100%; max-width: 460px; margin: 0 auto; box-sizing: border-box;">
      <!-- Shield Header -->
      <div style="width: 58px; height: 58px; margin: 0 auto 14px; border-radius: 50%; background: #181a1f; border: 1px solid rgba(255, 255, 255, 0.1); display: flex; align-items: center; justify-content: center;">
        <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="#f97316" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path d="M9 12l2 2 4-4"/>
        </svg>
      </div>

      <h2 style="font-size: 1.45rem; font-weight: 700; margin: 0 0 6px; color: var(--text-main, #ffffff); letter-spacing: -0.01em;">
        License Activated
      </h2>
      <p style="color: var(--text-muted, #9ca3af); font-size: 0.88rem; margin: 0 0 18px; line-height: 1.45;">
        ${escapeSectionHtml(subtitleText)}
      </p>

      <!-- Clean Vertical List of Unlocked Capabilities -->
      <div style="display: flex; flex-direction: column; gap: 8px; margin-bottom: 22px; width: 100%; box-sizing: border-box;">
        ${capabilities.map(cap => `
          <div style="display: flex; align-items: flex-start; gap: 10px; padding: 9px 12px; background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.07); border-radius: 6px; box-sizing: border-box; text-align: left; width: 100%;">
            <div style="width: 20px; height: 20px; border-radius: 4px; background: rgba(249, 115, 22, 0.12); color: #f97316; display: flex; align-items: center; justify-content: center; flex-shrink: 0; margin-top: 1px;">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="20 6 9 17 4 12"/>
              </svg>
            </div>
            <div style="flex: 1; min-width: 0;">
              <div style="font-size: 0.84rem; font-weight: 600; color: var(--text-main, #f3f4f6); line-height: 1.3;">
                ${escapeSectionHtml(cap.title)}
              </div>
              <div style="font-size: 0.75rem; color: var(--text-muted, #9ca3af); line-height: 1.3; margin-top: 1px;">
                ${escapeSectionHtml(cap.desc)}
              </div>
            </div>
          </div>
        `).join('')}
      </div>

      <!-- Action Button -->
      <button type="button" class="btn btn-primary" data-section-action="close-modal" style="width: 100%; padding: 11px 16px; font-size: 0.92rem; font-weight: 600; border-radius: 6px; cursor: pointer;">
        Go to Console
      </button>
    </div>
  `;

  SectionUI.showModal(content, { panelClass: 'modal-content license-modal-panel', closeOnBackdrop: true });
}

/**
 * Displays an understated, clear modal when license activation fails.
 * Follows Aegis app UI cleanly without drifting content, neon green, or glow effects.
 */
export function showLicenseErrorModal(rawError: string | Error): void {
  const message = typeof rawError === 'string' ? rawError : (rawError?.message || '');
  let friendlyTitle = 'License Activation Failed';
  let friendlyDescription = message || 'The license key could not be verified. Please check the key and try again.';
  const lower = message.toLowerCase();

  if (lower.includes('invalid_license_key') || lower.includes('invalid licence key') || lower.includes('invalid_request') || lower.includes('checksum') || lower.includes('format')) {
    friendlyTitle = 'Invalid License Key';
    friendlyDescription = 'The license key was not recognized or contains a typo. Please check that it matches the format AEGIS-PRO-... and try again.';
  } else if (lower.includes('over_limit')) {
    friendlyTitle = 'Activation Limit Reached';
    friendlyDescription = 'All concurrent installation seats for this license key are in use. Please deactivate another node or add more seats to your plan.';
  } else if (lower.includes('license_not_active') || lower.includes('suspended') || lower.includes('revoked') || lower.includes('expired')) {
    friendlyTitle = 'License Not Active';
    friendlyDescription = 'This license key is expired, inactive, or has been revoked. Please verify your account status.';
  } else if (lower.includes('connect') || lower.includes('refused') || lower.includes('timeout') || lower.includes('network') || lower.includes('502') || lower.includes('unreachable')) {
    friendlyTitle = 'Connection Failed';
    friendlyDescription = 'Unable to reach the license verification service. Please verify that this machine has outbound internet connectivity and try again.';
  }

  const content = `
    <div class="license-modal-container" style="text-align: center; padding: 24px 20px 20px; width: 100%; max-width: 460px; margin: 0 auto; box-sizing: border-box;">
      <!-- Warning Icon -->
      <div style="width: 56px; height: 56px; margin: 0 auto 14px; border-radius: 50%; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); display: flex; align-items: center; justify-content: center; color: #ef4444;">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
      </div>

      <div style="display: inline-block; padding: 3px 10px; border-radius: 2px; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.25); color: #ef4444; font-size: 0.72rem; font-weight: 600; letter-spacing: 0.06em; text-transform: uppercase; margin-bottom: 10px;">
        ACTIVATION ERROR
      </div>

      <h2 style="font-size: 1.35rem; font-weight: 700; margin: 0 0 6px; color: var(--text-main, #ffffff); letter-spacing: -0.01em;">
        ${escapeSectionHtml(friendlyTitle)}
      </h2>
      <p style="color: var(--text-muted, #9ca3af); font-size: 0.88rem; margin: 0 0 18px; line-height: 1.45;">
        ${escapeSectionHtml(friendlyDescription)}
      </p>

      ${message && message !== friendlyDescription ? `
        <div style="background: rgba(0, 0, 0, 0.3); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 6px; padding: 8px 12px; margin-bottom: 18px; font-family: monospace; font-size: 0.76rem; color: #fca5a5; word-break: break-all; text-align: left; box-sizing: border-box;">
          <strong>Error detail:</strong> ${escapeSectionHtml(message)}
        </div>
      ` : ''}

      <div style="display: flex; gap: 10px; width: 100%; box-sizing: border-box;">
        <button type="button" class="btn btn-outline" data-section-action="close-modal" style="flex: 1; padding: 9px 12px; font-weight: 500; cursor: pointer; border-radius: 6px;">
          Dismiss
        </button>
        <button type="button" class="btn btn-primary" data-section-action="close-modal" style="flex: 1; padding: 9px 12px; font-weight: 600; cursor: pointer; border-radius: 6px;">
          Try Again
        </button>
      </div>
    </div>
  `;

  SectionUI.showModal(content, { panelClass: 'modal-content license-modal-panel', closeOnBackdrop: true });
}
