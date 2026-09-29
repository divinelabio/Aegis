/**
 * Module dashboard
 * Source of truth: web/admin/src/modules/dashboard.ts
 * Runtime output: web/admin/dist/js/modules/dashboard.js
 */
import { api } from '../api.js';
import { FEATURES } from '../core/features.js';
import { SectionUI } from '../sections/ui-components.js';
const configureArrow = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m9 18 6-6-6-6"/></svg>';
export const ModuleDashboard = {
    render() {
        const modules = [
            {
                id: 'module_reputation',
                name: 'IP Reputation',
                description: 'IP risk scoring and threat intelligence feeds.',
                icon: '<svg viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"></ellipse><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path></svg>',
                feature: FEATURES.TRAFFIC_REPUTATION
            },
            {
                id: 'module_captcha',
                name: 'Captcha',
                description: 'Provider-backed human verification.',
                icon: '<svg viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>',
            },
            {
                id: 'module_challenge',
                name: 'Smart Challenge',
                description: 'Challenge pages and solve policy.',
                icon: '<svg viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2" ry="2"></rect><rect x="9" y="9" width="6" height="6"></rect><line x1="9" y1="1" x2="9" y2="4"></line><line x1="15" y1="1" x2="15" y2="4"></line><line x1="9" y1="20" x2="9" y2="23"></line><line x1="15" y1="20" x2="15" y2="23"></line><line x1="20" y1="9" x2="23" y2="9"></line><line x1="20" y1="14" x2="23" y2="14"></line><line x1="1" y1="9" x2="4" y2="9"></line><line x1="1" y1="14" x2="4" y2="14"></line></svg>',
            },
            {
                id: 'module_error_pages',
                name: 'Error Pages',
                description: 'Custom browser error pages and template styling.',
                icon: '<svg viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>'
            }
        ];
        const availableModules = modules.filter(module => !module.feature || api.hasFeature(module.feature));
        const moduleCount = availableModules.length;
        const content = `
      <div class="module-registry-operator-stack">
        ${SectionUI.renderOperatorSection('Available modules', `<div class="module-registry-module-grid">
            ${availableModules.map(module => this.renderCard(module)).join('')}
          </div>`, {
            subtitle: 'Select a module to configure it.',
            actions: `<span class="config-status-pill tone-neutral">${moduleCount} modules</span>`,
            className: 'module-registry-section'
        })}
      </div>
    `;
        return SectionUI.renderOperatorFrame({
            title: 'Modules',
            kicker: 'System',
            subtitle: 'Configure shared services used across Aegis protection policies.',
            content,
            className: 'module-registry-operator-frame'
        });
    },
    renderCard(module) {
        return `
      <button type="button"
              class="module-registry-module-card"
              data-nav-target="${module.id}"
              aria-label="Configure ${module.name}">
        <span class="operator-control-icon module-registry-module-icon" aria-hidden="true">${module.icon}</span>
        <span class="operator-control-copy">
          <span class="operator-control-title">${module.name}</span>
          <span class="operator-control-desc">${module.description}</span>
        </span>
        <span class="module-registry-module-open">Configure ${configureArrow}</span>
      </button>
    `;
    }
};
