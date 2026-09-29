import { showSectionToast } from './section-toast-helpers.js';
import { formatSectionCompactNumber } from './section-runtime-helpers.js';
import { SectionUI } from './ui-components.js';

import { ANTIBOT_ICONS } from './antibots-config-shared.js';

export function formatAntibotNumber(n: number | string): string {
    return formatSectionCompactNumber(n);
}

export function showAntibotToast(msg: string, type: ToastType = 'info'): void {
    showSectionToast(msg, type);
}

export function getAntibotIcon(name: string): string {
    return ANTIBOT_ICONS[name] || '';
}

export function renderAntibotSaveButton(): string {
    return SectionUI.renderSaveActionBar({
        actionAttr: 'data-antibot-action',
        resetAction: 'reset-config',
        saveAction: 'save-config'
    });
}
