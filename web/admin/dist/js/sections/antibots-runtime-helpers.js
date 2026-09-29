import { showSectionToast } from './section-toast-helpers.js';
import { formatSectionCompactNumber } from './section-runtime-helpers.js';
import { SectionUI } from './ui-components.js';
import { ANTIBOT_ICONS } from './antibots-config-shared.js';
export function formatAntibotNumber(n) {
    return formatSectionCompactNumber(n);
}
export function showAntibotToast(msg, type = 'info') {
    showSectionToast(msg, type);
}
export function getAntibotIcon(name) {
    return ANTIBOT_ICONS[name] || '';
}
export function renderAntibotSaveButton() {
    return SectionUI.renderSaveActionBar({
        actionAttr: 'data-antibot-action',
        resetAction: 'reset-config',
        saveAction: 'save-config'
    });
}
