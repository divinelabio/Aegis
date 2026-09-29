import { SectionUI } from './ui-components.js';

export function renderAPISecuritySaveButtons(): string {
    return SectionUI.renderSaveActionBar({
        actionAttr: 'data-api-security-action',
        resetAction: 'reset',
        saveAction: 'save',
        saveLabel: 'Save Changes'
    });
}
