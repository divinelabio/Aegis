import { SectionUI } from './ui-components.js';

export function renderHTTPSecuritySaveButtons(): string {
    return SectionUI.renderSaveActionBar({
        actionAttr: 'data-httpsec-action',
        resetAction: 'reset',
        saveAction: 'save'
    });
}
