import { SectionUI } from './ui-components.js';
export function renderHTTPSecuritySaveButtons() {
    return SectionUI.renderSaveActionBar({
        actionAttr: 'data-httpsec-action',
        resetAction: 'reset',
        saveAction: 'save'
    });
}
