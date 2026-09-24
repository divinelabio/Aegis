import { SectionUI } from './ui-components.js';

export function renderTrafficSaveButtons(): string {
    return SectionUI.renderSaveActionBar({
        actionAttr: 'data-traffic-action',
        resetAction: 'reset',
        saveAction: 'save-config',
        className: 'flow-save-actions'
    });
}
