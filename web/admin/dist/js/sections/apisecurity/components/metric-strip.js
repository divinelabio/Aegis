import { SectionUI } from '../../ui-components.js';
export function renderAPISecurityMetricStrip(metrics, className = '') {
    return SectionUI.renderOperatorMetricStrip(metrics, className);
}
