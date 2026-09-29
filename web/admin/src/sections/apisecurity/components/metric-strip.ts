import { SectionUI } from '../../ui-components.js';

export function renderAPISecurityMetricStrip(metrics: Parameters<typeof SectionUI.renderOperatorMetricStrip>[0], className = ''): string {
    return SectionUI.renderOperatorMetricStrip(metrics, className);
}
