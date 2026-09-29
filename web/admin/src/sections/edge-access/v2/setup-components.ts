import { SectionUI } from '../../ui-components.js';
import { escapeHTML } from '../view-helpers.js';

export function renderSetupHeading(title: string, description: string): string {
  return `<div class="edge-access-v2-setup-heading"><div><h3>${escapeHTML(title)}</h3><p>${escapeHTML(description)}</p></div></div>`;
}

export function renderCreateBack(label: string, ariaLabel: string, action: string): string {
  return SectionUI.renderOperatorBackButton({
    label: ariaLabel || `Back to ${label}`,
    ariaLabel,
    attrs: `data-edge-access-v2-action="${escapeHTML(action)}"`,
    className: 'edge-access-v2-create-back'
  });
}

export function renderSetupChoiceCard(options: {
  type: 'radio' | 'checkbox';
  name: string;
  value?: string;
  checked?: boolean;
  title: string;
  description: string;
  icon: string;
  className?: string;
}): string {
  const value = options.value === undefined ? '' : ` value="${escapeHTML(options.value)}"`;
  const checked = options.checked ? ' checked' : '';
  const extraClass = options.className ? ` ${escapeHTML(options.className)}` : '';
  return `<label class="edge-access-v2-choice-card${extraClass}">
    <input class="edge-access-v2-choice-input" type="${options.type}" name="${escapeHTML(options.name)}"${value}${checked}>
    <span class="edge-access-v2-selection-mark" aria-hidden="true">${SectionUI.icons.check}</span>
    <span class="edge-access-v2-choice-icon" aria-hidden="true">${options.icon}</span>
    <span class="edge-access-v2-choice-copy"><strong>${escapeHTML(options.title)}</strong><span>${escapeHTML(options.description)}</span></span>
  </label>`;
}

export function renderSetupCheckboxRow(options: {
  name: string;
  value?: string;
  checked?: boolean;
  disabled?: boolean;
  title: string;
  description: string;
  className?: string;
}): string {
  const checked = options.checked ? ' checked' : '';
  const value = options.value === undefined ? '' : ` value="${escapeHTML(options.value)}"`;
  const disabled = options.disabled ? ' disabled' : '';
  const extraClass = options.className ? ` ${escapeHTML(options.className)}` : '';
  return `<label class="edge-access-v2-checkbox-row${extraClass}">
    <input class="edge-access-v2-checkbox-input" type="checkbox" name="${escapeHTML(options.name)}"${value}${checked}${disabled}>
    <span class="edge-access-v2-checkbox-control" aria-hidden="true">${SectionUI.icons.check}</span>
    <span class="edge-access-v2-checkbox-copy"><strong>${escapeHTML(options.title)}</strong><span>${escapeHTML(options.description)}</span></span>
  </label>`;
}

export function renderAdvancedDisclosure(options: {
  title: string;
  description?: string;
  body: string;
  open?: boolean;
  className?: string;
}): string {
  const extraClass = options.className ? ` ${escapeHTML(options.className)}` : '';
  return `<details class="edge-access-v2-advanced-disclosure${extraClass}"${options.open ? ' open' : ''}>
    <summary><span>${escapeHTML(options.title)}</span>${options.description ? `<small>${escapeHTML(options.description)}</small>` : ''}</summary>
    <div class="edge-access-v2-advanced-disclosure-body">${options.body}</div>
  </details>`;
}
