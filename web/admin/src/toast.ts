/**
 * Aegis Toast Notification System
 * Source of truth: web/admin/src/toast.ts
 * Runtime output: web/admin/dist/js/toast.js
 */

import { getById } from './core/dom.js';

export const Toast: ToastApi = {
  container: null,

  init(): void {
    const existing = getById('toast-container');
    if (!existing) {
      const container = document.createElement('div');
      container.id = 'toast-container';
      container.className = 'aeg-toast-container';
      document.body.appendChild(container);
      this.container = container;
      return;
    }

    existing.classList.add('aeg-toast-container');
    this.container = existing;
  },

  show(message: unknown, type: ToastType = 'info', title: string | null = null): void {
    if (!this.container) this.init();
    if (!this.container) return;

    const validTypes: ToastType[] = ['success', 'error', 'warning', 'info'];
    const safeType: ToastType = validTypes.includes(type) ? type : 'info';
    const icons: Record<ToastType, string> = {
      success:
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>',
      error:
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>',
      warning:
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
      info:
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
    };

    if (!title) title = safeType.charAt(0).toUpperCase() + safeType.slice(1);

    const toast = document.createElement('div');
    toast.className = `aeg-toast aeg-toast-${safeType}`;

    const iconBox = document.createElement('div');
    iconBox.className = 'aeg-toast-icon-box';
    iconBox.innerHTML = icons[safeType];

    const content = document.createElement('div');
    content.className = 'aeg-toast-content';

    const titleEl = document.createElement('div');
    titleEl.className = 'aeg-toast-title';
    titleEl.textContent = title;

    const messageEl = document.createElement('div');
    messageEl.className = 'aeg-toast-message';
    messageEl.textContent = String(message ?? '');

    const closeBtn = document.createElement('button');
    closeBtn.className = 'aeg-toast-close';
    closeBtn.setAttribute('type', 'button');
    closeBtn.setAttribute('aria-label', 'Dismiss notification');
    closeBtn.innerHTML =
      '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>';

    content.appendChild(titleEl);
    content.appendChild(messageEl);
    toast.appendChild(iconBox);
    toast.appendChild(content);
    toast.appendChild(closeBtn);
    this.container.appendChild(toast);

    requestAnimationFrame(() => {
      toast.classList.add('is-visible');
    });

    const removeToast = (): void => {
      if (!toast.parentElement) return;
      toast.classList.remove('is-visible');
      window.setTimeout(() => {
        if (toast.parentElement) toast.remove();
      }, 350);
    };

    closeBtn.addEventListener('click', removeToast);
    window.setTimeout(removeToast, 5000);
  }
};
