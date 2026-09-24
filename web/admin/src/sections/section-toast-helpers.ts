import { notify } from '../core/notify.js';

export function showSectionToast(message: string, type: ToastType = 'info'): void {
    notify(message, type);
}
