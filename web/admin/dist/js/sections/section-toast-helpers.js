import { notify } from '../core/notify.js';
export function showSectionToast(message, type = 'info') {
    notify(message, type);
}
