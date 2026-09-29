import { Toast } from '../toast.js';
export function notify(message, type = 'info', _options = {}) {
    Toast.show(message, type);
}
