import { Toast } from '../toast.js';

export interface NotifyOptions {
  onError?: (message: string) => void;
  logger?: Pick<Console, 'log'>;
}

export function notify(message: unknown, type: ToastType = 'info', _options: NotifyOptions = {}): void {
  Toast.show(message, type);
}
