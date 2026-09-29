/**
 * Aegis API Module
 * Source of truth: web/admin/src/api.ts
 * Runtime output: web/admin/dist/js/api.js
 */


import { SectionUI } from './sections/ui-components.js';
import { notify } from './core/notify.js';
import * as AdminDOM from './core/dom.js';

export { getErrorMessage, parseJsonSafe };

interface ApiErrorPayload {
  error?: string | {
    code?: unknown;
    message?: unknown;
    details?: unknown;
  };
  code?: unknown;
  details?: unknown;
  message?: unknown;
}

function getErrorMessage(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

function getApiErrorResponseMessage(payload: ApiErrorPayload, fallback: string): string {
  if (typeof payload.message === 'string' && payload.message.trim()) {
    return payload.message;
  }
  if (typeof payload.error === 'string' && payload.error.trim()) {
    return payload.error;
  }
  if (
    payload.error
    && typeof payload.error === 'object'
    && typeof payload.error.message === 'string'
    && payload.error.message.trim()
  ) {
    return payload.error.message;
  }
  return fallback;
}

function getApiErrorResponseCode(payload: ApiErrorPayload): string | undefined {
  if (typeof payload.code === 'string' && payload.code.trim()) {
    return payload.code;
  }
  if (
    payload.error
    && typeof payload.error === 'object'
    && typeof payload.error.code === 'string'
    && payload.error.code.trim()
  ) {
    return payload.error.code;
  }
  return typeof payload.error === 'string' && payload.error.trim()
    ? payload.error
    : undefined;
}

function getApiErrorResponseDetails(payload: ApiErrorPayload): unknown {
  if (payload.details !== undefined) {
    return payload.details;
  }
  return payload.error && typeof payload.error === 'object'
    ? payload.error.details
    : undefined;
}

async function parseJsonSafe<T>(response: Response, fallback: T): Promise<T> {
  try {
    return (await response.json()) as T;
  } catch {
    return fallback;
  }
}

function isStateChangingMethod(method: string): boolean {
  return ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method.toUpperCase());
}

async function isCSRFRejection(response: Response): Promise<boolean> {
  if (response.status !== 403) return false;

  try {
    const rawText = await response.clone().text();
    if (/csrf/i.test(rawText)) return true;
    const payload = JSON.parse(rawText) as ApiErrorPayload;
    const code = getApiErrorResponseCode(payload);
    const message = getApiErrorResponseMessage(payload, '');
    return code === 'CSRF_REQUIRED' || /csrf\s+token/i.test(message);
  } catch {
    return false;
  }
}

export const api: ApiClient = {
  sessionTimeout: null,
  expiryTimeout: null,
  sessionWarningShown: false,
  SESSION_DURATION: 24 * 60 * 60 * 1000,
  WARNING_BEFORE: 5 * 60 * 1000,
  activeRequests: 0,
  csrfToken: null,
  currentUser: null,

  showLoading(): void {
    const loader = AdminDOM.getById('global-loader');
    if (loader) loader.classList.add('active');
    this.activeRequests += 1;
  },

  hideLoading(): void {
    this.activeRequests -= 1;
    if (this.activeRequests <= 0) {
      this.activeRequests = 0;
      const loader = AdminDOM.getById('global-loader');
      if (loader) loader.classList.remove('active');
    }
  },

  resetSessionTimer(): void {
    if (this.sessionTimeout) window.clearTimeout(this.sessionTimeout);
    this.sessionWarningShown = false;

    this.sessionTimeout = window.setTimeout(() => {
      if (!this.sessionWarningShown) {
        this.sessionWarningShown = true;
        SectionUI.openConfirmModal(
          'Session Expiring',
          'Your session will expire in 5 minutes. Do you want to stay logged in?',
          'Stay Logged In',
          'var(--primary)',
          () => {
            SectionUI.closeModal();
            api.get('config').then(() => {
              notify('Session extended', 'success');
            });
          }
        );
      }
    }, this.SESSION_DURATION - this.WARNING_BEFORE);

    if (this.expiryTimeout) window.clearTimeout(this.expiryTimeout);
    this.expiryTimeout = window.setTimeout(() => {
      SectionUI.closeModal();
      notify('Session expired. Please log in again.', 'error');
      window.setTimeout(() => {
        window.location.href = '/admin/login';
      }, 2000);
    }, this.SESSION_DURATION);
  },

  async get<T = unknown>(endpoint: string, options: RequestInit = {}): Promise<T | null> {
    this.showLoading();
    this.resetSessionTimer();

    try {
      const response = await fetch(`/api/${endpoint}`, {
        headers: { Accept: 'application/json' },
        ...options
      });

      if (response.status === 401) {
        notify('Session expired. Redirecting to login...', 'error');
        window.setTimeout(() => {
          window.location.href = '/admin/login';
        }, 1500);
        return null;
      }

      if (!response.ok) {
        const fallbackMessage = `Request failed: ${response.status} for ${endpoint}`;
        const errorData = await parseJsonSafe<ApiErrorPayload>(response, {});
        throw new Error(getApiErrorResponseMessage(errorData, fallbackMessage));
      }

      return await parseJsonSafe<T | null>(response, null);
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') {
        return null;
      }
      console.error('[Aegis API]', error);
      notify(getErrorMessage(error, 'Failed to fetch data'), 'error');
      return null;
    } finally {
      this.hideLoading();
    }
  },

  async post<T = unknown>(endpoint: string, data?: unknown, options: RequestInit = {}): Promise<T | false> {
    return this.request<T>(endpoint, 'POST', data, options);
  },

  async put<T = unknown>(endpoint: string, data?: unknown, options: RequestInit = {}): Promise<T | false> {
    return this.request<T>(endpoint, 'PUT', data, options);
  },

  async requestResult<T = unknown>(
    endpoint: string,
    method: string,
    data?: unknown,
    options: RequestInit = {}
  ): Promise<ApiRequestResult<T>> {
    this.showLoading();
    this.resetSessionTimer();

    if (isStateChangingMethod(method) && !this.csrfToken) {
      await this.checkSession();
    }

    const sendRequest = (): Promise<Response> => {
      const headers = new Headers(options.headers);
      if (!headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
      if (!headers.has('Accept')) headers.set('Accept', 'application/json');
      if (this.csrfToken) headers.set('X-CSRF-Token', this.csrfToken);

      return fetch(`/api/${endpoint}`, {
        ...options,
        method,
        headers,
        body: data === undefined ? null : JSON.stringify(data)
      });
    };

    try {
      let response = await sendRequest();
      if (isStateChangingMethod(method) && await isCSRFRejection(response)) {
        if (await this.checkSession()) {
          response = await sendRequest();
        } else {
          notify('Session expired. Redirecting to login...', 'error');
          window.setTimeout(() => {
            window.location.href = '/admin/login';
          }, 1500);
          return { data: null, error: { status: 401, code: 'session_expired', message: 'Session expired.' } };
        }
      }

      if (response.status === 401) {
        notify('Session expired. Redirecting to login...', 'error');
        window.setTimeout(() => {
          window.location.href = '/admin/login';
        }, 1500);
        return { data: null, error: { status: 401, code: 'session_expired', message: 'Session expired.' } };
      }

      if (!response.ok) {
        const errorData = await parseJsonSafe<ApiErrorPayload>(response, {});
        return {
          data: null,
          error: {
            status: response.status,
            code: getApiErrorResponseCode(errorData),
            message: getApiErrorResponseMessage(
              errorData,
              `Request failed: ${response.status} for ${endpoint}`
            ),
            details: getApiErrorResponseDetails(errorData)
          }
        };
      }

      if (response.status === 204) return { data: true as T, error: null };
      return { data: await parseJsonSafe<T>(response, true as T), error: null };
    } catch (error) {
      console.error(`[Aegis API] ${method} ${endpoint} failed:`, error);
      return {
        data: null,
        error: {
          status: 0,
          message: getErrorMessage(error, `Failed to ${method.toLowerCase()} data`)
        }
      };
    } finally {
      this.hideLoading();
    }
  },

  async checkSession(): Promise<boolean> {
    try {
      const response = await fetch('/api/verify_session');
      if (response.ok) {
        const data = (await response.json()) as VerifySessionResponse;
        if (data.status === 'active') {
          this.csrfToken = data.csrf_token || null;
          this.currentUser = {
            id: data.id ?? '',
            username: data.username || '',
            roleId: data.role_id,
            permissions: data.permissions || [],
            edition: data.edition,
            features: data.active_features || []
          };
          return true;
        }
      }
    } catch (error) {
      console.warn('[Aegis] Session check failed:', error);
    }

    return false;
  },

  hasFeature(featureId: string): boolean {
    if (!this.currentUser || !Array.isArray(this.currentUser.features)) return false;
    return this.currentUser.features.includes(featureId);
  },

  hasPermission(slug: string): boolean {
    if (!this.currentUser || !Array.isArray(this.currentUser.permissions)) return false;
    return this.currentUser.permissions.includes(slug);
  },

  async request<T = unknown>(
    endpoint: string,
    method: string,
    data?: unknown,
    options: RequestInit = {}
  ): Promise<T | false> {
    this.showLoading();
    this.resetSessionTimer();

    if (isStateChangingMethod(method) && !this.csrfToken) {
      await this.checkSession();
    }

    const sendRequest = (): Promise<Response> => {
      const headers = new Headers(options.headers);
      if (!headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
      if (!headers.has('Accept')) headers.set('Accept', 'application/json');
      if (this.csrfToken) headers.set('X-CSRF-Token', this.csrfToken);

      return fetch(`/api/${endpoint}`, {
        ...options,
        method,
        headers,
        body: data === undefined ? null : JSON.stringify(data)
      });
    };

    try {
      let response = await sendRequest();
      if (isStateChangingMethod(method) && await isCSRFRejection(response)) {
        if (await this.checkSession()) {
          response = await sendRequest();
        } else {
          notify('Session expired. Redirecting to login...', 'error');
          window.setTimeout(() => {
            window.location.href = '/admin/login';
          }, 1500);
          return false;
        }
      }

      if (response.status === 401) {
        notify('Session expired. Redirecting to login...', 'error');
        window.setTimeout(() => {
          window.location.href = '/admin/login';
        }, 1500);
        return false;
      }

      if (!response.ok) {
        const fallbackMessage = `Request failed: ${response.status} for ${endpoint}`;
        const errorData = await parseJsonSafe<ApiErrorPayload>(response, {});
        throw new Error(getApiErrorResponseMessage(errorData, fallbackMessage));
      }

      const emptySuccess = true as T;
      if (response.status === 204) return emptySuccess;
      return await parseJsonSafe<T>(response, emptySuccess);
    } catch (error) {
      console.error(`[Aegis API] ${method} ${endpoint} failed:`, error);
      notify(getErrorMessage(error, `Failed to ${method.toLowerCase()} data`), 'error');
      return false;
    } finally {
      this.hideLoading();
    }
  },

  async delete(endpoint: string): Promise<boolean> {
    this.showLoading();
    this.resetSessionTimer();

    try {
      if (!this.csrfToken) {
        await this.checkSession();
      }
      const response = await fetch(`/api/${endpoint}`, {
        method: 'DELETE',
        headers: {
          Accept: 'application/json',
          ...(this.csrfToken ? { 'X-CSRF-Token': this.csrfToken } : {})
        }
      });

      if (response.status === 401) {
        notify('Session expired. Redirecting to login...', 'error');
        window.setTimeout(() => {
          window.location.href = '/admin/login';
        }, 1500);
        return false;
      }

      return response.ok;
    } catch (error) {
      console.error('[Aegis API]', error);
      notify(getErrorMessage(error, 'Failed to delete'), 'error');
      return false;
    } finally {
      this.hideLoading();
    }
  },

  async logout(): Promise<void> {
    this.showLoading();
    try {
      if (!this.csrfToken) {
        await this.checkSession();
      }
      await fetch('/api/logout', {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          ...(this.csrfToken ? { 'X-CSRF-Token': this.csrfToken } : {})
        }
      });
    } catch (error) {
      console.error('Logout failed', error);
    } finally {
      this.hideLoading();
      window.location.href = '/admin/login';
    }
  },

  async login(username: string, password: string): Promise<LoginResult> {
    this.showLoading();
    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });

      if (response.ok) return { success: true };
      return { success: false, error: 'Invalid credentials' };
    } catch (error) {
      return { success: false, error: getErrorMessage(error, 'Login failed') };
    } finally {
      this.hideLoading();
    }
  },

  async getModules<T = unknown>(): Promise<T | null> {
    return this.get<T>('modules');
  },

  async getStats<T = unknown>(windowValue?: string): Promise<T | null> {
    return this.get<T>(`stats?window=${windowValue || '1h'}`);
  },

  async getLogs<T = unknown>(windowValue?: string): Promise<T | null> {
    return this.get<T>(`logs?window=${windowValue || '1h'}`);
  }
};

document.addEventListener('DOMContentLoaded', () => {
  api.resetSessionTimer();
});
