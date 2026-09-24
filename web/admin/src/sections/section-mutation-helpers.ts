import { api } from '../api.js';
import * as AdminDOM from '../core/dom.js';
import { showSectionToast } from './section-toast-helpers.js';

type SectionMutationToastType = Extract<ToastType, 'success' | 'error' | 'info' | 'warning'>;

export interface SectionMutationError extends Error {
    status?: number;
    code?: string;
    details?: unknown;
}

interface SaveSectionConfigOptions<TResponse = unknown> {
    endpoint: string;
    config: unknown;
    successMessage: string;
    failureMessage: string;
    failedResponseMessage?: string;
    errorLogMessage?: string;
    errorToastPrefix?: string;
    suppressErrorToastSelector?: string;
    onSuccess?: (response: Exclude<TResponse, false>) => void | Promise<void>;
    showToast?: (message: string, type?: SectionMutationToastType) => void;
}

export function isSuccessfulSectionMutation(response: unknown): boolean {
    return response !== false
        && (typeof response !== 'object' || response === null || (response as { success?: unknown }).success !== false);
}

export function getSectionErrorMessage(error: unknown, fallback = 'Unknown error'): string {
    if (!(error instanceof Error)) return fallback;
    const mutationError = error as SectionMutationError;
    const code = mutationError.code ? ` [${mutationError.code}]` : '';
    const field = mutationError.details
        && typeof mutationError.details === 'object'
        && typeof (mutationError.details as { field?: unknown }).field === 'string'
        ? `${(mutationError.details as { field: string }).field}: `
        : '';
    return `${field}${error.message}${code}`;
}

export async function saveSectionConfig<TResponse = unknown>(options: SaveSectionConfigOptions<TResponse>): Promise<Exclude<TResponse, false>> {
    const showToast = options.showToast || showSectionToast;

    try {
        const result = await api.requestResult<TResponse>(options.endpoint, 'PUT', options.config);
        if (result.error) {
            const requestError = new Error(result.error.message) as SectionMutationError;
            requestError.status = result.error.status;
            requestError.code = result.error.code;
            requestError.details = result.error.details;
            throw requestError;
        }
        const response = result.data as TResponse;
        if (!isSuccessfulSectionMutation(response)) {
            throw new Error(options.failedResponseMessage || options.failureMessage);
        }

        showToast(options.successMessage, 'success');
        const successResponse = response as Exclude<TResponse, false>;
        await options.onSuccess?.(successResponse);
        return successResponse;
    } catch (error) {
        if (options.errorLogMessage) {
            console.error(options.errorLogMessage, error);
        } else {
            console.error(error);
        }

        if (options.suppressErrorToastSelector && AdminDOM.query(options.suppressErrorToastSelector)) {
            throw error;
        }

        const message = options.errorToastPrefix
            ? `${options.errorToastPrefix}${getSectionErrorMessage(error)}`
            : options.failureMessage;
        showToast(message || options.failureMessage, 'error');
        throw error;
    }
}
