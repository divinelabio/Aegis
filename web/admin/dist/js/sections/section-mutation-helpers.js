import { api } from '../api.js';
import * as AdminDOM from '../core/dom.js';
import { showSectionToast } from './section-toast-helpers.js';
export function isSuccessfulSectionMutation(response) {
    return response !== false
        && (typeof response !== 'object' || response === null || response.success !== false);
}
export function getSectionErrorMessage(error, fallback = 'Unknown error') {
    if (!(error instanceof Error))
        return fallback;
    const mutationError = error;
    const code = mutationError.code ? ` [${mutationError.code}]` : '';
    const field = mutationError.details
        && typeof mutationError.details === 'object'
        && typeof mutationError.details.field === 'string'
        ? `${mutationError.details.field}: `
        : '';
    return `${field}${error.message}${code}`;
}
export async function saveSectionConfig(options) {
    const showToast = options.showToast || showSectionToast;
    try {
        const result = await api.requestResult(options.endpoint, 'PUT', options.config);
        if (result.error) {
            const requestError = new Error(result.error.message);
            requestError.status = result.error.status;
            requestError.code = result.error.code;
            requestError.details = result.error.details;
            throw requestError;
        }
        const response = result.data;
        if (!isSuccessfulSectionMutation(response)) {
            throw new Error(options.failedResponseMessage || options.failureMessage);
        }
        showToast(options.successMessage, 'success');
        const successResponse = response;
        await options.onSuccess?.(successResponse);
        return successResponse;
    }
    catch (error) {
        if (options.errorLogMessage) {
            console.error(options.errorLogMessage, error);
        }
        else {
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
