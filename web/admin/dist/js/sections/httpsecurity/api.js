import { api } from '../../api.js';
function getHTTPSecurityErrorMessage(payload, fallback) {
    if (!payload || typeof payload !== 'object')
        return fallback;
    const record = payload;
    const nested = record.error;
    if (nested && typeof nested === 'object') {
        const error = nested;
        const details = Array.isArray(error.details) ? error.details : [];
        const firstDetail = details[0] && typeof details[0] === 'object' ? details[0] : null;
        const detailMessage = firstDetail?.message
            ? ` ${firstDetail.path ? `${String(firstDetail.path)}: ` : ''}${String(firstDetail.message)}`
            : '';
        return `${String(error.message || fallback)}${detailMessage}`;
    }
    return String(record.message || nested || fallback);
}
async function isHTTPSecurityCSRFRejection(response) {
    if (response.status !== 403)
        return false;
    const payload = await response.clone().json().catch(() => null);
    const error = payload?.error;
    if (!error || typeof error !== 'object')
        return /csrf\s+token/i.test(String(payload?.message || ''));
    const details = error;
    return details.code === 'CSRF_REQUIRED' || /csrf\s+token/i.test(String(details.message || ''));
}
export async function httpSecurityJSONRequest(endpoint, method, data) {
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method.toUpperCase()) && !api.csrfToken) {
        await api.checkSession?.();
    }
    const sendRequest = () => {
        const headers = { 'Content-Type': 'application/json', Accept: 'application/json' };
        if (api.csrfToken)
            headers['X-CSRF-Token'] = api.csrfToken;
        return fetch(`/api/${endpoint}`, {
            method,
            headers,
            body: data === undefined ? null : JSON.stringify(data)
        });
    };
    let response = await sendRequest();
    if (await isHTTPSecurityCSRFRejection(response) && await api.checkSession?.()) {
        response = await sendRequest();
    }
    let payload = null;
    try {
        payload = await response.json();
    }
    catch {
        payload = null;
    }
    if (response.status === 401) {
        throw new Error('Session expired. Please sign in again.');
    }
    if (!response.ok) {
        const error = new Error(getHTTPSecurityErrorMessage(payload, `Request failed: ${response.status}`));
        error.status = response.status;
        error.payload = payload;
        throw error;
    }
    return payload;
}
