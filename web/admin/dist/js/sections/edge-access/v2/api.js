import { api } from '../../../api.js';
import { EDGE_ACCESS_ENDPOINTS } from './endpoints.js';
const ROOT = EDGE_ACCESS_ENDPOINTS.root;
function isRecord(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function normalizePolicyRuntimeCapabilities(value) {
    if (!isRecord(value)
        || typeof value.mfa_satisfied !== 'boolean'
        || typeof value.source_cidrs !== 'boolean'
        || typeof value.trusted_device !== 'boolean'
        || typeof value.countries !== 'boolean'
        || typeof value.time_windows !== 'boolean') {
        return null;
    }
    return {
        mfa_satisfied: value.mfa_satisfied,
        source_cidrs: value.source_cidrs,
        trusted_device: value.trusted_device,
        countries: value.countries,
        time_windows: value.time_windows
    };
}
export async function loadV2PolicyCapabilities() {
    const response = await api.get(`${ROOT}/policy-capabilities`);
    if (!isRecord(response) || response.success !== true)
        return null;
    return normalizePolicyRuntimeCapabilities(response.capabilities);
}
