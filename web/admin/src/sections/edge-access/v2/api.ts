import { api } from '../../../api.js';
import type { PolicyRuntimeCapabilitiesContract } from '../../edge-access-contract.js';
import { EDGE_ACCESS_ENDPOINTS } from './endpoints.js';

const ROOT = EDGE_ACCESS_ENDPOINTS.root;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function normalizePolicyRuntimeCapabilities(value: unknown): PolicyRuntimeCapabilitiesContract | null {
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

export async function loadV2PolicyCapabilities(): Promise<PolicyRuntimeCapabilitiesContract | null> {
  const response = await api.get<unknown>(`${ROOT}/policy-capabilities`);
  if (!isRecord(response) || response.success !== true) return null;
  return normalizePolicyRuntimeCapabilities(response.capabilities);
}
