import { api } from '../../../api.js';
import { EDGE_ACCESS_ENDPOINTS } from './endpoints.js';

const ROLES_ENDPOINT = `${EDGE_ACCESS_ENDPOINTS.root}/roles`;

export interface AccessRole {
  id: string;
  name: string;
  description: string;
  permissions: string[];
  inherits: string[];
  is_builtin: boolean;
}

export interface AccessRoleInput {
  id: string;
  name: string;
  description: string;
  permissions: string[];
  inherits: string[];
  is_builtin: boolean;
}

interface RoleResult<T> {
  data: T | null;
  error: { message: string } | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

function normalizeRole(value: unknown): AccessRole | null {
  if (!isRecord(value) || typeof value.id !== 'string' || !value.id.trim()) return null;
  return {
    id: value.id,
    name: typeof value.name === 'string' && value.name.trim() ? value.name : value.id,
    description: typeof value.description === 'string' ? value.description : '',
    permissions: strings(value.permissions),
    inherits: strings(value.inherits),
    is_builtin: value.is_builtin === true
  };
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}

async function list(): Promise<RoleResult<AccessRole[]>> {
  try {
    const response = await api.get<unknown>(ROLES_ENDPOINT);
    const values = isRecord(response) && Array.isArray(response.roles) ? response.roles : [];
    return { data: values.map(normalizeRole).filter((role): role is AccessRole => role !== null), error: null };
  } catch (error) {
    return { data: null, error: { message: errorMessage(error, 'Roles could not be loaded.') } };
  }
}

async function create(input: AccessRoleInput): Promise<RoleResult<AccessRole>> {
  try {
    const response = await api.post<unknown>(ROLES_ENDPOINT, input);
    if (response === false || !isRecord(response)) return { data: null, error: { message: 'Role could not be created.' } };
    const role = normalizeRole(response.role);
    return role ? { data: role, error: null } : { data: null, error: { message: 'The role response was invalid.' } };
  } catch (error) {
    return { data: null, error: { message: errorMessage(error, 'Role could not be created.') } };
  }
}

async function update(id: string, input: AccessRoleInput): Promise<RoleResult<AccessRole>> {
  try {
    const response = await api.put<unknown>(`${ROLES_ENDPOINT}/${encodeURIComponent(id)}`, input);
    if (response === false) return { data: null, error: { message: 'Role could not be updated.' } };
    return { data: input, error: null };
  } catch (error) {
    return { data: null, error: { message: errorMessage(error, 'Role could not be updated.') } };
  }
}

async function remove(id: string): Promise<RoleResult<boolean>> {
  try {
    const success = await api.delete(`${ROLES_ENDPOINT}/${encodeURIComponent(id)}`);
    return success ? { data: true, error: null } : { data: null, error: { message: 'Role could not be deleted.' } };
  } catch (error) {
    return { data: null, error: { message: errorMessage(error, 'Role could not be deleted.') } };
  }
}

export const rolesV2Api = { list, create, update, remove };
