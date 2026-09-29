import { api } from '../../../api.js';
import { EDGE_ACCESS_ENDPOINTS } from './endpoints.js';
const ROLES_ENDPOINT = `${EDGE_ACCESS_ENDPOINTS.root}/roles`;
function isRecord(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function strings(value) {
    return Array.isArray(value) ? value.filter((item) => typeof item === 'string') : [];
}
function normalizeRole(value) {
    if (!isRecord(value) || typeof value.id !== 'string' || !value.id.trim())
        return null;
    return {
        id: value.id,
        name: typeof value.name === 'string' && value.name.trim() ? value.name : value.id,
        description: typeof value.description === 'string' ? value.description : '',
        permissions: strings(value.permissions),
        inherits: strings(value.inherits),
        is_builtin: value.is_builtin === true
    };
}
function errorMessage(error, fallback) {
    return error instanceof Error && error.message ? error.message : fallback;
}
async function list() {
    try {
        const response = await api.get(ROLES_ENDPOINT);
        const values = isRecord(response) && Array.isArray(response.roles) ? response.roles : [];
        return { data: values.map(normalizeRole).filter((role) => role !== null), error: null };
    }
    catch (error) {
        return { data: null, error: { message: errorMessage(error, 'Roles could not be loaded.') } };
    }
}
async function create(input) {
    try {
        const response = await api.post(ROLES_ENDPOINT, input);
        if (response === false || !isRecord(response))
            return { data: null, error: { message: 'Role could not be created.' } };
        const role = normalizeRole(response.role);
        return role ? { data: role, error: null } : { data: null, error: { message: 'The role response was invalid.' } };
    }
    catch (error) {
        return { data: null, error: { message: errorMessage(error, 'Role could not be created.') } };
    }
}
async function update(id, input) {
    try {
        const response = await api.put(`${ROLES_ENDPOINT}/${encodeURIComponent(id)}`, input);
        if (response === false)
            return { data: null, error: { message: 'Role could not be updated.' } };
        return { data: input, error: null };
    }
    catch (error) {
        return { data: null, error: { message: errorMessage(error, 'Role could not be updated.') } };
    }
}
async function remove(id) {
    try {
        const success = await api.delete(`${ROLES_ENDPOINT}/${encodeURIComponent(id)}`);
        return success ? { data: true, error: null } : { data: null, error: { message: 'Role could not be deleted.' } };
    }
    catch (error) {
        return { data: null, error: { message: errorMessage(error, 'Role could not be deleted.') } };
    }
}
export const rolesV2Api = { list, create, update, remove };
