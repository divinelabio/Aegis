/**
 * WAF rules management - policies view
 * Source of truth: web/admin/src/categories.ts
 * Runtime output: web/admin/dist/js/categories.js
 */
import { SectionUI } from './sections/ui-components.js';
import { api } from './api.js';
import { router } from './router.js';
import * as AdminEvents from './core/events.js';
import * as AdminDOM from './core/dom.js';
import { notify } from './core/notify.js';
function debounce(func, wait) {
    let timeout = null;
    return function executedFunction(...args) {
        const later = () => {
            if (timeout)
                window.clearTimeout(timeout);
            func(...args);
        };
        if (timeout)
            window.clearTimeout(timeout);
        timeout = window.setTimeout(later, wait);
    };
}
const ruleCache = {
    data: new Map(),
    set(key, value, ttl = 300000) {
        this.data.set(key, {
            value,
            expires: Date.now() + ttl
        });
    },
    get(key) {
        const item = this.data.get(key);
        if (!item)
            return null;
        if (Date.now() > item.expires) {
            this.data.delete(key);
            return null;
        }
        return item.value;
    },
    clear() {
        this.data.clear();
    }
};
let rulesData = [];
let currentPage = 1;
let pageSize = 20;
let categoriesBindingsInitialized = false;
const ruleDescriptions = {
    'sql-injection': 'Blocks UNION SELECT, blind SQLi, database functions, and bypass techniques',
    'xss': 'Blocks script tags, event handlers, JavaScript URIs, DOM manipulation',
    'rce': 'Blocks shell commands, Unix binaries, PowerShell, and command chaining',
    'lfi': 'Blocks path traversal, OS file access, PHP wrappers, and remote includes',
    'php-injection': 'Blocks dangerous PHP functions, superglobals, wrappers, and object injection',
    'java': 'Blocks Log4Shell, deserialization, Spring4Shell, Struts OGNL attacks',
    'webshell': 'Detects 60+ PHP/ASP shell signatures and command execution patterns',
    'deserialization': 'Blocks Java, PHP, .NET, Python, Ruby deserialization exploits',
    'nosql': 'Blocks MongoDB, Redis, Cassandra injection patterns',
    'ldap': 'Blocks LDAP filter injection and directory traversal',
    'xxe': 'Blocks DOCTYPE, ENTITY declarations, and XML bombs',
    'ssti': 'Blocks Jinja2, Twig, Freemarker, Velocity template attacks',
    'ssrf': 'Blocks internal IP access, cloud metadata, and URL schemes',
    'protocol': 'Request smuggling prevention, header validation, encoding attacks',
    'http-desync': 'CL.TE, TE.CL, and chunked encoding attacks',
    'http-method': 'Blocks dangerous methods: TRACE, TRACK, DEBUG, CONNECT',
    'multipart': 'Validates file uploads, blocks dangerous extensions',
    'encoding': 'Unicode bypass, null bytes, double encoding detection',
    'scanner': 'Detects Nmap, SQLMap, Nikto, Nuclei, and 40+ scanner signatures',
    'session-fixation': 'Prevents session hijacking via HTML/meta tag injection',
    'session': 'Cookie security, session ID protection',
    'jwt': 'Blocks algorithm confusion, none alg, weak signatures',
    'cors': 'Detects dangerous CORS patterns and null origins',
    'api-abuse': 'Mass assignment, BOLA, excessive data exposure',
    'graphql': 'Introspection, deep queries, batching attacks',
    'data-leakage': 'PII detection, error disclosure, source code leaks',
    'redirect': 'Blocks malicious redirect parameters and URLs',
    'generic': 'Variable interpolation, template patterns, Log4j lookups'
};
const ruleTestExamples = {
    'aegis/sql-injection.yaml': {
        method: 'GET',
        uri: "/search?q=1' UNION SELECT password FROM users--",
        headers: 'User-Agent: Mozilla/5.0',
        body: '',
        description: 'SQL injection attack - UNION SELECT'
    }
};
function encodePolicyValue(value) {
    return encodeURIComponent(value);
}
function decodePolicyValue(value) {
    return value ? decodeURIComponent(value) : '';
}
function openRuleEditor(filePath) {
    if (typeof router !== 'undefined' && router.navigateToRuleEditor) {
        router.navigateToRuleEditor(filePath);
    }
    else {
        categoriesShowToast('Rule editor is unavailable right now', 'error');
    }
}
function ensureCategoriesBindings() {
    if (categoriesBindingsInitialized)
        return;
    categoriesBindingsInitialized = true;
    AdminEvents.delegateEvent(document, 'click', '[data-categories-action]', (_event, target) => {
        const action = target.dataset.categoriesAction;
        const file = decodePolicyValue(target.dataset.policyFile);
        const modalId = target.dataset.modalId;
        switch (action) {
            case 'open-add-policy-modal':
                openAddPolicyModal();
                break;
            case 'delete-policy':
                if (file)
                    void deletePolicyFile(file);
                break;
            case 'edit-policy':
                if (file)
                    openRuleEditor(file);
                break;
            case 'close-modal':
                if (modalId)
                    closeModal(modalId);
                break;
            case 'create-policy':
                void createPolicy();
                break;
            default:
                break;
        }
    });
    AdminEvents.delegateEvent(document, 'change', '[data-categories-toggle="policy-enabled"]', (_event, target) => {
        const file = decodePolicyValue(target.dataset.policyFile);
        if (!file)
            return;
        void togglePolicyFile(file, target.checked);
    });
}
function renderPoliciesTable() {
    ensureCategoriesBindings();
    const container = AdminDOM.getById('policies-container');
    if (!container)
        return;
    const grouped = {};
    rulesData.forEach(policy => {
        const group = policy.category || 'Other';
        if (!grouped[group])
            grouped[group] = [];
        grouped[group].push(policy);
    });
    const groupOrder = [
        'Core Attack Detection',
        'Injection Attacks',
        'Protocol & Application Security',
        'Protocol & App Security',
        'Scanner & Bot Detection',
        'Session & API Security',
        'Data Protection',
        'Protocol & Initialization',
        'Attack Detection',
        'Data Leakage Prevention',
        'Custom',
        'Other'
    ];
    const allGroups = Object.keys(grouped);
    const sortedGroups = [...groupOrder.filter(group => grouped[group]), ...allGroups.filter(group => !groupOrder.includes(group)).sort()];
    container.innerHTML = `
        <div class="policies-header flex justify-between align-start mb-24">
            <div>
                <h1 class="m-0 text-24 font-700 text-main">Security Policies</h1>
                <p class="m-0 mt-6 text-14 text-muted">${rulesData.length} detection policies active across ${allGroups.length} categories</p>
            </div>
            <div class="flex gap-12">
                <button type="button" class="btn font-600" data-categories-action="open-add-policy-modal">+ Create Policy</button>
            </div>
        </div>
        
        <div class="policy-groups-container flex flex-col gap-32">
        ${sortedGroups.map(group => {
        const policies = grouped[group];
        return `
                <div class="policy-group-section">
                    <div class="flex justify-between align-center mb-20">
                        <h2 class="m-0 text-14 font-700 text-note text-uc ls-1">${group}</h2>
                        <span class="text-xs text-muted">${policies.length} Policies</span>
                    </div>
                    <div class="grid-auto-320">
                    ${policies.map(policy => {
            const filename = policy.file;
            const displayName = policy.name || filename.split('/').pop()?.replace('.yaml', '').replace('.conf', '') || filename;
            const description = policy.description || ruleDescriptions[displayName.toLowerCase()] || 'Security policy';
            const isEnabled = Boolean(policy.enabled);
            const isAegis = filename.startsWith('aegis/');
            return `
                        <div class="card card-flush policy-card ${isEnabled ? '' : 'disabled'}">
                            <div class="card-section flex justify-between align-center bg-depth">
                                <div class="flex align-center gap-12">
                                    <div class="w-8 h-8 rounded-full ${isEnabled ? 'bg-success' : 'bg-muted'}"></div>
                                    <div>
                                        <h3 class="m-0 text-14 font-600 text-main">${displayName}</h3>
                                        <div class="text-note text-mono text-xs mt-2">${filename}</div>
                                    </div>
                                </div>
                                <label class="switch scale-80" title="${isEnabled ? 'Disable Policy' : 'Enable Policy'}">
                                    <input type="checkbox" ${isEnabled ? 'checked' : ''} data-categories-toggle="policy-enabled" data-policy-file="${encodePolicyValue(filename)}" />
                                    <span class="switch-slider round"></span>
                                </label>
                            </div>
                            <div class="p-16 flex flex-col">
                                <p class="m-0 mb-16 text-12 text-muted lh-15 flex-1">
                                    ${description}
                                </p>
                                <div class="flex justify-between align-center pt-12 border-top">
                                    <div class="flex gap-8 text-xs font-600 text-uc ls-1">
                                        ${!isEnabled ? '<span class="text-warning">Disabled</span>' : '<span class="text-success">Active</span>'}
                                        ${isAegis ? '<span class="text-primary">• Built-in</span>' : '<span class="text-muted">• Imported</span>'}
                                    </div>
                                    <div class="flex gap-8">
                                        ${policy.type === 'custom' ? `<button type="button" class="btn btn-xs btn-outline-danger" data-categories-action="delete-policy" data-policy-file="${encodePolicyValue(filename)}" aria-label="Delete ${escapeHtml(displayName)} policy" title="Delete Policy"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg></button>` : ''}
                                        <button type="button" class="btn btn-xs font-600" data-categories-action="edit-policy" data-policy-file="${encodePolicyValue(filename)}">Edit</button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;
        }).join('')}
                    </div>
                </div>
            `;
    }).join('')}
        </div>
    `;
}
export async function loadPoliciesTable() {
    const container = AdminDOM.getById('policies-container');
    if (!container)
        return;
    const cached = ruleCache.get('rules-list');
    if (cached) {
        rulesData = cached;
        renderPoliciesTable();
        return;
    }
    container.innerHTML = '<div class="text-center p-40 text-muted">Loading policies...</div>';
    try {
        const data = await api.get('rules');
        if (!data?.rules || !Array.isArray(data.rules)) {
            container.innerHTML = '<div class="text-center p-40 text-danger">Failed to load policies</div>';
            return;
        }
        rulesData = data.rules;
        ruleCache.set('rules-list', rulesData);
        renderPoliciesTable();
    }
    catch (error) {
        console.error(error);
        container.innerHTML = '<div class="text-center p-40 text-danger">Error loading policies</div>';
    }
}
function reloadPolicies() {
    ruleCache.clear();
    void loadPoliciesTable();
}
async function togglePolicyFile(filename, enable) {
    try {
        await api.post('rules/toggle', { file: filename, enable });
        window.setTimeout(reloadPolicies, 200);
        categoriesShowToast(`Policy ${enable ? 'enabled' : 'disabled'} successfully`, 'success');
    }
    catch {
        categoriesShowToast('Failed to update policy state', 'error');
    }
}
async function deletePolicyFile(filename) {
    SectionUI.openConfirmModal('Delete Policy File', `Are you sure you want to delete policy <strong>"${filename}"</strong>?<br><br>This action cannot be undone.`, 'Delete', 'var(--danger)', () => {
        void confirmDeletePolicyFile(filename);
    });
}
async function confirmDeletePolicyFile(filename) {
    SectionUI.closeModal();
    try {
        await fetch(`/api/rules?file=${encodeURIComponent(filename)}`, { method: 'DELETE' });
        reloadPolicies();
        categoriesShowToast('Policy deleted successfully', 'success');
    }
    catch {
        categoriesShowToast('Failed to delete policy', 'error');
    }
}
function openAddPolicyModal() {
    const modalHtml = `
    <div class="modal-overlay active" id="add-policy-modal">
        <div class="modal-content modal-narrow">
            <div class="modal-header">
                <div>
                    <h3 class="m-0 text-16 text-main">New Security Policy</h3>
                    <p class="m-0 mt-4 text-12 text-muted">Create a new YAML rule file</p>
                </div>
                <button type="button" class="btn btn-outline btn-sm" data-categories-action="close-modal" data-modal-id="add-policy-modal">Close</button>
            </div>
            
            <div class="modal-body">
                <div class="settings-field mb-20">
                    <label class="text-main">Policy Name</label>
                    <input type="text" id="new-policy-name" class="settings-input" placeholder="e.g., WordPress Protection">
                    <span class="settings-hint">This will be the filename (e.g., wordpress-protection.yaml)</span>
                </div>
                
                <div class="settings-field">
                    <label class="text-main">Description</label>
                    <input type="text" id="new-policy-desc" class="settings-input" placeholder="e.g., Specific rules for WordPress sites">
                </div>
            </div>
            
            <div class="modal-footer">
                <button type="button" class="btn btn-outline" data-categories-action="close-modal" data-modal-id="add-policy-modal">Cancel</button>
                <button type="button" class="btn" data-categories-action="create-policy">Create Policy</button>
            </div>
        </div>
    </div>
    `;
    const container = AdminDOM.getById('modal-container');
    if (container)
        container.innerHTML = modalHtml;
}
async function createPolicy() {
    const name = AdminDOM.inputValue('new-policy-name').trim();
    const desc = AdminDOM.inputValue('new-policy-desc').trim();
    if (!name) {
        categoriesShowToast('Please enter a policy name', 'warning');
        return;
    }
    const safeName = name.toLowerCase().replace(/[^a-z0-9-]/g, '-');
    const filename = `custom/${safeName}.yaml`;
    const content = `# ${name}\n# ${desc || 'Custom Rule Policy'}\n# Created: ${new Date().toISOString()}\n\n`;
    try {
        const response = await fetch('/api/rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ file: filename, content, description: desc })
        });
        if (response.ok) {
            closeModal('add-policy-modal');
            await loadPoliciesTable();
            categoriesShowToast('Policy created successfully', 'success');
            return;
        }
        categoriesShowToast('Failed to create policy', 'error');
    }
    catch (error) {
        console.error(error);
        categoriesShowToast('Failed to create policy', 'error');
    }
}
function closeModal(id) {
    const modal = AdminDOM.getById(id);
    if (modal)
        modal.remove();
}
function escapeHtml(text) {
    if (!text)
        return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
function categoriesShowToast(message, type = 'info') {
    notify(message, type);
}
void debounce;
void ruleTestExamples;
void currentPage;
void pageSize;
void escapeHtml;
