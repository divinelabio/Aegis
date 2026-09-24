// Rule Editor - Full-Page Visual Rule Builder
// Provides comprehensive editing of individual rules within YAML policy files

import './api.js';
import { SectionUI } from './sections/ui-components.js';
import { router } from './router.js';
import * as AdminEvents from './core/events.js';
import * as AdminDOM from './core/dom.js';
import { notify } from './core/notify.js';

interface PatternValidationResult {
    valid?: boolean;
    matches?: boolean;
    error?: string;
    matched_text?: string;
}

interface RuleTestResponse {
    matched?: boolean;
    action?: string;
    status?: string | number;
    message?: string;
    matched_variables?: Array<{ message?: string }>;
}

interface RuleEditorRule {
    id: string;
    severity: string;
    score: number;
    patterns: string[];
    message: string;
    [key: string]: unknown;
}

interface RuleFileData {
    name?: string;
    category?: string;
    rules?: RuleEditorRule[];
    [key: string]: unknown;
}

function ruleEditorErrorMessage(error: unknown, fallback: string): string {
    return error instanceof Error ? error.message : fallback;
}

function getFieldValue(id: string): string {
    const field = AdminDOM.getById(id) as HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement | null;
    return field?.value ?? '';
}

let ruleEditorBindingsInitialized = false;

function ensureRuleEditorBindings(): void {
    if (ruleEditorBindingsInitialized) return;
    ruleEditorBindingsInitialized = true;

    AdminEvents.delegateEvent<HTMLElement>(document, 'click', '[data-rule-editor-action]', (_event, target) => {
        const action = target.dataset.ruleEditorAction;
        const tab = target.dataset.ruleTab as 'visual' | 'source' | 'test' | undefined;
        const indexValue = target.dataset.ruleIndex ?? target.dataset.patternIndex;
        const index = indexValue ? Number.parseInt(indexValue, 10) : -1;

        switch (action) {
            case 'navigate-back':
                router.navigate('waf');
                break;
            case 'save-file':
                void RuleEditor.saveFile();
                break;
            case 'switch-tab':
                if (tab) void RuleEditor.switchTab(tab);
                break;
            case 'add-rule':
                RuleEditor.addNewRule();
                break;
            case 'select-rule':
                if (index >= 0) RuleEditor.selectRule(index);
                break;
            case 'duplicate-rule':
                if (index >= 0) RuleEditor.duplicateRule(index);
                break;
            case 'delete-rule':
                if (index >= 0) RuleEditor.deleteRule(index);
                break;
            case 'add-pattern':
                RuleEditor.addPattern();
                break;
            case 'remove-pattern':
                if (index >= 0) RuleEditor.removePattern(index);
                break;
            case 'run-test':
                void RuleEditor.runTester();
                break;
            default:
                break;
        }
    });

    AdminEvents.delegateEvent<HTMLInputElement>(document, 'input', '#rule-search', (_event, target) => {
        RuleEditor.filterRules(target.value);
    });

    AdminEvents.delegateEvent<HTMLInputElement>(document, 'change', '[data-rule-field]', (_event, target) => {
        const field = target.dataset.ruleField;
        if (!field) return;
        RuleEditor.updateField(field, target.value);
    });

    AdminEvents.delegateEvent<HTMLInputElement>(document, 'input', '#rule-score-slider', (_event, target) => {
        const scoreInput = AdminDOM.getInput('rule-score');
        if (scoreInput) scoreInput.value = target.value;
        RuleEditor.updateField('score', Number.parseInt(target.value, 10));
    });

    AdminEvents.delegateEvent<HTMLInputElement>(document, 'change', '#rule-score', (_event, target) => {
        const scoreSlider = AdminDOM.getInput('rule-score-slider');
        if (scoreSlider) scoreSlider.value = target.value;
        RuleEditor.updateField('score', Number.parseInt(target.value, 10));
    });

    AdminEvents.delegateEvent<HTMLInputElement>(document, 'change', '[data-pattern-index]', (_event, target) => {
        const index = Number.parseInt(target.dataset.patternIndex || '', 10);
        if (Number.isNaN(index)) return;
        RuleEditor.updatePattern(index, target.value);
    });

    AdminEvents.delegateEvent<HTMLInputElement>(document, 'focusout', '[data-pattern-validate]', (_event, target) => {
        const index = Number.parseInt(target.dataset.patternValidate || '', 10);
        if (Number.isNaN(index)) return;
        void RuleEditor.validatePatternInput(target, index);
    });

    AdminEvents.delegateEvent<HTMLSelectElement>(document, 'change', '#common-patterns', (_event, target) => {
        RuleEditor.insertCommonPattern(target.value);
        target.value = '';
    });

    AdminEvents.delegateEvent<HTMLTextAreaElement>(document, 'input', '#source-code', (_event, target) => {
        RuleEditor.sourceContent = target.value;
        RuleEditor.markUnsaved();
    });

    AdminEvents.delegateEvent<HTMLElement>(document, 'dragstart', '.pattern-item[draggable="true"]', (event, target) => {
        const index = Number.parseInt(target.dataset.patternIndex || '', 10);
        if (Number.isNaN(index) || !(event instanceof DragEvent)) return;
        RuleEditor.handleDragStart(event, index);
    });

    AdminEvents.delegateEvent<HTMLElement>(document, 'dragover', '.pattern-item[draggable="true"]', (event) => {
        if (!(event instanceof DragEvent)) return;
        RuleEditor.handleDragOver(event);
    });

    AdminEvents.delegateEvent<HTMLElement>(document, 'drop', '.pattern-item[draggable="true"]', (event, target) => {
        const index = Number.parseInt(target.dataset.patternIndex || '', 10);
        if (Number.isNaN(index) || !(event instanceof DragEvent)) return;
        RuleEditor.handleDrop(event, index);
    });
}

const RuleEditor = {
    // Current state
    filePath: '' as string,       // Current file being edited (e.g. 'aegis/sql-injection.yaml')
    fileData: null as RuleFileData | null,     // Parsed YAML data
    selectedRuleIndex: -1 as number,
    unsavedChanges: false as boolean,

    // State
    tabs: ['visual', 'source', 'test'] as Array<'visual' | 'source' | 'test'>,
    activeTab: 'visual' as 'visual' | 'source' | 'test',
    dragSrcIndex: -1 as number,
    sourceContent: '' as string,

    // Initialize the rule editor
    async init(filePath: string) {
        ensureRuleEditorBindings();
        this.filePath = filePath;
        this.selectedRuleIndex = -1;
        this.unsavedChanges = false;
        this.activeTab = 'visual'; // Reset to visual tab

        // Load data
        await this.loadFile();
        this.render();
    },

    // Switch tabs
    async switchTab(tab: 'visual' | 'source' | 'test') {
        this.activeTab = tab;
        if (tab === 'source') {
            await this.loadSource();
        }
        this.render();
    },

    // Load data from file via API
    async loadFile() {
        try {
            const res = await fetch(`/api/sections/waf_core/editor/file?path=${encodeURIComponent(this.filePath)}`);
            if (!res.ok) throw new Error('Failed to load file');
            const response = await res.json();

            // Backend returns { success: true, file: "...", data: { ... } }
            // So we need to store the 'data' part
            if (response.success && response.data) {
                this.fileData = response.data;
            } else {
                this.fileData = response; // Fallback
            }
        } catch (e) {
            console.error('Error loading rule file:', e);
            alert('Failed to load policy data: ' + ruleEditorErrorMessage(e, 'Unknown error'));
        }
    },

    // Load raw source
    async loadSource() {
        try {
            const res = await fetch(`/api/sections/waf_core/editor/content?file=${encodeURIComponent(this.filePath)}`);
            this.sourceContent = await res.text();
        } catch (e) {
            this.sourceContent = '# Error loading source';
        }
    },

    // Validate a regex pattern via backend
    async validatePattern(pattern: string, testInput = ''): Promise<PatternValidationResult> {
        try {
            const res = await fetch('/api/sections/waf_core/editor/validate-pattern', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pattern, test_input: testInput })
            });
            return await res.json();
        } catch (e) {
            return { valid: false, error: 'API Error: ' + ruleEditorErrorMessage(e, 'Unknown error') };
        }
    },

    // Main render function
    render() {
        const container = AdminDOM.getById('content');
        if (!container) return;

        const policyName = this.fileData?.name || this.fileData?.category || this.filePath.split('/').pop()?.replace('.yaml', '') || '';

        container.innerHTML = `
            <div class="rule-editor-container">
                <!-- Rule Editor Header -->
                <div class="rule-editor-header">
                    <div class="rule-editor-top">
                        <div class="rule-editor-title">
                            ${SectionUI.renderOperatorBackButton({
                                label: 'Back to policies',
                                attrs: 'data-rule-editor-action="navigate-back"'
                            })}
                            <div class="divider-vertical"></div>
                            <div>
                                <h1 class="rule-heading">
                                    ${this.escapeHtml(policyName)}
                                    <span id="unsaved-badge" class="unsaved-badge ${this.unsavedChanges ? '' : 'hidden'}">Unsaved</span>
                                </h1>
                                <p class="rule-path text-xs text-note">${this.filePath}</p>
                            </div>
                        </div>
                        <div class="rule-actions">
                            <button type="button" class="btn btn-primary" data-rule-editor-action="save-file">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z"/><polyline points="17,21 17,13 7,13 7,21"/><polyline points="7,3 7,8 15,8"/></svg>
                                Save Policy
                            </button>
                        </div>
                    </div>

                    <!-- Tabs -->
                    <div class="editor-tabs">
                        <button type="button" class="editor-tab ${this.activeTab === 'visual' ? 'active' : ''}" data-rule-editor-action="switch-tab" data-rule-tab="visual">
                            Visual Builder
                        </button>
                        <button type="button" class="editor-tab ${this.activeTab === 'source' ? 'active' : ''}" data-rule-editor-action="switch-tab" data-rule-tab="source">
                            YAML Configuration
                        </button>
                        <button type="button" class="editor-tab ${this.activeTab === 'test' ? 'active' : ''}" data-rule-editor-action="switch-tab" data-rule-tab="test">
                            Request Tester
                        </button>
                    </div>
                </div>

                <!-- Main Content Area -->
                <div class="rule-editor-body">
                    ${this.renderContent()}
                </div>
            </div>
        `;
    },

    // Render content based on active tab
    renderContent() {
        if (this.activeTab === 'visual') return this.renderVisualEditor();
        if (this.activeTab === 'source') return this.renderSourceEditor();
        if (this.activeTab === 'test') return this.renderRuleTester();
        return '';
    },

    // Render Visual Editor (2-pane)
    renderVisualEditor() {
        return `
            <div class="rule-layout">
                <div class="rules-sidebar">
                    <div class="rules-sidebar-header">
                        <div class="flex justify-between align-center mb-12">
                            <h3 class="m-0 text-xs font-600 text-note text-uc">Rules List</h3>
                            <button type="button" class="btn btn-xs btn-outline" data-rule-editor-action="add-rule" title="Add Rule">+ Add</button>
                        </div>
                        <div class="rules-search">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="search-icon"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                            <input type="text" id="rule-search" placeholder="Filter rules..." 
                                   class="settings-input text-13 pl-32">
                        </div>
                    </div>
                    <div id="rules-list" class="rules-list">
                        ${this.renderRulesList()}
                    </div>
                </div>

                <div class="rule-detail">
                    <div id="rule-editor-content" class="rule-detail-inner">
                        ${this.renderRuleDetail()}
                    </div>
                </div>
            </div>
        `;
    },

    // Render sidebar rules list
    renderRulesList() {
        if (!this.fileData?.rules?.length) {
            return `<div class="pattern-empty">No rules found. Click "Add Rule" to create one.</div>`;
        }

	        const rules = this.fileData.rules as RuleEditorRule[];
        return rules.map((rule, index: number) => {
            const isSelected = index === this.selectedRuleIndex;
            return `
                <button type="button" class="rule-item ${isSelected ? 'selected' : ''}" data-rule-editor-action="select-rule" data-rule-index="${index}" aria-pressed="${isSelected ? 'true' : 'false'}">
                    <div class="rule-item-header">
                        <div class="rule-item-title ${isSelected ? 'text-primary' : ''}">${this.escapeHtml(rule.id)}</div>
                        <div class="dot-var ${this.getSeverityClass(rule.severity)}" title="Severity: ${rule.severity}"></div>
                    </div>
                    <div class="rule-item-meta">
                        <div class="text-capitalize">${rule.severity} • ${rule.patterns?.length || 0} patterns</div>
                        <div class="font-500 text-note">Score ${rule.score}</div>
                    </div>
                </button>
            `;
        }).join('');
    },

    // Render rule detail editor
    renderRuleDetail() {
        if (this.selectedRuleIndex < 0 || !this.fileData?.rules?.[this.selectedRuleIndex]) {
            return `
                <div class="empty-state">
                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" class="icon-faded mb-16">
                        <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/>
                        <polyline points="14,2 14,8 20,8"/>
                        <line x1="16" y1="13" x2="8" y2="13"/>
                        <line x1="16" y1="17" x2="8" y2="17"/>
                        <polyline points="10,9 9,9 8,9"/>
                    </svg>
                    <p class="text-14">Select a rule from the sidebar to edit</p>
                    <p class="text-12 mt-8">or click "Add Rule" to create a new one</p>
                </div>
            `;
        }

        const rule = this.fileData.rules[this.selectedRuleIndex];

        return `
            <div class="rule-editor-form">
                <div class="rule-section">
                    <div class="flex align-center gap-12 mb-16">
                        <h3 class="m-0 text-16 text-main">Rule Configuration</h3>
                        <div class="flex gap-8 ml-auto">
                            <button type="button" class="btn btn-sm btn-outline" data-rule-editor-action="duplicate-rule" data-rule-index="${this.selectedRuleIndex}" title="Duplicate this rule">
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
                                Duplicate
                            </button>
                            <button type="button" class="btn btn-sm btn-outline text-danger" data-rule-editor-action="delete-rule" data-rule-index="${this.selectedRuleIndex}">
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>
                                Delete
                            </button>
                        </div>
                    </div>
                    
                    <div class="grid-2-cols-16">
                        <div>
                            <label class="form-label" for="rule-id">Rule ID</label>
                            <input type="text" id="rule-id" value="${this.escapeHtml(rule.id)}" 
                                   data-rule-field="id"
                                   class="settings-input text-mono">
                        </div>
                        <div>
                            <label class="form-label" for="rule-score-slider">Score (1-100)</label>
                            <div class="flex align-center gap-12">
                                <input type="range" id="rule-score-slider" value="${rule.score}" min="1" max="100"
                                       class="flex-1 score-slider">
                                <input type="number" id="rule-score" value="${rule.score}" min="1" max="100" aria-label="Score value"
                                       class="settings-input text-center w-64">
                            </div>
                        </div>
                    </div>

                    <div class="grid-2-cols-16 mt-16">
                        <div>
                            <label class="form-label" for="rule-severity">Severity</label>
                            <select id="rule-severity" data-rule-field="severity" class="settings-input">
                                <option value="critical" ${rule.severity === 'critical' ? 'selected' : ''}>Critical (Block)</option>
                                <option value="high" ${rule.severity === 'high' ? 'selected' : ''}>High</option>
                                <option value="medium" ${rule.severity === 'medium' ? 'selected' : ''}>Medium</option>
                                <option value="low" ${rule.severity === 'low' ? 'selected' : ''}>Low</option>
                                <option value="info" ${rule.severity === 'info' ? 'selected' : ''}>Informational</option>
                            </select>
                        </div>
                        <div>
                            <label class="form-label" for="rule-message">Alert Message</label>
                            <input type="text" id="rule-message" value="${this.escapeHtml(rule.message || '')}" 
                                   data-rule-field="message"
                                   placeholder="Alert message when rule triggers..."
                                   class="settings-input">
                        </div>
                    </div>
                </div>

                <div class="rule-section">
                    <div class="flex justify-between align-center mb-12">
                        <h3 class="m-0 text-16 text-main">Detection Patterns (${rule.patterns?.length || 0})</h3>
                        <div class="flex gap-8">
                            <select id="common-patterns" data-rule-editor-action="insert-common-pattern" class="settings-input text-12 w-200" aria-label="Pattern template library">
                                <option value="">Template Library</option>
                                <optgroup label="SQL Injection">
                                    <option value="(?i)\\bunion\\s+select\\b">UNION SELECT</option>
                                    <option value="(?i)\\bor\\s+1\\s*=\\s*1">OR 1=1 Tautology</option>
                                    <option value="(?i)\\bsleep\\s*\\(">SLEEP() Function</option>
                                </optgroup>
                                <optgroup label="XSS">
                                    <option value="(?i)&lt;script[^&gt;]*&gt;">&lt;script&gt; Tag</option>
                                    <option value="(?i)\\bon\\w+\\s*=">Event Handler</option>
                                    <option value="(?i)javascript:">JavaScript URI</option>
                                </optgroup>
                                <optgroup label="File Inclusion">
                                    <option value="(?:\\.\\./){2,}">Path Traversal ../</option>
                                    <option value="(?i)(?:file|php|data)://">PHP Wrappers</option>
                                </optgroup>
                                <optgroup label="Command Injection">
                                    <option value="(?:;|\\||\\$\\(|\\x60)">Shell Metacharacters</option>
                                    <option value="(?i)/bin/(?:bash|sh|cat)">Unix Commands</option>
                                </optgroup>
                            </select>
                            <button type="button" class="btn btn-sm btn-outline" data-rule-editor-action="add-pattern">
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                                New Pattern
                            </button>
                        </div>
                    </div>

                    <div id="patterns-list" class="pattern-list">
                        ${this.renderPatternsList(rule.patterns || [])}
                    </div>
                </div>

        `;
    },

    // Render patterns list
    renderPatternsList(patterns: string[]) {
        if (!patterns.length) {
            return `<div class="pattern-empty">No patterns. Click "Add Pattern" to create one.</div>`;
        }

        return patterns.map((pattern: string, index: number) => `
            <div class="pattern-item" 
                 draggable="true"
                 data-pattern-index="${index}">
                <div class="pattern-handle" title="Drag to reorder">⋮⋮</div>
                <span class="pattern-number">#${index + 1}</span>
                <div class="pattern-body">
                    <input type="text" value="${this.escapeHtml(pattern)}" aria-label="Detection pattern ${index + 1}"
                           data-pattern-index="${index}"
                           data-pattern-validate="${index}"
                           class="code-input">
                    <div id="pattern-status-${index}" class="pattern-status"></div>
                </div>
                <button type="button" class="btn btn-sm btn-outline btn-danger-text" data-rule-editor-action="remove-pattern" data-pattern-index="${index}" aria-label="Remove detection pattern ${index + 1}" title="Remove pattern">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                </button>
            </div>
        `).join('');
    },

    // Select a rule
    selectRule(index: number) {
        this.selectedRuleIndex = index;
        const rulesList = AdminDOM.getById('rules-list');
        if (rulesList) rulesList.innerHTML = this.renderRulesList();
        const editorContent = AdminDOM.getById('rule-editor-content');
        if (editorContent) editorContent.innerHTML = this.renderRuleDetail();
    },

    // Filter rules by search
    filterRules(query: string) {
        const list = AdminDOM.getById('rules-list');
        if (!list) return;
        const items = list.querySelectorAll<HTMLElement>('.rule-item');
        const rules = this.fileData?.rules || [];
        const lowerQuery = query.toLowerCase();

        items.forEach((item, index: number) => {
            const rule = rules[index];
            if (!rule) return;
            const matches = rule.id.toLowerCase().includes(lowerQuery) ||
                (rule.message && rule.message.toLowerCase().includes(lowerQuery));
            item.style.display = matches ? 'block' : 'none';
        });
    },

    // Update a field in the current rule
    updateField(field: string, value: unknown) {
        if (this.selectedRuleIndex < 0 || !this.fileData?.rules?.[this.selectedRuleIndex]) return;
        this.fileData.rules[this.selectedRuleIndex][field] = value;
        this.markUnsaved();
        // Update sidebar if ID changed
        if (field === 'id' || field === 'severity' || field === 'score') {
            const rulesList = AdminDOM.getById('rules-list');
            if (rulesList) rulesList.innerHTML = this.renderRulesList();
        }
    },

    // Update a pattern
    updatePattern(index: number, value: string) {
        if (this.selectedRuleIndex < 0 || !this.fileData?.rules?.[this.selectedRuleIndex]) return;
        if (!this.fileData.rules[this.selectedRuleIndex].patterns) this.fileData.rules[this.selectedRuleIndex].patterns = [];
        this.fileData.rules[this.selectedRuleIndex].patterns[index] = value;
        this.markUnsaved();
    },

    // Validate a pattern input
    async validatePatternInput(input: HTMLInputElement, index: number) {
        const statusEl = AdminDOM.getById(`pattern-status-${index}`);
        const result = await this.validatePattern(input.value);

        if (result.valid) {
            input.style.borderColor = 'var(--success)';
            if (statusEl) statusEl.innerHTML = '<span class="text-success">✓ Valid regex</span>';
        } else {
            input.style.borderColor = 'var(--danger)';
            if (statusEl) statusEl.innerHTML = `<span class="text-danger">✗ ${this.escapeHtml(result.error)}</span>`;
        }
    },

    // Add new pattern
    addPattern() {
        if (this.selectedRuleIndex < 0 || !this.fileData?.rules?.[this.selectedRuleIndex]) return;
        if (!this.fileData.rules[this.selectedRuleIndex].patterns) {
            this.fileData.rules[this.selectedRuleIndex].patterns = [];
        }
        this.fileData.rules[this.selectedRuleIndex].patterns.push('');
        this.markUnsaved();
        const editorContent = AdminDOM.getById('rule-editor-content');
        if (editorContent) editorContent.innerHTML = this.renderRuleDetail();
    },

    // Remove pattern
    removePattern(index: number) {
        if (this.selectedRuleIndex < 0 || !this.fileData?.rules?.[this.selectedRuleIndex]) return;
        this.fileData.rules[this.selectedRuleIndex].patterns.splice(index, 1);
        this.markUnsaved();
        const editorContent = AdminDOM.getById('rule-editor-content');
        if (editorContent) editorContent.innerHTML = this.renderRuleDetail();
    },

    // Handle Drag Start
    handleDragStart(e: DragEvent, index: number) {
        this.dragSrcIndex = index;
        if (e.dataTransfer) {
            e.dataTransfer.effectAllowed = 'move';
            e.dataTransfer.setData('text/plain', String(index));
        }
        const target = e.target as HTMLElement | null;
        if (target) target.style.opacity = '0.5';
    },

    // Handle Drag Over
    handleDragOver(e: DragEvent) {
        if (e.preventDefault) e.preventDefault();
        return false;
    },

    // Handle Drop
    handleDrop(e: DragEvent, dropIndex: number) {
        e.stopPropagation();
        const target = e.target as HTMLElement | null;
        const patternRow = target?.closest('.pattern-item') as HTMLElement | null;
        if (patternRow) patternRow.style.opacity = '1';

        if (this.dragSrcIndex === dropIndex) return;

        const patterns = this.fileData?.rules?.[this.selectedRuleIndex]?.patterns;
        if (!patterns) return false;
        const [movedItem] = patterns.splice(this.dragSrcIndex, 1);
        patterns.splice(dropIndex, 0, movedItem);

        this.markUnsaved();
        const editorContent = AdminDOM.getById('rule-editor-content');
        if (editorContent) editorContent.innerHTML = this.renderRuleDetail();
        return false;
    },

    // Render Source Editor
    renderSourceEditor() {
        return `
            <div class="source-wrapper">
                <textarea id="source-code" aria-label="Policy source"
                          class="source-textarea"
                          spellcheck="false"
                          placeholder="Loading source..."
                          >${this.escapeHtml(this.sourceContent)}</textarea>
                <div class="alert-warning">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                    Direct YAML editing skips validation. Use with caution.
                </div>
            </div>
        `;
    },

    // Render Rule Tester
    renderRuleTester() {
        return `
            <div class="tester-shell">
                <div class="card">
                     <div class="test-card">
                        <h3 class="m-0 text-18 font-600 text-main">Interactive Tester</h3>
                        <p class="m-0 mt-4 text-13 text-muted">Test the rules in this policy against HTTP requests.</p>
                     </div>
                     <div class="test-body">
                        <div class="mb-20">
                            <div class="test-label">Request Method & URI</div>
                            <div class="test-row">
                                <select id="test-method" class="settings-input w-120" aria-label="Request method">
                                    <option value="GET">GET</option>
                                    <option value="POST">POST</option>
                                    <option value="PUT">PUT</option>
                                    <option value="DELETE">DELETE</option>
                                </select>
                                <input type="text" id="test-uri" class="settings-input flex-1" aria-label="Request URI" placeholder="/api/login?user=' OR '1'='1" value="/test">
                            </div>
                        </div>
                        
                        <div class="mb-20">
                            <label class="test-label" for="test-headers">Headers (One per line)</label>
                            <textarea id="test-headers" class="settings-input" rows="3" placeholder="User-Agent: Mozilla/5.0&#10;Cookie: session=123"></textarea>
                        </div>
                        
                        <div class="mb-24">
                            <label class="test-label" for="test-body">Request Body</label>
                            <textarea id="test-body" class="settings-input" rows="4" placeholder='{"key": "value"}'></textarea>
                        </div>

                        <div class="flex justify-between align-center">
                            <div class="text-12 text-muted">Note: Unsaved changes to rules may not be reflected in tests.</div>
                            <button type="button" class="btn btn-primary" data-rule-editor-action="run-test">Run Test</button>
                        </div>
                     </div>
                </div>

                <div id="test-results" class="mt-24 hidden"></div>
            </div>
        `;
    },

    // Execute rule tester
    async runTester() {
        const method = getFieldValue('test-method');
        const uri = getFieldValue('test-uri');
        const headersText = getFieldValue('test-headers');
        const body = getFieldValue('test-body');
        const resultsEl = AdminDOM.getById('test-results');
        if (!resultsEl) return;

        resultsEl.classList.remove('hidden');
        resultsEl.innerHTML = '<div class="table-empty">Testing...</div>';

        // Parse headers
        const headers: Record<string, string> = {};
        if (headersText) {
            headersText.split('\\n').forEach((line: string) => {
                const parts = line.split(':');
                if (parts.length >= 2) headers[parts[0].trim()] = parts.slice(1).join(':').trim();
            });
        }

        try {
            // We use the file content from the SERVER for testing (consistent with policy tester)
            // But we might want to support current editor content?
            // Since we don't have a reliable JSON->YAML converter on client, ensuring Save is best.
            // But we can fallback to the loaded sourceContent if available from Save tab?
            // For now, let's fetch the FILE CONTENT from server again to be safe.
            const contentRes = await fetch(`/api/sections/waf_core/editor/content?file=${encodeURIComponent(this.filePath)}`);
            const ruleContent = await contentRes.text();

            const res = await fetch('/api/sections/waf_core/editor/test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    rule: ruleContent,
                    request: { method, uri, headers, body }
                })
            });
            const result = (await res.json()) as RuleTestResponse;

            // Render Result (Reuse policy tester style)
            if (result.matched) {
                resultsEl.innerHTML = `
                    <div class="alert-danger-soft">
                        <h4 class="m-0 mb-16 flex align-center gap-10 text-15 font-700 text-danger">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
                            REQUEST BLOCKED
                        </h4>
                        <div class="grid-auto-1fr">
                            <span class="text-note">Action:</span> <span class="font-600">${result.action}</span>
                            <span class="text-note">Status:</span> <span>${result.status}</span>
                            <span class="text-note">Message:</span> <span>${this.escapeHtml(result.message)}</span>
                        </div>
                        ${result.matched_variables ? `
                            <div class="mt-12 text-12">
                                <div class="font-600 mb-4">Matched Rules:</div>
                                ${result.matched_variables.map((v) => `<div class="pill pill-muted text-mono mb-2">${this.escapeHtml(v.message)}</div>`).join('')}
                            </div>
                        ` : ''}
                    </div>
                `;
            } else {
                resultsEl.innerHTML = `
                    <div class="alert-success-soft">
                        <h4 class="m-0 mb-12 flex align-center gap-10 text-15 font-700 text-success">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                            REQUEST ALLOWED
                        </h4>
                        <p class="m-0 text-13 text-muted">No rules were triggered by this request.</p>
                        <div class="mt-8 text-12 text-note">${this.escapeHtml(result.message)}</div>
                    </div>
                `;
            }
            return; // Important: Return after success
        } catch (e) {
            resultsEl.innerHTML = `<div class="alert-danger-soft text-danger">Error running test: ${this.escapeHtml(ruleEditorErrorMessage(e, 'Unknown error'))}</div>`;
        }
    },

    // Save file via API
    async saveFile() {
        if (!this.fileData) return;
        try {
            const res = await fetch(`/api/sections/waf_core/editor/file?path=${encodeURIComponent(this.filePath)}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(this.fileData)
            });
            if (!res.ok) throw new Error('Save failed');
            this.unsavedChanges = false;
            this.updateHeader();
            this.showToast('Policy saved successfully', 'success');
        } catch (e) {
            console.error('Error saving rule file:', e);
            alert('Failed to save policy: ' + ruleEditorErrorMessage(e, 'Unknown error'));
        }
    },

    // Add new rule
    addNewRule() {
        if (!this.fileData) return;

        // Use name or category for ID prefix
        const namePrefix = (this.fileData.name || this.fileData.category || 'RULE')
            .toUpperCase().split(' ').join('-');

        const newId = `${namePrefix}-NEW-${Date.now().toString(36).toUpperCase()}`;
        const newRule = {
            id: newId,
            score: 25,
            severity: 'medium',
            patterns: [],
            message: 'New rule - update this message'
        };

        if (!this.fileData.rules) this.fileData.rules = [];
        this.fileData.rules.push(newRule);
        this.selectedRuleIndex = this.fileData.rules.length - 1;
        this.markUnsaved();
        this.render();
    },

    // Delete rule
    deleteRule(index: number) {
        if (!this.fileData?.rules?.[index]) return;
        const ruleId = this.fileData.rules[index].id;
        SectionUI.openConfirmModal(
            'Delete Rule',
            `Are you sure you want to delete rule <strong>"${this.escapeHtml(ruleId)}"</strong>?`,
            'Delete',
            'var(--danger)',
            () => { RuleEditor.confirmDeleteRule(index); }
        );
    },

    confirmDeleteRule(index: number) {
        SectionUI.closeModal();
        if (!this.fileData?.rules?.[index]) return;
        this.fileData.rules.splice(index, 1);
        this.selectedRuleIndex = -1;
        this.markUnsaved();
        this.render();
    },

    // Test all patterns
    async testPatterns() {
        const testInput = getFieldValue('pattern-test-input');
        const resultsEl = AdminDOM.getById('pattern-test-results');
        if (!resultsEl) return;
        const rule = this.fileData?.rules?.[this.selectedRuleIndex];

        if (!testInput || !rule?.patterns?.length) {
            resultsEl.classList.add('hidden');
            return;
        }

        let html = '<div class="test-patterns">';
        for (let i = 0; i < rule.patterns.length; i++) {
            const result = await this.validatePattern(rule.patterns[i], testInput);
            const matchStatus = result.matches ? 'Match found' : 'No match';
            const matchText = result.matches ? ` — "${this.escapeHtml(result.matched_text)}"` : '';

            html += `
                <div class="pattern-match-line ${result.matches ? 'text-danger' : 'text-note'}">
                    <div class="pattern-match-dot ${result.matches ? 'dot-danger' : 'dot-muted'}"></div>
                    <span class="font-500">Pattern #${i + 1}:</span>
                    <span>${matchStatus}${matchText}</span>
                </div>`;
        }
        html += '</div>';
        resultsEl.innerHTML = html;
        resultsEl.classList.remove('hidden');
    },

    // Mark as unsaved
    markUnsaved() {
        this.unsavedChanges = true;
        this.updateHeader();
    },

    // Update header badge
    updateHeader() {
        const badge = AdminDOM.getById('unsaved-badge');
        if (badge) {
            badge.classList.toggle('hidden', !this.unsavedChanges);
        }
    },

    // Get severity color
    getSeverityColor(severity: string) {
        const colors: Record<string, string> = {
            critical: '#e74c3c',
            high: '#f97316',
            medium: '#f1c40f',
            low: '#27ae60',
            info: '#3498db'
        };
        return colors[severity?.toLowerCase()] || '#95a5a6';
    },

    getSeverityClass(severity: string) {
        const classes: Record<string, string> = {
            critical: 'dot-critical',
            high: 'dot-high',
            medium: 'dot-medium',
            low: 'dot-low',
            info: 'dot-info'
        };
        return classes[severity?.toLowerCase()] || 'dot-info';
    },

    // Get score color
    getScoreColor(score: number) {
        if (score >= 70) return '#e74c3c';
        if (score >= 40) return '#f97316';
        return '#27ae60';
    },

    // Duplicate a rule
    duplicateRule(index: number) {
        const original = this.fileData?.rules?.[index];
        if (!original || !this.fileData?.rules) return;
        const duplicate = {
            id: original.id + '-COPY',
            score: original.score,
            severity: original.severity,
            patterns: [...(original.patterns || [])],
            message: original.message
        };
        this.fileData.rules.splice(index + 1, 0, duplicate);
        this.selectedRuleIndex = index + 1;
        this.markUnsaved();
        this.render();
        this.showToast('Rule duplicated', 'success');
    },

    // Insert common pattern
    insertCommonPattern(pattern: string) {
        if (!pattern || this.selectedRuleIndex < 0) return;
        if (!this.fileData?.rules?.[this.selectedRuleIndex]) return;
        // Decode HTML entities
        pattern = pattern.replace(/&lt;/g, '<').replace(/&gt;/g, '>');
        if (!this.fileData.rules[this.selectedRuleIndex].patterns) {
            this.fileData.rules[this.selectedRuleIndex].patterns = [];
        }
        this.fileData.rules[this.selectedRuleIndex].patterns.push(pattern);
        this.markUnsaved();
        const editorContent = AdminDOM.getById('rule-editor-content');
        if (editorContent) editorContent.innerHTML = this.renderRuleDetail();
        this.showToast('Pattern added', 'success');
    },

    // Live test patterns as user types
    async liveTestPatterns() {
        const testInput = getFieldValue('pattern-test-input');
        const indicator = AdminDOM.getById('test-indicator');
        const rule = this.fileData?.rules?.[this.selectedRuleIndex];

        if (!testInput || !rule?.patterns?.length) {
            if (indicator) indicator.style.display = 'none';
            return;
        }

        // Check if any pattern matches
        let hasMatch = false;
        for (const pattern of rule.patterns) {
            const result = await this.validatePattern(pattern, testInput);
            if (result.matches) {
                hasMatch = true;
                break;
            }
        }

        if (indicator) {
            indicator.style.display = 'block';
            indicator.innerHTML = hasMatch
                ? '<span class="text-danger font-700 text-11 ls-1">MATCH DETECTED</span>'
                : '<span class="text-success text-11 font-600">NO MATCH</span>';
        }
    },

    // Escape HTML
    escapeHtml(str: unknown) {
        if (!str) return '';
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    },

    // Toast notification
    showToast(message: string, type: ToastType = 'info') {
        notify(message, type);
    }
};

export function initRuleEditor(filePath: string): Promise<void> {
    return RuleEditor.init(filePath);
}
