/**
 * HTTP Security - Payload Protection & Upload Security Coordinator
 * Assembles baseline limits, inspection profiles, and upload controls.
 */
import { SectionUI } from '../ui-components.js';
import { renderHTTPSecuritySaveButtons } from '../httpsecurity-render-helpers.js';
import { renderExtensionChips, renderFileTypePolicyModal } from './controls/extension-chips.js';
import {
    httpsecSizeToMb,
    renderBasicBodyCeiling,
    renderPayloadEnforcementProfiles
} from './render-payload-basic.js';
import {
    renderBodyExpertThreshold,
    renderBodyExpertGuards
} from './render-body-guard.js';
import {
    renderUploadPrimaryControls,
    renderUploadAdvancedControls
} from './render-upload-scanner.js';

type HTTPSecurityRenderRuntime = Record<string, any>;

export function renderHTTPSecurityPayloadProtection(runtime: HTTPSecurityRenderRuntime): string {
    return renderHTTPSecurityPayloadUploadWorkspace(runtime, 'payload');
}

export function renderHTTPSecurityUploadSecurity(runtime: HTTPSecurityRenderRuntime): string {
    return renderHTTPSecurityPayloadUploadWorkspace(runtime, 'upload');
}

function renderHTTPSecurityPayloadUploadWorkspace(
    runtime: HTTPSecurityRenderRuntime,
    workspace: 'payload' | 'upload' | 'combined'
): string {
    const view = runtime;
    const payloadProtection = view.viewModel?.payloadProtection || {};
    const uploadSecurity = view.viewModel?.uploadSecurity || {};
    const limit = payloadProtection.uploadLimit || {};
    const body = payloadProtection.requestBodyGuard || {};
    const upload = uploadSecurity.uploadProtection || {};
    const legacy = uploadSecurity.extensionFilter || {};
    const content = upload.content_rules || {};
    const archive = upload.archive_policy || {};
    const hasBodyGuard = view.canConfigure('request_body_guard');
    const hasUploadProtection = view.canConfigure('upload_protection');
    const bodyUpgrade = view.isUpgrade('request_body_guard');
    const currentSize = limit.max_body_size || '10MB';
    const currentSizeMb = httpsecSizeToMb(currentSize);
    const bodyProfile = view.getPayloadProfile();
    const inspectionProfile = view.getPayloadInspectionProfile();
    const extensionPath = hasUploadProtection ? 'upload_protection.blocked_extensions' : 'extension_filter.blocked_extensions';
    const blockedExtensions = hasUploadProtection ? (upload.blocked_extensions || []) : (legacy.blocked_extensions || []);

    const bodyCeiling = renderBasicBodyCeiling(view, limit, currentSize, currentSizeMb);
    const canOpenPayloadExpert = hasBodyGuard || bodyUpgrade;
    const customInspectionSelected = canOpenPayloadExpert && (inspectionProfile.id === 'custom' || runtime.payloadInspectionCustomSelected === true);
    const payloadProfiles = renderPayloadEnforcementProfiles(
        view,
        bodyProfile,
        inspectionProfile,
        customInspectionSelected,
        canOpenPayloadExpert
    );

    const bodyExpertThreshold = hasBodyGuard ? renderBodyExpertThreshold(body) : '';
    const bodyExpertGuardsHtml = hasBodyGuard ? renderBodyExpertGuards(body) : '';

    const uploadPrimary = hasUploadProtection ? renderUploadPrimaryControls(upload) : '';
    const uploadAdvanced = hasUploadProtection ? renderUploadAdvancedControls(upload, content, archive) : '';

    const payloadWorkspace = `
        <div class="httpsec-overview-stack httpsec-payload-upload-stack">
            ${hasBodyGuard ? SectionUI.renderOperatorSection('Payload inspection', `
                ${payloadProfiles}
            `, {
                subtitle: 'Set enforcement and parser limits.'
            }) : ''}
            ${SectionUI.renderOperatorSection('Maximum request body', bodyCeiling, {
                subtitle: 'Set the largest request body the application accepts.'
            })}
        </div>`;

    const payloadExpertPage = canOpenPayloadExpert ? `
        <div class="httpsec-overview-stack httpsec-payload-upload-stack httpsec-payload-expert-page">
            <header class="httpsec-payload-expert-header">
                ${SectionUI.renderOperatorBackButton({
                    label: 'Back to Payload Protection',
                    attrs: 'data-httpsec-action="close-payload-expert"',
                    className: 'httpsec-payload-expert-back'
                })}
                <div class="httpsec-payload-expert-title"><span>Custom inspection profile</span><h2>Expert payload tuning</h2><p>Fine-tune request parsing without changing the selected enforcement mode.</p></div>
            </header>
            ${SectionUI.renderOperatorSection('Detection threshold', bodyExpertThreshold, {
                subtitle: 'Limit how many findings a request can produce during inspection.'
            })}
            ${hasBodyGuard ? SectionUI.renderOperatorSection('Parser safeguards', bodyExpertGuardsHtml, {
                subtitle: 'Set format-specific limits for request parsing.'
            }) : ''}
        </div>` : '';

    const uploadWorkspace = `
        <div class="httpsec-overview-stack httpsec-payload-upload-stack httpsec-upload-security-workspace">
            ${SectionUI.renderOperatorSection('File type policy', `
                <div class="httpsec-upload-file-policy">
                    ${renderExtensionChips('Blocked extensions', extensionPath, blockedExtensions, 'upload-ext-add-input', { groups: true, countLabel: 'blocked' })}
                </div>
            `, {
                subtitle: 'Block unsafe or unwanted file extensions from upload.'
            })}

            ${hasUploadProtection ? `
            ${SectionUI.renderOperatorSection('Upload limits and validation', uploadPrimary, {
                subtitle: 'Everyday limits and validation rules for incoming files.'
            })}

            ${SectionUI.renderOperatorSection('Deep inspection & archive guard', uploadAdvanced)}
            ` : ''}
        </div>`;

    const workspaceContent = workspace === 'payload' ? (runtime.payloadExpertPage && canOpenPayloadExpert ? payloadExpertPage : payloadWorkspace) : workspace === 'upload' ? uploadWorkspace : `${payloadWorkspace}${uploadWorkspace}`;
    const fileTypeModal = workspace !== 'payload' && runtime.fileTypePolicyModal
        ? renderFileTypePolicyModal({
            ...runtime.fileTypePolicyModal,
            values: runtime.getField(runtime.fileTypePolicyModal.path, []) || [],
            icon: runtime.icons.file
        })
        : '';
    return `${workspaceContent}${fileTypeModal}${renderHTTPSecuritySaveButtons()}`;
}
