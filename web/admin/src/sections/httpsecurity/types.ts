export type HTTPSecurityCapabilityStatus = 'available' | 'upgrade' | 'unsupported' | 'not_implemented';

export interface HTTPSecurityCapability {
    area: string;
    status: HTTPSecurityCapabilityStatus;
	config_supported: boolean;
	runtime_implemented: boolean;
	toggle_supported: boolean;
	upgrade_feature?: string;
    reason?: string;
    config_keys?: string[];
}

export interface HTTPSecurityFunctionInfo {
    id: string;
    name?: string;
    description?: string;
    enabled?: boolean;
    category?: string;
    capability?: Partial<HTTPSecurityCapability>;
}

export type HTTPSecurityCapabilities = Record<string, HTTPSecurityCapability>;

export interface HTTPSecurityProfile {
    id: string;
    label: string;
    note: string;
    description?: string;
}

export interface HTTPSecurityValidationResult {
    errors: string[];
    warnings: string[];
}

export type AppSecurityEditionID = 'community' | 'professional' | 'enterprise' | 'commercial' | 'unknown';

export interface AppSecurityEditionInfo {
    id: AppSecurityEditionID;
    label: string;
}

export interface AppSecurityRequestPolicyModel {
    hostValidator: unknown;
    methodEnforcer: unknown;
    contentTypeValidator: unknown;
    requestSizeGuard: unknown;
    headerManager?: unknown;
}

export interface AppSecurityPayloadProtectionModel {
    uploadLimit: unknown;
    requestBodyGuard?: unknown;
}

export interface AppSecurityUploadSecurityModel {
    extensionFilter: unknown;
    uploadProtection?: unknown;
}

export interface AppSecurityResponseProtectionModel {
    securityHeaders: unknown;
    infoHiding: unknown;
    cookieHardener: unknown;
    headerManager?: unknown;
    securityTxt: {
        contact: string;
    };
}

export interface AppSecurityOptimizationModel {
    gzip: unknown;
    htmlInjector?: unknown;
}

export interface AppSecurityViewModel {
    edition: AppSecurityEditionInfo;
    capabilities: HTTPSecurityCapabilities;
    requestPolicy: AppSecurityRequestPolicyModel;
    payloadProtection: AppSecurityPayloadProtectionModel;
    uploadSecurity: AppSecurityUploadSecurityModel;
    responseProtection: AppSecurityResponseProtectionModel;
    optimization: AppSecurityOptimizationModel;
}
