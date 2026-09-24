import { HTTPSEC_TABS } from './constants.js';

export function createHTTPSecurityInitialState() {
    return {
        currentTab: 'overview',
        requestControl: 'method_enforcer',
        config: {},
        effectiveState: {},
        capabilities: {},
        viewModel: null,
        edition: 'unknown',
        functions: [],
		securityTxtContact: '',
		securityTxtVerification: {
			status: 'not_configured',
			message: 'Add a contact to publish the public disclosure file.'
		},
		validationIssues: [],
		stats: {},
		tabs: HTTPSEC_TABS,
        headerManagerTab: 'resp'
    };
}
