import { createEnsureAntibotBindings } from './antibots-config-bindings.js';
import { createAntibotsBindingsDeps } from './antibots-config-bindings-deps.js';
import { createAntibotsFacadeParts } from './antibots-config-facade-parts.js';
import { createSectionFacade } from './section-facade.js';
export function createAntibotsComposition(runtime, helpers) {
    const ensureBindings = createEnsureAntibotBindings(createAntibotsBindingsDeps(runtime, {
        isModeName: (value) => helpers.isModeName(value),
        parseDatasetValue: (target) => helpers.parseDatasetValue(target),
        getNode: (id) => helpers.getNode(id)
    }));
    const parts = createAntibotsFacadeParts(runtime);
    const facade = createSectionFacade({
        target: parts.target,
        state: parts.state,
        runtime,
        service: parts.service,
        serviceMethods: parts.serviceMethods,
        view: parts.view,
        viewMethods: parts.viewMethods,
        controller: parts.controller
    });
    return { ensureBindings, facade };
}
