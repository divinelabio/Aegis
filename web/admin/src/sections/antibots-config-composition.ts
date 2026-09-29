import { createEnsureAntibotBindings } from './antibots-config-bindings.js';
import { createAntibotsBindingsDeps } from './antibots-config-bindings-deps.js';
import { createAntibotsFacadeParts } from './antibots-config-facade-parts.js';
import type { AntibotsRuntime } from './antibots-config-facade-parts.js';
import type { AntibotModeName } from './antibots-config-shared.js';
import { createSectionFacade } from './section-facade.js';

type AntibotsCompositionHelpers = {
    isModeName(value: string): value is AntibotModeName;
    parseDatasetValue(target: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement): unknown;
    getNode(id: string): HTMLElement | null;
};

export function createAntibotsComposition(
    runtime: AntibotsRuntime,
    helpers: AntibotsCompositionHelpers
) {
    const ensureBindings = createEnsureAntibotBindings(
        createAntibotsBindingsDeps(runtime, {
            isModeName: (value): value is AntibotModeName => helpers.isModeName(value),
            parseDatasetValue: (target) => helpers.parseDatasetValue(target),
            getNode: (id) => helpers.getNode(id)
        })
    );

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
