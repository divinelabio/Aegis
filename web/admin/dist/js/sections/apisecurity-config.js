// API Security configuration compatibility entrypoint.
// The runtime lives under ./apisecurity/ so the frontend can migrate to a
// modular settings architecture without changing router imports.
export { APISecurityConfigFacade } from './apisecurity/config-runtime.js';
