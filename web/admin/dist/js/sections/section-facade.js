function hasOwnStringKey(obj, key) {
    return Object.prototype.hasOwnProperty.call(obj, key);
}
function createMethodNameGuard(names) {
    const nameSet = new Set(names);
    return (name) => nameSet.has(name);
}
export function createSectionFacade(config) {
    const isServiceMethod = createMethodNameGuard(config.serviceMethods);
    const isViewMethod = createMethodNameGuard(config.viewMethods);
    return new Proxy(config.target, {
        get(_target, prop) {
            if (prop === 'state')
                return config.state;
            if (typeof prop !== 'string')
                return undefined;
            if (isServiceMethod(prop) && hasOwnStringKey(config.service, prop)) {
                return config.service[prop];
            }
            if (isViewMethod(prop) && hasOwnStringKey(config.view, prop)) {
                return config.view[prop];
            }
            if (hasOwnStringKey(config.controller, prop)) {
                return config.controller[prop];
            }
            if (!hasOwnStringKey(config.runtime, prop))
                return undefined;
            const value = config.runtime[prop];
            if (typeof value === 'function') {
                const callable = value;
                return callable.bind(config.runtime);
            }
            return value;
        },
        set(_target, prop, value) {
            if (typeof prop === 'string' && hasOwnStringKey(config.runtime, prop)) {
                return Reflect.set(config.runtime, prop, value);
            }
            return false;
        }
    });
}
