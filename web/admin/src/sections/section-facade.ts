function hasOwnStringKey<T extends object>(obj: T, key: string): key is Extract<keyof T, string> {
    return Object.prototype.hasOwnProperty.call(obj, key);
}

function createMethodNameGuard<const TNames extends readonly string[]>(
    names: TNames
): (name: string) => name is TNames[number] {
    const nameSet: ReadonlySet<string> = new Set(names);
    return (name: string): name is TNames[number] => nameSet.has(name);
}

type SectionMethodMap = Record<string, unknown>;

type SectionFacadeConfig<TTarget extends object, TRuntime extends object, TState> = {
    target: TTarget;
    state: TState;
    runtime: TRuntime;
    service: SectionMethodMap;
    serviceMethods: readonly string[];
    view: SectionMethodMap;
    viewMethods: readonly string[];
    controller: SectionMethodMap;
};

export function createSectionFacade<TTarget extends object, TRuntime extends object, TState>(
    config: SectionFacadeConfig<TTarget, TRuntime, TState>
): TTarget {
    const isServiceMethod = createMethodNameGuard(config.serviceMethods);
    const isViewMethod = createMethodNameGuard(config.viewMethods);

    return new Proxy(config.target, {
        get(_target, prop: string | symbol): unknown {
            if (prop === 'state') return config.state;
            if (typeof prop !== 'string') return undefined;

            if (isServiceMethod(prop) && hasOwnStringKey(config.service, prop)) {
                return config.service[prop];
            }
            if (isViewMethod(prop) && hasOwnStringKey(config.view, prop)) {
                return config.view[prop];
            }
            if (hasOwnStringKey(config.controller, prop)) {
                return config.controller[prop];
            }

            if (!hasOwnStringKey(config.runtime, prop)) return undefined;
            const value = config.runtime[prop];
            if (typeof value === 'function') {
                const callable = value as (...args: unknown[]) => unknown;
                return callable.bind(config.runtime);
            }
            return value;
        },
        set(_target, prop: string | symbol, value: unknown): boolean {
            if (typeof prop === 'string' && hasOwnStringKey(config.runtime, prop)) {
                return Reflect.set(config.runtime, prop, value);
            }
            return false;
        }
    });
}
