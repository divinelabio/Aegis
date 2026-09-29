export function delegateEvent(root, eventName, selector, handler) {
    const listener = (event) => {
        if (!(event.target instanceof Element))
            return;
        const matched = event.target.closest(selector);
        if (!(matched instanceof Element))
            return;
        if (root instanceof Element && !root.contains(matched))
            return;
        handler(event, matched);
    };
    root.addEventListener(eventName, listener);
    return () => root.removeEventListener(eventName, listener);
}
export function bindEscape(handler, root = document) {
    const listener = (event) => {
        if (event instanceof KeyboardEvent && event.key === 'Escape') {
            handler();
        }
    };
    root.addEventListener('keydown', listener);
    return () => root.removeEventListener('keydown', listener);
}
