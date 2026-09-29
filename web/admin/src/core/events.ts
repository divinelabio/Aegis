export type EventRoot = Document | Element;
export type DelegateHandler<T extends Element = Element> = (event: Event, target: T) => void;

export function delegateEvent<T extends Element = Element>(
  root: EventRoot,
  eventName: string,
  selector: string,
  handler: DelegateHandler<T>
): () => void {
  const listener = (event: Event): void => {
    if (!(event.target instanceof Element)) return;
    const matched = event.target.closest(selector);
    if (!(matched instanceof Element)) return;
    if (root instanceof Element && !root.contains(matched)) return;
    handler(event, matched as T);
  };

  root.addEventListener(eventName, listener);
  return () => root.removeEventListener(eventName, listener);
}

export function bindEscape(handler: () => void, root: Document | HTMLElement = document): () => void {
  const listener = (event: Event): void => {
    if (event instanceof KeyboardEvent && event.key === 'Escape') {
      handler();
    }
  };

  root.addEventListener('keydown', listener);
  return () => root.removeEventListener('keydown', listener);
}
