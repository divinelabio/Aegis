export type ElementTarget = string | Element | null | undefined;
export type QueryRoot = Document | Element;

export function getById<T extends Element = HTMLElement>(id: string): T | null {
  const element = document.getElementById(id);
  return element instanceof Element ? (element as unknown as T) : null;
}

export function resolveElement(target: ElementTarget): HTMLElement | null {
  if (!target) return null;
  if (typeof target === 'string') {
    const el = getById(target);
    return el instanceof HTMLElement ? el : null;
  }
  return target instanceof HTMLElement ? target : null;
}

export function query<T extends Element = HTMLElement>(selector: string, root: QueryRoot = document): T | null {
  const element = root.querySelector(selector);
  return element instanceof Element ? (element as T) : null;
}

export function queryAll<T extends Element = HTMLElement>(selector: string, root: QueryRoot = document): T[] {
  return Array.from(root.querySelectorAll(selector)).filter((element): element is T => element instanceof Element);
}

export function getInput(id: string): HTMLInputElement | null {
  const element = document.getElementById(id);
  return element instanceof HTMLInputElement ? element : null;
}

export function getSelect(id: string): HTMLSelectElement | null {
  const element = document.getElementById(id);
  return element instanceof HTMLSelectElement ? element : null;
}

export function getTextarea(id: string): HTMLTextAreaElement | null {
  const element = document.getElementById(id);
  return element instanceof HTMLTextAreaElement ? element : null;
}

export function inputValue(id: string, fallback = ''): string {
  return getInput(id)?.value || fallback;
}

export function textareaValue(id: string, fallback = ''): string {
  return getTextarea(id)?.value || fallback;
}

export function selectValue(id: string, fallback = ''): string {
  return getSelect(id)?.value || fallback;
}

export function checkboxValue(id: string, fallback = false): boolean {
  const input = getInput(id);
  return input ? input.checked : fallback;
}

export function numberValue(id: string, fallback = 0): number {
  const parsed = Number.parseInt(inputValue(id), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function firstFile(id: string): File | null {
  return getInput(id)?.files?.[0] || null;
}

export function focusById(id: string): void {
  getById(id)?.focus();
}
