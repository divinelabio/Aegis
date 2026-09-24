export function parseDatasetBoundValue(target, valueType) {
    const normalizedType = valueType || '';
    const rawValue = target.value;
    switch (normalizedType) {
        case 'checkbox':
            return target instanceof HTMLInputElement ? target.checked : rawValue === 'true';
        case 'number': {
            const parsed = Number.parseFloat(rawValue);
            return Number.isFinite(parsed) ? parsed : 0;
        }
        case 'string-array':
            return rawValue
                .split('\n')
                .map((entry) => entry.trim())
                .filter(Boolean);
        default:
            return rawValue;
    }
}
