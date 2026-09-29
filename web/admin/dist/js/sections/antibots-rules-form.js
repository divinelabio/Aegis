export function toggleAntibotRuleFields(args) {
    const fieldSelect = args.getSelect('new-rule-field');
    if (!fieldSelect)
        return;
    const field = fieldSelect.value;
    const keyContainer = args.getNode('rule-key-container');
    const keyInput = args.getInput('new-rule-key');
    const valInput = args.getInput('new-rule-val');
    const valBool = args.getSelect('new-rule-val-bool');
    const valCat = args.getSelect('new-rule-val-cat');
    if (['header', 'cookie', 'query'].includes(field) && keyContainer && keyInput) {
        keyContainer.classList.remove('is-hidden');
        keyInput.placeholder = field === 'header' ? 'X-API-Key' : (field === 'query' ? 'token' : 'session_id');
    }
    else if (keyContainer) {
        keyContainer.classList.add('is-hidden');
    }
    if (!valInput || !valBool || !valCat)
        return;
    valInput.classList.add('is-hidden');
    valBool.classList.add('is-hidden');
    valCat.classList.add('is-hidden');
    if (field === 'verified_bot' || field === 'is_headless') {
        valBool.classList.remove('is-hidden');
    }
    else if (field === 'bot_category') {
        valCat.classList.remove('is-hidden');
    }
    else {
        valInput.classList.remove('is-hidden');
    }
}
export function selectAntibotRuleAction(action, args) {
    const ruleModal = args.getNode('rule-modal');
    if (ruleModal) {
        Array.from(ruleModal.querySelectorAll('.section-choice-card-compact')).forEach((el) => {
            if (el instanceof HTMLElement)
                el.classList.remove('active');
        });
    }
    const card = args.getNode(`action-card-${action}`);
    if (card)
        card.classList.add('active');
    const actionInput = args.getInput('new-rule-action');
    if (actionInput)
        actionInput.value = action;
}
export function readNewAntibotRuleFromForm(getValue) {
    const name = getValue('new-rule-name');
    const advancedExpression = getValue('new-rule-expression').trim();
    let field = getValue('new-rule-field');
    const op = getValue('new-rule-op');
    let val = getValue('new-rule-val');
    if (field === 'verified_bot' || field === 'is_headless') {
        val = getValue('new-rule-val-bool');
    }
    else if (field === 'bot_category') {
        val = getValue('new-rule-val-cat');
    }
    const action = getValue('new-rule-action');
    const actionMap = { allow: 'allow', block: 'block', challenge: 'challenge', log: 'log' };
    const actionValue = actionMap[action] || 'log';
    if (advancedExpression) {
        if (!name)
            return { ok: false, error: 'missing-fields' };
        return {
            ok: true,
            rule: {
                id: '',
                name,
                enabled: true,
                action: actionValue,
                priority: Date.now(),
                type: 'bot',
                section: 'bot',
                mode: 'expression',
                expression: advancedExpression,
                conditions: []
            }
        };
    }
    if (['header', 'cookie', 'query'].includes(field)) {
        const key = getValue('new-rule-key').trim();
        if (!key) {
            return { ok: false, error: 'missing-key' };
        }
        field = `${field}:${key}`;
    }
    if (!name || (!val && op !== 'exists' && op !== 'not_exists')) {
        return { ok: false, error: 'missing-fields' };
    }
    const expression = `${fieldToExpressionField(field)} ${operatorToExpressionOperator(op)} ${JSON.stringify(String(val))}`;
    return {
        ok: true,
        rule: {
            id: '',
            name,
            enabled: true,
            action: actionValue,
            priority: Date.now(),
            type: 'bot',
            section: 'bot',
            mode: 'builder',
            expression,
            conditions: [{ field, operator: op, value: val }]
        }
    };
}
function fieldToExpressionField(field) {
    if (field.startsWith('header:'))
        return `http.request.headers[${JSON.stringify(field.slice(7))}]`;
    if (field.startsWith('cookie:'))
        return `http.cookie[${JSON.stringify(field.slice(7))}]`;
    if (field.startsWith('query:'))
        return `http.request.query[${JSON.stringify(field.slice(6))}]`;
    const map = {
        ip: 'ip.src',
        path: 'http.request.uri.path',
        method: 'http.request.method',
        user_agent: 'http.user_agent',
        country: 'ip.geoip.country',
        asn: 'ip.asn',
        bot_score: 'aegis.bot.score',
        verified_bot: 'aegis.bot.verified',
        is_headless: 'aegis.bot.headless',
        bot_category: 'aegis.bot.category',
        ip_reputation: 'ip.reputation.score',
        ja3: 'tls.ja3',
        ja4: 'tls.ja4'
    };
    return map[field] || field;
}
function operatorToExpressionOperator(op) {
    const map = {
        neq: 'ne',
        regex: 'matches'
    };
    return map[op] || op;
}
