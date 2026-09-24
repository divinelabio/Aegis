import '../api.js';
import * as AdminDOM from '../core/dom.js';
import { Toast } from '../toast.js';
function getInput(id) {
    return AdminDOM.getInput(id);
}
function getElement(id) {
    return AdminDOM.getById(id);
}
function showError(message) {
    const errorAlert = getElement('error-alert');
    const errorMsg = getElement('error-msg');
    if (!errorAlert || !errorMsg)
        return;
    errorMsg.textContent = message;
    errorAlert.style.display = 'flex';
    const card = AdminDOM.query('.login-card');
    if (card instanceof HTMLElement && typeof card.animate === 'function') {
        card.animate([
            { transform: 'translateX(0)' },
            { transform: 'translateX(-5px)' },
            { transform: 'translateX(5px)' },
            { transform: 'translateX(0)' }
        ], { duration: 300 });
    }
}
function hideError() {
    const errorAlert = getElement('error-alert');
    if (errorAlert)
        errorAlert.style.display = 'none';
}
function setSubmitState(button, disabled, text) {
    button.disabled = disabled;
    button.textContent = text;
}
function bindPasswordToggle() {
    const toggleRaw = AdminDOM.getById('togglePassword') || AdminDOM.query('#togglePassword');
    const togglePassword = toggleRaw instanceof SVGElement ? toggleRaw : null;
    const passwordInput = getInput('password');
    if (!togglePassword || !passwordInput)
        return;
    const toggleHandler = (event) => {
        if (event instanceof KeyboardEvent && event.key !== 'Enter' && event.key !== ' ')
            return;
        if (event instanceof KeyboardEvent)
            event.preventDefault();
        const isPassword = passwordInput.type === 'password' || passwordInput.getAttribute('type') === 'password';
        const nextType = isPassword ? 'text' : 'password';
        passwordInput.type = nextType;
        passwordInput.setAttribute('type', nextType);
        togglePassword.style.color = nextType === 'text' ? 'var(--primary)' : 'var(--text-muted)';
        togglePassword.setAttribute('aria-label', nextType === 'text' ? 'Hide password' : 'Show password');
    };
    togglePassword.addEventListener('click', toggleHandler);
    togglePassword.addEventListener('keydown', toggleHandler);
}
function bindErrorDismissOnInput() {
    const ids = ['username', 'password', 'mfaCode'];
    ids.forEach((id) => {
        const input = getInput(id);
        if (input)
            input.addEventListener('input', hideError);
    });
}
async function parseJsonResponse(response) {
    try {
        const text = await response.text();
        return JSON.parse(text);
    }
    catch {
        return null;
    }
}
function resolveRedirectPath() {
    const params = new URLSearchParams(window.location.search);
    return params.get('redirect') || '/admin';
}
async function submitMfaFlow(button) {
    const mfaInput = getInput('mfaCode');
    const code = (mfaInput?.value || '').replace(/\s/g, '');
    if (!code || code.length !== 6) {
        showError('Please enter a valid 6-digit code');
        return;
    }
    setSubmitState(button, true, 'Verifying...');
    try {
        const response = await fetch('/api/login/mfa', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code })
        });
        if (response.ok) {
            Toast.show('Authentication successful', 'success');
            window.setTimeout(() => {
                window.location.href = '/admin';
            }, 500);
            return;
        }
        const data = await parseJsonResponse(response);
        showError(data?.error || 'Invalid code. Please try again.');
        setSubmitState(button, false, 'Verify Code');
        if (mfaInput) {
            mfaInput.value = '';
            mfaInput.focus();
        }
    }
    catch {
        showError('Connection error');
        setSubmitState(button, false, 'Verify Code');
    }
}
function transitionToMfaMode(button) {
    setSubmitState(button, false, 'Verify Code');
    const groups = AdminDOM.queryAll('.form-group:not(#mfa-group), .remember-row');
    groups.forEach((element) => {
        if (element instanceof HTMLElement)
            element.classList.add('fade-out');
    });
    window.setTimeout(() => {
        groups.forEach((element) => {
            if (element instanceof HTMLElement)
                element.style.display = 'none';
        });
        const mfaGroup = getElement('mfa-group');
        if (mfaGroup) {
            mfaGroup.style.display = 'block';
            mfaGroup.classList.add('fade-in');
        }
        const mfaInput = getInput('mfaCode');
        if (mfaInput)
            mfaInput.focus();
        const title = AdminDOM.query('h1');
        const subtitle = AdminDOM.query('.subtitle');
        if (title instanceof HTMLElement)
            title.textContent = 'Two-Factor Auth';
        if (subtitle instanceof HTMLElement)
            subtitle.textContent = 'Enter the code from your authenticator app';
    }, 300);
}
async function submitLoginFlow(button) {
    const username = (getInput('username')?.value || '').trim();
    const password = getInput('password')?.value || '';
    const rememberMe = getInput('rememberMe')?.checked || false;
    if (!username || !password) {
        showError('Username and password are required');
        return false;
    }
    setSubmitState(button, true, 'Authenticating...');
    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, remember_me: rememberMe })
        });
        const data = await parseJsonResponse(response);
        if (!data) {
            showError('Connection failed: Invalid server response');
            setSubmitState(button, false, 'Sign In');
            return false;
        }
        if (response.status === 200 && data.status === 'mfa_required') {
            transitionToMfaMode(button);
            return true;
        }
        if (response.ok) {
            Toast.show('Login successful. Redirecting...', 'success');
            const redirectTarget = resolveRedirectPath();
            window.setTimeout(() => {
                window.location.href = redirectTarget;
            }, 1000);
            return false;
        }
        showError(data.error || 'Invalid credentials.');
        setSubmitState(button, false, 'Sign In');
        return false;
    }
    catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        showError(`Connection failed: ${message}`);
        setSubmitState(button, false, 'Sign In');
        return false;
    }
}
async function checkFirstRunSetup() {
    try {
        const res = await fetch('/api/setup/status', { headers: { Accept: 'application/json' } });
        if (res.ok) {
            const data = await res.json();
            if (data.setup_required && !data.completed && (data.user_count ?? 0) === 0) {
                window.location.replace('/admin');
            }
        }
    }
    catch {
        // Ignore network errors on setup check
    }
}
function initLoginPage() {
    void checkFirstRunSetup();
    bindPasswordToggle();
    bindErrorDismissOnInput();
    hideError();
    let mfaMode = false;
    const form = getElement('loginForm');
    const submitButton = getElement('submitBtn');
    if (!form || !submitButton)
        return;
    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        hideError();
        if (mfaMode) {
            await submitMfaFlow(submitButton);
            return;
        }
        mfaMode = await submitLoginFlow(submitButton);
    });
}
document.addEventListener('DOMContentLoaded', initLoginPage);
