import '../api.js';
import * as AdminDOM from '../core/dom.js';
function getInput(id) {
    return AdminDOM.getInput(id);
}
function getElement(id) {
    return AdminDOM.getById(id);
}
function showAlert(message, type) {
    const alertBox = getElement('alert');
    if (!alertBox)
        return;
    alertBox.textContent = message;
    alertBox.className = `alert ${type}`;
    alertBox.style.display = 'block';
}
async function parseJson(response) {
    try {
        return (await response.json());
    }
    catch {
        return null;
    }
}
function initResetConfirmPage() {
    const form = getElement('resetForm');
    const submitButton = getElement('submitBtn');
    if (!form || !submitButton)
        return;
    const params = new URLSearchParams(window.location.search);
    const token = params.get('token');
    if (!token) {
        showAlert('Invalid reset link. Missing token.', 'error');
        form.style.display = 'none';
        return;
    }
    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        const password = getInput('password')?.value || '';
        const confirmPassword = getInput('confirmPassword')?.value || '';
        if (password !== confirmPassword) {
            showAlert('Passwords do not match.', 'error');
            return;
        }
        if (password.length < 8) {
            showAlert('Password must be at least 8 characters.', 'error');
            return;
        }
        submitButton.disabled = true;
        submitButton.textContent = 'Updating...';
        const alertBox = getElement('alert');
        if (alertBox)
            alertBox.style.display = 'none';
        try {
            const response = await fetch('/api/reset-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token, password })
            });
            const data = await parseJson(response);
            if (response.ok) {
                showAlert('Password updated successfully. Redirecting...', 'success');
                form.style.display = 'none';
                window.setTimeout(() => {
                    window.location.href = '/admin/login';
                }, 2000);
                return;
            }
            showAlert(data?.error || 'Failed to update password. Link may be expired.', 'error');
            submitButton.disabled = false;
            submitButton.textContent = 'Set Password';
        }
        catch {
            showAlert('Connection error. Please try again.', 'error');
            submitButton.disabled = false;
            submitButton.textContent = 'Set Password';
        }
    });
}
document.addEventListener('DOMContentLoaded', initResetConfirmPage);
