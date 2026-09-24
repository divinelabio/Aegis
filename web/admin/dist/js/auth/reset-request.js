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
function initResetRequestPage() {
    const form = getElement('resetForm');
    const submitButton = getElement('submitBtn');
    if (!form || !submitButton)
        return;
    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        const email = (getInput('email')?.value || '').trim();
        if (!email)
            return;
        submitButton.disabled = true;
        submitButton.textContent = 'Sending...';
        const alertBox = getElement('alert');
        if (alertBox)
            alertBox.style.display = 'none';
        try {
            await fetch('/api/request-reset', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email })
            });
            showAlert('If an account exists with this email, you will receive a password reset link shortly.', 'success');
            form.style.display = 'none';
        }
        catch {
            showAlert('Something went wrong. Please try again.', 'error');
        }
        finally {
            submitButton.disabled = false;
            submitButton.textContent = 'Send Reset Link';
        }
    });
}
document.addEventListener('DOMContentLoaded', initResetRequestPage);
