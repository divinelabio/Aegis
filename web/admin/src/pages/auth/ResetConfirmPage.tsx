import React, { useState, useEffect } from 'react';
import {
  Form,
  Stack,
  TextInput,
  PasswordInput,
  Button,
  InlineNotification,
  Link,
} from '@carbon/react';
import { CheckmarkOutline, ArrowLeft } from '@carbon/icons-react';
import './auth.css';
import { apiService } from '../../services/api';

export const ResetConfirmPage: React.FC = () => {
  const [token, setToken] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [confirmPassword, setConfirmPassword] = useState<string>('');
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [success, setSuccess] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const searchParams = new URLSearchParams(window.location.search);
    let urlToken = searchParams.get('token') || '';
    if (!urlToken && window.location.hash.includes('?')) {
      const hashParams = new URLSearchParams(window.location.hash.split('?')[1]);
      urlToken = hashParams.get('token') || '';
    }
    if (urlToken) {
      setToken(urlToken);
    } else {
      setError('Please provide a valid password reset token or request a new link.');
    }
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmedToken = token.trim();
    if (!trimmedToken) {
      setError('Missing reset token. Please enter your reset token or request a new reset link.');
      return;
    }

    if (password.length < 8) {
      setError('Password must be at least 8 characters long.');
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setSubmitting(true);
    setError(null);
    try {
      const res = await apiService.confirmPasswordReset(trimmedToken, password);
      if (res.success) {
        setSuccess(true);
      } else {
        setError(res.error || 'Failed to update password.');
      }
    } catch (err: any) {
      setError(err?.message || 'Error communicating with server.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="auth-card-shell">
      <div className="auth-card">
        <div className="auth-logo-small" style={{ marginBottom: '24px' }}></div>
        <h1 className="auth-title">New password</h1>
        <p className="auth-subtitle">Please enter a new password for your account.</p>

        {error && (
          <InlineNotification
            kind="error"
            lowContrast
            title="Reset error"
            subtitle={error}
            onCloseButtonClick={() => setError(null)}
            style={{ marginBottom: '1.5rem', width: '100%' }}
          />
        )}

        {success && (
          <InlineNotification
            kind="success"
            lowContrast
            title="Password updated"
            subtitle="Password updated successfully. You can now sign in with your new credentials."
            style={{ marginBottom: '1.5rem', width: '100%' }}
          />
        )}

        {!success ? (
          <Form id="resetForm" onSubmit={handleSubmit}>
            <Stack gap={6}>
              <TextInput
                id="token"
                labelText="Reset Token"
                placeholder="Enter or paste your reset token"
                required
                size="lg"
                value={token}
                onChange={(e) => {
                  setToken(e.target.value);
                  if (error) setError(null);
                }}
                helperText="Pre-populated from reset link if present"
              />

              <PasswordInput
                id="password"
                labelText="New password"
                placeholder="••••••••"
                required
                autoFocus={Boolean(token)}
                size="lg"
                minLength={8}
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value);
                  if (error) setError(null);
                }}
                helperText="Must be at least 8 characters"
              />

              <PasswordInput
                id="confirmPassword"
                labelText="Confirm password"
                placeholder="••••••••"
                required
                size="lg"
                minLength={8}
                value={confirmPassword}
                onChange={(e) => {
                  setConfirmPassword(e.target.value);
                  if (error) setError(null);
                }}
              />

              <Button
                type="submit"
                id="submitBtn"
                kind="primary"
                size="lg"
                renderIcon={CheckmarkOutline}
                disabled={submitting || !token.trim() || password.length < 8 || password !== confirmPassword}
                style={{ width: '100%', maxWidth: '100%' }}
              >
                {submitting ? 'Setting Password...' : 'Set Password'}
              </Button>
            </Stack>
          </Form>
        ) : (
          <div style={{ marginTop: '20px' }}>
            <Button
              kind="primary"
              size="lg"
              href="#login"
              style={{ width: '100%', maxWidth: '100%' }}
            >
              Sign in now
            </Button>
          </div>
        )}

        <div className="auth-footer-link" style={{ marginTop: '32px' }}>
          <Link href="#login" renderIcon={ArrowLeft}>
            Back to sign in
          </Link>
        </div>
      </div>
    </div>
  );
};

