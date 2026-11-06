import React, { useState } from 'react';
import {
  Form,
  Stack,
  TextInput,
  Button,
  InlineNotification,
  Link,
} from '@carbon/react';
import { Send, ArrowLeft } from '@carbon/icons-react';
import './auth.css';
import { apiService } from '../../services/api';

export const ResetRequestPage: React.FC = () => {
  const [email, setEmail] = useState<string>('');
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [sent, setSent] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim()) {
      setError('Email address is required');
      return;
    }

    setSubmitting(true);
    setError(null);
    try {
      const res = await apiService.requestPasswordReset(email.trim());
      if (res.success) {
        setSent(true);
      } else {
        setError(res.error || 'Failed to submit reset request.');
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
        <h1 className="auth-title">Reset password</h1>
        <p className="auth-subtitle">
          Enter your email address and we will send you instructions to reset your password.
        </p>

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

        {sent && (
          <InlineNotification
            kind="success"
            lowContrast
            title="Request dispatched"
            subtitle="If an account exists with this email address, a password reset link has been dispatched."
            style={{ marginBottom: '1.5rem', width: '100%' }}
          />
        )}

        {!sent ? (
          <Form id="resetForm" onSubmit={handleSubmit}>
            <Stack gap={6}>
              <TextInput
                type="email"
                id="email"
                labelText="Email address"
                placeholder="name@company.com"
                value={email}
                onChange={(e) => {
                  setEmail(e.target.value);
                  if (error) setError(null);
                }}
                size="lg"
                required
                autoFocus
              />

              <Button
                type="submit"
                id="submitBtn"
                kind="primary"
                size="lg"
                renderIcon={Send}
                disabled={submitting}
                style={{ width: '100%', maxWidth: '100%' }}
              >
                {submitting ? 'Sending...' : 'Send Reset Link'}
              </Button>
            </Stack>
          </Form>
        ) : (
          <div style={{ marginTop: '16px', textAlign: 'center' }}>
            <p style={{ fontSize: '14px', color: 'var(--cds-text-secondary)', lineHeight: '1.5', margin: '0 0 20px 0' }}>
              Please check your inbox and follow the link to reset your credentials.
            </p>
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

