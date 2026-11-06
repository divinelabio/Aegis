import React, { useState } from 'react';
import {
  Form,
  Stack,
  TextInput,
  PasswordInput,
  Checkbox,
  Button,
  InlineNotification,
  Link,
} from '@carbon/react';
import { ArrowRight, Login } from '@carbon/icons-react';
import './auth.css';
import { useAuth } from '../../context/AuthContext';

interface LoginPageProps {
  onSuccess?: () => void;
}

export const LoginPage: React.FC<LoginPageProps> = ({ onSuccess }) => {
  const { login, verifyMFA } = useAuth();

  const [username, setUsername] = useState<string>('admin');
  const [password, setPassword] = useState<string>('');
  const [rememberMe, setRememberMe] = useState<boolean>(true);
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const [mfaMode, setMfaMode] = useState<boolean>(false);
  const [mfaCode, setMfaCode] = useState<string>('');

  const handleCredentialsSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setError('Username and password are required');
      return;
    }

    setSubmitting(true);
    setError(null);
    try {
      const res = await login(username.trim(), password, rememberMe);
      if (res.mfaRequired) {
        setMfaMode(true);
        setError(null);
      } else if (res.success) {
        if (onSuccess) {
          onSuccess();
        } else {
          window.location.hash = '#security-events';
        }
      } else {
        setError(res.error || 'Invalid credentials');
      }
    } catch (err: any) {
      setError(err?.message || 'Connection error');
    } finally {
      setSubmitting(false);
    }
  };

  const handleMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanCode = mfaCode.replace(/\s/g, '');
    if (!cleanCode || cleanCode.length !== 6) {
      setError('Please enter a valid 6-digit code');
      return;
    }

    setSubmitting(true);
    setError(null);
    try {
      const res = await verifyMFA(cleanCode);
      if (res.success) {
        if (onSuccess) {
          onSuccess();
        } else {
          window.location.hash = '#security-events';
        }
      } else {
        setError(res.error || 'Invalid code. Please try again.');
      }
    } catch (err: any) {
      setError(err?.message || 'Connection error');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="auth-shell">
      <div className="auth-panel auth-panel-form">
        <div className="auth-form-container">
          <div className="auth-logo-small" style={{ marginBottom: '28px' }} aria-label="Aegis Logo"></div>
          <h1 className="auth-title">
            {mfaMode ? 'Two-factor authentication' : 'Log in to Aegis'}
          </h1>
          <p className="auth-subtitle">
            {mfaMode
              ? 'Enter the 6-digit verification code from your device'
              : 'Enter your credentials to access the console'}
          </p>

          {error && (
            <InlineNotification
              id="error-alert"
              kind="error"
              lowContrast
              title="Authentication error"
              subtitle={error}
              onCloseButtonClick={() => setError(null)}
              style={{ marginBottom: '1.5rem', width: '100%' }}
            />
          )}

          {!mfaMode ? (
            <Form id="loginForm" onSubmit={handleCredentialsSubmit}>
              <Stack gap={6}>
                <TextInput
                  id="username"
                  labelText="Username"
                  placeholder="Enter your username"
                  value={username}
                  onChange={(e) => {
                    setUsername(e.target.value);
                    if (error) setError(null);
                  }}
                  size="lg"
                  autoFocus
                  required
                />

                <PasswordInput
                  id="password"
                  labelText="Password"
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    if (error) setError(null);
                  }}
                  size="lg"
                  required
                />

                <div className="auth-remember-row">
                  <Checkbox
                    id="rememberMe"
                    labelText="Remember me"
                    checked={rememberMe}
                    onChange={(_e, { checked }) => setRememberMe(checked)}
                  />
                  <Link href="#request-reset" size="sm">
                    Forgot password?
                  </Link>
                </div>

                <Button
                  id="submitBtn"
                  type="submit"
                  kind="primary"
                  size="lg"
                  renderIcon={ArrowRight}
                  disabled={submitting}
                  style={{ width: '100%', maxWidth: '100%' }}
                >
                  {submitting ? 'Logging in...' : 'Log in'}
                </Button>
              </Stack>
            </Form>
          ) : (
            <Form id="mfaForm" onSubmit={handleMfaSubmit}>
              <Stack gap={6}>
                <TextInput
                  id="mfaCode"
                  labelText="Authenticator code"
                  placeholder="123456"
                  maxLength={6}
                  value={mfaCode}
                  onChange={(e) => {
                    setMfaCode(e.target.value.replace(/\D/g, ''));
                    if (error) setError(null);
                  }}
                  size="lg"
                  autoFocus
                  required
                  helperText="Enter the 6-digit verification code from your device"
                />

                <Button
                  id="submitMfaBtn"
                  type="submit"
                  kind="primary"
                  size="lg"
                  renderIcon={Login}
                  disabled={submitting || mfaCode.length !== 6}
                  style={{ width: '100%', maxWidth: '100%' }}
                >
                  {submitting ? 'Verifying...' : 'Verify code'}
                </Button>

                <Button
                  type="button"
                  kind="ghost"
                  size="md"
                  onClick={() => {
                    setMfaMode(false);
                    setMfaCode('');
                    setError(null);
                  }}
                  style={{ width: '100%', maxWidth: '100%' }}
                >
                  Back to log in
                </Button>
              </Stack>
            </Form>
          )}

          <div className="auth-footer">
            &copy; 2026 Aegis Security. All rights reserved.
          </div>
        </div>
      </div>

      <div className="auth-panel auth-panel-visual">
        <div className="auth-visual-grid"></div>
        <div className="auth-visual-copy">
          <h2>
            Web Application<br />Firewall
          </h2>
          <p>Enterprise edge protection, zero-trust access control, and proactive threat mitigation.</p>
        </div>
      </div>
    </div>
  );
};
