import React, { useEffect, useState } from 'react';
import {
  Grid,
  Column,
  Tabs,
  TabList,
  Tab,
  TabPanels,
  TabPanel,
  StructuredListWrapper,
  StructuredListHead,
  StructuredListRow,
  StructuredListCell,
  StructuredListBody,
  Tile,
  Form,
  Stack,
  PasswordInput,
  TextInput,
  Button,
  Tag,
  InlineNotification,
  Modal,
  ProgressIndicator,
  ProgressStep,
  CodeSnippet,
  UnorderedList,
  ListItem,
} from '@carbon/react';
import {
  UserAvatar,
  Renew,
  Password,
  QrCode,
  Copy,
  Locked,
} from '@carbon/icons-react';
import { apiService } from '../services/api';
import { useAuth } from '../context/AuthContext';
import type { ProfileDetails, MFASecretData } from '../types';
import { PageHeader } from '../components/common';

const ROLES_MAP: Record<string, string> = {
  '49d8bc43-6365-453f-a842-200faa560cd0': 'Super Admin',
  'a1b2c3d4-e5f6-7890-1234-567890abcdef': 'Super Admin',
  'b2c3d4e5-f6a7-8901-2345-678901abcdef': 'Network Admin',
  'c3d4e5f6-a7b8-9012-3456-789012abcdef': 'Security Analyst',
  'd4e5f6a7-b8c9-0123-4567-890123abcdef': 'Viewer',
  '1': 'Super Admin',
  '2': 'Network Admin',
  '3': 'Security Analyst',
  '4': 'Viewer',
  'super_admin': 'Super Admin',
  'admin': 'Admin',
  'network_admin': 'Network Admin',
  'security_analyst': 'Security Analyst',
  'viewer': 'Viewer',
};

function formatCreatedDate(dateStr?: string): string {
  if (!dateStr || dateStr.startsWith('0001-')) return '—';
  const d = new Date(dateStr);
  return Number.isNaN(d.getTime())
    ? dateStr
    : d.toLocaleString(undefined, {
        year: 'numeric',
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
      });
}

export const ProfilePage: React.FC = () => {
  const { user } = useAuth();
  const [profile, setProfile] = useState<ProfileDetails | null>(null);
  const [rolesMap, setRolesMap] = useState<Record<string, string>>(ROLES_MAP);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedTab, setSelectedTab] = useState<number>(0);
  const [notification, setNotification] = useState<{
    kind: 'error' | 'success' | 'info' | 'warning';
    message: string;
  } | null>(null);

  const [newPassword, setNewPassword] = useState<string>('');
  const [confirmPassword, setConfirmPassword] = useState<string>('');
  const [updatingPassword, setUpdatingPassword] = useState<boolean>(false);

  const [mfaModalOpen, setMfaModalOpen] = useState<boolean>(false);
  const [mfaStep, setMfaStep] = useState<1 | 2 | 3>(1);
  const [mfaSecretData, setMfaSecretData] = useState<MFASecretData | null>(null);
  const [mfaCode, setMfaCode] = useState<string>('');
  const [mfaLoading, setMfaLoading] = useState<boolean>(false);
  const [mfaError, setMfaError] = useState<string | null>(null);

  const [disableModalOpen, setDisableModalOpen] = useState<boolean>(false);
  const [disableCode, setDisableCode] = useState<string>('');
  const [disablingMfa, setDisablingMfa] = useState<boolean>(false);
  const [disableError, setDisableError] = useState<string | null>(null);

  const [copiedSecret, setCopiedSecret] = useState<boolean>(false);

  const loadProfile = async () => {
    setLoading(true);
    try {
      const [profileRes, rolesRes] = await Promise.allSettled([
        apiService.getProfile(),
        apiService.getRoles(),
      ]);

      if (profileRes.status === 'fulfilled' && profileRes.value) {
        setProfile(profileRes.value);
      } else {
        setNotification({ kind: 'error', message: 'Failed to load profile details from server.' });
      }

      if (rolesRes.status === 'fulfilled' && rolesRes.value?.data && Array.isArray(rolesRes.value.data)) {
        setRolesMap((prev) => {
          const updated = { ...prev };
          rolesRes.value.data.forEach((r) => {
            if (r.id && r.name) {
              updated[String(r.id)] = r.name;
            }
          });
          return updated;
        });
      }
    } catch {
      setNotification({ kind: 'error', message: 'Failed to load profile details from server.' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadProfile();
  }, []);

  const username = profile?.username || user?.username || 'admin';
  const roleName = (() => {
    if (profile?.role_name) return profile.role_name;
    if (user?.role_name) return user.role_name;
    const roleId = profile?.role_id ? String(profile.role_id) : (user?.role_id ? String(user.role_id) : '');
    if (roleId) {
      if (rolesMap[roleId]) return rolesMap[roleId];
      return `Role (${roleId.slice(0, 8)})`;
    }
    return 'Operator';
  })();
  const mfaActive = profile?.mfa_enabled === true;

  const handleUpdatePassword = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!newPassword || newPassword.length < 8) {
      setNotification({ kind: 'error', message: 'New password must contain at least 8 characters.' });
      return;
    }
    if (newPassword !== confirmPassword) {
      setNotification({ kind: 'error', message: 'Password confirmation does not match.' });
      return;
    }

    setUpdatingPassword(true);
    setNotification(null);
    try {
      const res = await apiService.updateProfilePassword(newPassword);
      if (res.success) {
        setNewPassword('');
        setConfirmPassword('');
        setNotification({
          kind: 'success',
          message: 'Password updated successfully. Re-authentication may be required on your next session.',
        });
      } else {
        setNotification({ kind: 'error', message: res.error || 'Failed to update password.' });
      }
    } catch (err: any) {
      setNotification({ kind: 'error', message: err?.message || 'Error communicating with server.' });
    } finally {
      setUpdatingPassword(false);
    }
  };

  const handleStartMFA = async () => {
    setMfaStep(1);
    setMfaError(null);
    setMfaCode('');
    setMfaModalOpen(true);
  };

  const handleFetchMfaSecret = async () => {
    setMfaLoading(true);
    setMfaError(null);
    try {
      const res = await apiService.setupMFA();
      if (res.success && res.data) {
        setMfaSecretData(res.data);
        setMfaStep(2);
      } else {
        setMfaError(res.error || 'Unable to generate TOTP secret. Please try again.');
      }
    } catch (err: any) {
      setMfaError(err?.message || 'Failed to initialize MFA.');
    } finally {
      setMfaLoading(false);
    }
  };

  const handleVerifyEnableMFA = async () => {
    const cleanCode = mfaCode.replace(/\s/g, '');
    if (!cleanCode || cleanCode.length !== 6) {
      setMfaError('Please enter a valid 6-digit verification code.');
      return;
    }

    setMfaLoading(true);
    setMfaError(null);
    try {
      const res = await apiService.enableMFA(cleanCode);
      if (res.success) {
        setMfaStep(3);
        if (profile) {
          setProfile({ ...profile, mfa_enabled: true });
        }
      } else {
        setMfaError(res.error || 'Invalid verification code. Please check your authenticator app.');
      }
    } catch (err: any) {
      setMfaError(err?.message || 'Failed to verify TOTP code.');
    } finally {
      setMfaLoading(false);
    }
  };

  const handleDisableMFAConfirm = async () => {
    const cleanCode = disableCode.replace(/\s/g, '');
    if (!cleanCode || cleanCode.length !== 6) {
      setDisableError('Please enter the current 6-digit verification code to confirm.');
      return;
    }

    setDisablingMfa(true);
    setDisableError(null);
    try {
      const res = await apiService.disableMFA(cleanCode);
      if (res.success) {
        setDisableModalOpen(false);
        setDisableCode('');
        if (profile) {
          setProfile({ ...profile, mfa_enabled: false });
        }
        setNotification({
          kind: 'info',
          message: 'Two-factor authentication has been disabled for this account.',
        });
      } else {
        setDisableError(res.error || 'Verification code was incorrect.');
      }
    } catch (err: any) {
      setDisableError(err?.message || 'Failed to disable MFA.');
    } finally {
      setDisablingMfa(false);
    }
  };

  const handleCopySecret = (secret: string) => {
    navigator.clipboard.writeText(secret);
    setCopiedSecret(true);
    setTimeout(() => setCopiedSecret(false), 2000);
  };

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '24px',
        padding: '32px',
        width: '100%',
        boxSizing: 'border-box',
      }}
    >
      <PageHeader
        kicker="Account"
        title="Profile"
        icon={UserAvatar}
        action={
          <Button
            kind="ghost"
            size="md"
            renderIcon={Renew}
            disabled={loading}
            onClick={loadProfile}
          >
            {loading ? 'Refreshing...' : 'Reload profile'}
          </Button>
        }
      />

      {notification && (
        <InlineNotification
          kind={notification.kind}
          title={notification.message}
          onCloseButtonClick={() => setNotification(null)}
        />
      )}

      <Tabs selectedIndex={selectedTab} onChange={({ selectedIndex }) => setSelectedTab(selectedIndex)}>
        <TabList aria-label="Administrator profile tabs">
          <Tab renderIcon={UserAvatar}>Profile details</Tab>
          <Tab renderIcon={Password}>Password</Tab>
          <Tab renderIcon={Locked}>Two-factor authentication</Tab>
        </TabList>

        <TabPanels>
          <TabPanel style={{ padding: '24px 0' }}>
            <Grid narrow fullWidth style={{ padding: 0 }}>
              <Column sm={4} md={8} lg={10} style={{ marginBottom: '24px' }}>
                <Tile style={{ height: '100%' }}>
                  <h4 style={{ margin: '0 0 6px 0', fontSize: '16px', fontWeight: 600, color: 'var(--cds-text-primary)' }}>
                    Account details
                  </h4>
                  <p style={{ margin: '0 0 20px 0', fontSize: '14px', color: 'var(--cds-text-secondary)' }}>
                    Identity attributes and access privileges for the active session.
                  </p>

                  <StructuredListWrapper isCondensed aria-label="Account details structured list">
                    <StructuredListHead>
                      <StructuredListRow head>
                        <StructuredListCell head style={{ width: '35%' }}>
                          Attribute
                        </StructuredListCell>
                        <StructuredListCell head>Value</StructuredListCell>
                      </StructuredListRow>
                    </StructuredListHead>
                    <StructuredListBody>
                      <StructuredListRow>
                        <StructuredListCell noWrap style={{ fontWeight: 600, color: 'var(--cds-text-secondary)' }}>
                          Username
                        </StructuredListCell>
                        <StructuredListCell style={{ fontWeight: 600, color: 'var(--cds-text-primary)' }}>
                          {username}
                        </StructuredListCell>
                      </StructuredListRow>

                      <StructuredListRow>
                        <StructuredListCell noWrap style={{ fontWeight: 600, color: 'var(--cds-text-secondary)' }}>
                          Assigned role
                        </StructuredListCell>
                        <StructuredListCell>
                          <Tag type="cyan" size="sm">
                            {roleName}
                          </Tag>
                        </StructuredListCell>
                      </StructuredListRow>

                      <StructuredListRow>
                        <StructuredListCell noWrap style={{ fontWeight: 600, color: 'var(--cds-text-secondary)' }}>
                          User ID
                        </StructuredListCell>
                        <StructuredListCell>
                          <CodeSnippet type="inline">
                            {String(profile?.id || '—')}
                          </CodeSnippet>
                        </StructuredListCell>
                      </StructuredListRow>

                      <StructuredListRow>
                        <StructuredListCell noWrap style={{ fontWeight: 600, color: 'var(--cds-text-secondary)' }}>
                          Email address
                        </StructuredListCell>
                        <StructuredListCell style={{ color: 'var(--cds-text-primary)' }}>
                          {profile?.email || 'admin@aegis.internal'}
                        </StructuredListCell>
                      </StructuredListRow>

                      <StructuredListRow>
                        <StructuredListCell noWrap style={{ fontWeight: 600, color: 'var(--cds-text-secondary)' }}>
                          Authentication method
                        </StructuredListCell>
                        <StructuredListCell style={{ color: 'var(--cds-text-primary)' }}>
                          Local edge control plane (Argon2id)
                        </StructuredListCell>
                      </StructuredListRow>

                      <StructuredListRow>
                        <StructuredListCell noWrap style={{ fontWeight: 600, color: 'var(--cds-text-secondary)' }}>
                          Two-factor authentication
                        </StructuredListCell>
                        <StructuredListCell>
                          <Tag type={mfaActive ? 'green' : 'cool-gray'} size="sm">
                            {mfaActive ? 'Active (TOTP)' : 'Disabled'}
                          </Tag>
                        </StructuredListCell>
                      </StructuredListRow>

                      <StructuredListRow>
                        <StructuredListCell noWrap style={{ fontWeight: 600, color: 'var(--cds-text-secondary)' }}>
                          Account created
                        </StructuredListCell>
                        <StructuredListCell style={{ color: 'var(--cds-text-secondary)' }}>
                          {formatCreatedDate(profile?.created_at)}
                        </StructuredListCell>
                      </StructuredListRow>
                    </StructuredListBody>
                  </StructuredListWrapper>
                </Tile>
              </Column>

              <Column sm={4} md={8} lg={6} style={{ marginBottom: '24px' }}>
                <Stack gap={6}>
                  <Tile>
                    <h4 style={{ margin: '0 0 6px 0', fontSize: '14px', fontWeight: 600, color: 'var(--cds-text-primary)' }}>
                      Role permissions
                    </h4>
                    <p style={{ margin: '0 0 16px 0', fontSize: '13px', color: 'var(--cds-text-secondary)', lineHeight: 1.5 }}>
                      The <strong>{roleName}</strong> role is authorized for administrative operations across edge routing, WAF core rules, bot mitigations, certificates, and system telemetry according to assigned RBAC policy.
                    </p>
                    <Tag type={roleName.toLowerCase().includes('admin') || roleName.toLowerCase().includes('super') ? 'teal' : 'cyan'} size="md">
                      {roleName.toLowerCase().includes('admin') || roleName.toLowerCase().includes('super') ? 'Full control authorization' : `${roleName} privileges`}
                    </Tag>
                  </Tile>

                  <Tile>
                    <h4 style={{ margin: '0 0 6px 0', fontSize: '14px', fontWeight: 600, color: 'var(--cds-text-primary)' }}>
                      Security recommendations
                    </h4>
                    <p style={{ margin: '0 0 16px 0', fontSize: '13px', color: 'var(--cds-text-secondary)', lineHeight: 1.5 }}>
                      {mfaActive
                        ? 'Two-factor authentication is active. Sign-in requests require verification from an enrolled authenticator app.'
                        : 'Two-factor authentication is disabled. Enable TOTP to protect administrative access.'}
                    </p>
                    {!mfaActive && (
                      <Button
                        size="sm"
                        kind="tertiary"
                        renderIcon={QrCode}
                        onClick={() => setSelectedTab(2)}
                      >
                        Set up 2FA now
                      </Button>
                    )}
                  </Tile>
                </Stack>
              </Column>
            </Grid>
          </TabPanel>

          <TabPanel style={{ padding: '24px 0' }}>
            <Grid narrow fullWidth style={{ padding: 0 }}>
              <Column sm={4} md={8} lg={16} style={{ marginBottom: '24px' }}>
                <Tile>
                  <h4 style={{ margin: '0 0 6px 0', fontSize: '16px', fontWeight: 600, color: 'var(--cds-text-primary)' }}>
                    Change password
                  </h4>
                  <p style={{ margin: '0 0 24px 0', fontSize: '14px', color: 'var(--cds-text-secondary)' }}>
                    Update administrator password. Minimum 8 characters.
                  </p>

                  <Form onSubmit={handleUpdatePassword} style={{ maxWidth: '480px' }}>
                    <Stack gap={6}>
                      <PasswordInput
                        id="profile-new-password"
                        labelText="New password"
                        placeholder="Enter new password (min. 8 characters)"
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                        autoComplete="new-password"
                      />

                      <PasswordInput
                        id="profile-confirm-password"
                        labelText="Confirm new password"
                        placeholder="Re-enter new password"
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        autoComplete="new-password"
                      />

                      <div style={{ display: 'flex', justifyContent: 'flex-start', paddingTop: '8px' }}>
                        <Button
                          type="submit"
                          kind="primary"
                          renderIcon={Password}
                          disabled={updatingPassword || !newPassword || !confirmPassword}
                        >
                          {updatingPassword ? 'Changing password...' : 'Change password'}
                        </Button>
                      </div>
                    </Stack>
                  </Form>
                </Tile>
              </Column>
            </Grid>
          </TabPanel>

          <TabPanel style={{ padding: '24px 0' }}>
            <Grid narrow fullWidth style={{ padding: 0 }}>
              <Column sm={4} md={8} lg={16} style={{ marginBottom: '24px' }}>
                <Tile>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px', marginBottom: '16px' }}>
                    <div>
                      <h4 style={{ margin: '0 0 6px 0', fontSize: '16px', fontWeight: 600, color: 'var(--cds-text-primary)' }}>
                        Time-based one-time password (TOTP)
                      </h4>
                      <p style={{ margin: 0, fontSize: '14px', color: 'var(--cds-text-secondary)' }}>
                        Require a rotating 6-digit verification code from an authenticator app upon password sign-in.
                      </p>
                    </div>
                    <Tag type={mfaActive ? 'green' : 'cool-gray'} size="md">
                      {mfaActive ? 'Active' : 'Not configured'}
                    </Tag>
                  </div>

                  <p style={{ fontSize: '14px', color: 'var(--cds-text-secondary)', lineHeight: 1.6, marginBottom: '24px' }}>
                    {mfaActive
                      ? 'Two-factor authentication is active on this account. Whenever you sign in, you will be prompted for your username, password, and the current 6-digit code from your authenticator app.'
                      : 'Two-factor authentication provides an essential additional defense against credential compromise, phishing, and unauthorized access to your edge security control plane.'}
                  </p>

                  <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                    {mfaActive ? (
                      <>
                        <Button
                          kind="tertiary"
                          size="md"
                          renderIcon={Renew}
                          onClick={handleStartMFA}
                        >
                          Reconfigure authenticator
                        </Button>
                        <Button
                          kind="danger--ghost"
                          size="md"
                          onClick={() => {
                            setDisableError(null);
                            setDisableCode('');
                            setDisableModalOpen(true);
                          }}
                        >
                          Disable two-factor authentication
                        </Button>
                      </>
                    ) : (
                      <Button
                        kind="primary"
                        size="md"
                        renderIcon={QrCode}
                        onClick={handleStartMFA}
                      >
                        Set up two-factor authentication
                      </Button>
                    )}
                  </div>
                </Tile>
              </Column>
            </Grid>
          </TabPanel>
        </TabPanels>
      </Tabs>

      <Modal
        open={mfaModalOpen}
        modalHeading="Set up two-factor authentication"
        primaryButtonText={mfaStep === 1 ? 'Begin pairing' : mfaStep === 2 ? 'Activate 2FA' : 'Done'}
        secondaryButtonText={mfaStep === 3 ? undefined : 'Cancel'}
        primaryButtonDisabled={mfaLoading || (mfaStep === 2 && mfaCode.trim().length !== 6)}
        onRequestClose={() => {
          setMfaModalOpen(false);
          setMfaSecretData(null);
          setMfaStep(1);
        }}
        onRequestSubmit={() => {
          if (mfaStep === 1) {
            handleFetchMfaSecret();
          } else if (mfaStep === 2) {
            handleVerifyEnableMFA();
          } else {
            setMfaModalOpen(false);
            setMfaStep(1);
          }
        }}
      >
        <ProgressIndicator currentIndex={mfaStep - 1} spaceEqually style={{ marginBottom: '28px' }}>
          <ProgressStep label="Pairing info" description="Step 1" />
          <ProgressStep label="Scan and verify" description="Step 2" />
          <ProgressStep label="Confirmation" description="Step 3" />
        </ProgressIndicator>

        {mfaError && (
          <div style={{ marginBottom: '16px' }}>
            <InlineNotification kind="error" title={mfaError} onCloseButtonClick={() => setMfaError(null)} />
          </div>
        )}

        {mfaStep === 1 && (
          <Stack gap={5}>
            <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.5, color: 'var(--cds-text-secondary)' }}>
              Pair this administrator account with a TOTP-compatible authenticator application
              (such as Google Authenticator, Microsoft Authenticator, 1Password, or Bitwarden).
            </p>

            <Tile>
              <h5 style={{ fontWeight: 600, fontSize: '13px', color: 'var(--cds-text-primary)', margin: '0 0 8px 0' }}>
                How it works
              </h5>
              <UnorderedList style={{ fontSize: '13px', color: 'var(--cds-text-secondary)', lineHeight: 1.6 }}>
                <ListItem>A unique, secure pairing key will be generated for your administrator account.</ListItem>
                <ListItem>Scan the QR code with your mobile authenticator app, or enter the key manually.</ListItem>
                <ListItem>Enter the rotating 6-digit code to confirm and activate protection.</ListItem>
              </UnorderedList>
            </Tile>
          </Stack>
        )}

        {mfaStep === 2 && (
          <Stack gap={5}>
            <p style={{ margin: 0, fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
              Scan the QR code below with your authenticator app, or manually copy the pairing key.
            </p>

            {mfaSecretData?.qr_image && (
              <Tile style={{ display: 'flex', justifyContent: 'center', padding: '16px', background: '#ffffff' }}>
                <img
                  src={mfaSecretData.qr_image}
                  alt="MFA QR Code"
                  style={{ width: '180px', height: '180px', display: 'block' }}
                />
              </Tile>
            )}

            {mfaSecretData?.secret && (
              <Stack gap={2}>
                <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--cds-text-secondary)' }}>
                  Manual pairing key:
                </div>
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <CodeSnippet type="single">
                      {mfaSecretData.secret}
                    </CodeSnippet>
                  </div>
                  <Button
                    kind="tertiary"
                    size="sm"
                    renderIcon={Copy}
                    hasIconOnly
                    iconDescription={copiedSecret ? 'Copied' : 'Copy key'}
                    onClick={() => handleCopySecret(mfaSecretData.secret || '')}
                  />
                </div>
              </Stack>
            )}

            <div>
              <TextInput
                id="mfa-verify-code-input"
                labelText="Verification code"
                placeholder="000000"
                maxLength={6}
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ''))}
                helperText="Enter the 6-digit code from your authenticator app."
                autoFocus
              />
            </div>
          </Stack>
        )}

        {mfaStep === 3 && (
          <Stack gap={5}>
            <InlineNotification
              kind="success"
              title="Two-factor authentication active"
              subtitle="Two-factor authentication is active. Use your authenticator app for future sign-ins."
              hideCloseButton
            />
            <Tile>
              <h5 style={{ fontWeight: 600, fontSize: '13px', color: 'var(--cds-text-primary)', margin: '0 0 8px 0' }}>
                Next steps
              </h5>
              <p style={{ margin: 0, fontSize: '13px', color: 'var(--cds-text-secondary)', lineHeight: 1.5 }}>
                Ensure your authenticator application is backed up or synced with your cloud keychain so you don't lose access to this Aegis instance.
              </p>
            </Tile>
          </Stack>
        )}
      </Modal>

      <Modal
        open={disableModalOpen}
        modalHeading="Disable two-factor authentication"
        danger
        primaryButtonText="Disable 2FA"
        secondaryButtonText="Cancel"
        primaryButtonDisabled={disablingMfa || disableCode.trim().length !== 6}
        onRequestClose={() => {
          setDisableModalOpen(false);
          setDisableCode('');
          setDisableError(null);
        }}
        onRequestSubmit={handleDisableMFAConfirm}
      >
        <Stack gap={5}>
          <p style={{ margin: 0, fontSize: '14px', color: 'var(--cds-text-secondary)' }}>
            Disabling two-factor authentication reduces account security against credential stuffing and password guessing.
          </p>

          {disableError && (
            <InlineNotification kind="error" title={disableError} onCloseButtonClick={() => setDisableError(null)} />
          )}

          <TextInput
            id="disable-mfa-code-input"
            labelText="Current 6-digit verification code"
            placeholder="000000"
            maxLength={6}
            value={disableCode}
            onChange={(e) => setDisableCode(e.target.value.replace(/\D/g, ''))}
            helperText="Enter the 6-digit code from your authenticator app."
            autoFocus
          />
        </Stack>
      </Modal>
    </div>
  );
};
