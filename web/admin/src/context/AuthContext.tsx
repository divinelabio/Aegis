import React, { createContext, useContext, useState, useEffect, useCallback, useMemo } from 'react';
import type { UserSession, LoginResult, LicenseSnapshot } from '../types';
import { apiService } from '../services/api';
import { getFeaturesForTier } from '../utils/features';

export interface AuthContextType {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: UserSession | null;
  tier: 'community' | 'professional' | 'enterprise' | string;
  isCommunity: boolean;
  isProfessional: boolean;
  isEnterprise: boolean;
  license: LicenseSnapshot | null;
  hasFeature: (featureId?: string) => boolean;
  login: (username: string, password: string, rememberMe?: boolean) => Promise<LoginResult>;
  verifyMFA: (code: string) => Promise<LoginResult>;
  logout: () => Promise<void>;
  refreshSession: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const LOCAL_STORAGE_SESSION_KEY = 'aegis_admin_session';

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(() => {
    try {
      const stored = localStorage.getItem(LOCAL_STORAGE_SESSION_KEY);
      if (stored) {
        const parsed = JSON.parse(stored);
        return Boolean(parsed && parsed.status === 'active');
      }
    } catch {
    }
    return false;
  });

  const [user, setUser] = useState<UserSession | null>(() => {
    try {
      const stored = localStorage.getItem(LOCAL_STORAGE_SESSION_KEY);
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed && parsed.status === 'active') return parsed;
      }
    } catch {
    }
    return null;
  });

  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [license, setLicense] = useState<LicenseSnapshot | null>(null);

  const fetchLicense = useCallback(async (forceRefresh = false) => {
    try {
      const snap = await apiService.getLicense(forceRefresh);
      if (snap) {
        setLicense(snap);
      }
    } catch (err) {
      console.warn('[AuthContext] Failed to fetch license snapshot:', err);
    }
  }, []);

  const refreshSession = useCallback(async () => {
    try {
      const [sessionRes, licenseSnap] = await Promise.allSettled([
        apiService.verifySession(),
        apiService.getLicense(),
      ]);

      if (licenseSnap.status === 'fulfilled' && licenseSnap.value) {
        setLicense(licenseSnap.value);
      }

      if (sessionRes.status === 'fulfilled' && sessionRes.value && sessionRes.value.status === 'active') {
        const session = sessionRes.value;
        setUser(session);
        setIsAuthenticated(true);
        try {
          localStorage.setItem(LOCAL_STORAGE_SESSION_KEY, JSON.stringify(session));
        } catch {
        }
      } else {
        const stored = localStorage.getItem(LOCAL_STORAGE_SESSION_KEY);
        if (stored) {
          try {
            const parsed = JSON.parse(stored);
            if (parsed && parsed.status === 'active') {
              setUser(parsed);
              setIsAuthenticated(true);
              return;
            }
          } catch {
          }
        }
        setUser(null);
        setIsAuthenticated(false);
        try {
          localStorage.removeItem(LOCAL_STORAGE_SESSION_KEY);
        } catch {
        }
      }
    } catch (err) {
      console.warn('[AuthContext] Session refresh error:', err);
      setUser(null);
      setIsAuthenticated(false);
      try {
        localStorage.removeItem(LOCAL_STORAGE_SESSION_KEY);
      } catch {
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshSession();

    const handleAuthRequired = () => {
      setIsAuthenticated(false);
      setUser(null);
      try {
        localStorage.removeItem(LOCAL_STORAGE_SESSION_KEY);
      } catch {
      }
      window.location.hash = '#login';
    };

    const handleLicenseChanged = () => {
      fetchLicense(true);
    };

    window.addEventListener('aegis:auth-required', handleAuthRequired);
    window.addEventListener('aegis:license-changed', handleLicenseChanged);
    return () => {
      window.removeEventListener('aegis:auth-required', handleAuthRequired);
      window.removeEventListener('aegis:license-changed', handleLicenseChanged);
    };
  }, [refreshSession, fetchLicense]);

  // Determine current edition tier
  const tier: 'community' | 'professional' | 'enterprise' = useMemo(() => {
    const rawTier = (
      license?.effective_tier ||
      license?.licensed_tier ||
      user?.edition ||
      'community'
    ).toLowerCase().trim();

    if (rawTier === 'enterprise') return 'enterprise';
    if (rawTier === 'professional' || rawTier === 'pro') return 'professional';
    return 'community';
  }, [license?.effective_tier, license?.licensed_tier, user?.edition]);

  const isCommunity = tier === 'community';
  const isProfessional = tier === 'professional';
  const isEnterprise = tier === 'enterprise';

  // Feature entitlement evaluation
  const hasFeature = useCallback(
    (featureId?: string): boolean => {
      if (!featureId) {
        return true;
      }

      // Check if user session explicit active features include featureId
      if (user?.active_features && user.active_features.includes(featureId)) {
        return true;
      }

      // Check if license features snapshot includes featureId
      if (license?.features && license.features.includes(featureId)) {
        return true;
      }

      if (!user?.active_features || user.active_features.length === 0) {
        return getFeaturesForTier(tier).includes(featureId);
      }

      return false;
    },
    [user, license, tier]
  );

  const login = async (username: string, password: string, rememberMe = false): Promise<LoginResult> => {
    setIsLoading(true);
    try {
      const result = await apiService.login(username, password, rememberMe);

      if (result.success && result.mfaRequired) {
        setIsLoading(false);
        return { success: true, mfaRequired: true };
      }

      if (result.success && result.user) {
        setUser(result.user);
        setIsAuthenticated(true);
        try {
          localStorage.setItem(LOCAL_STORAGE_SESSION_KEY, JSON.stringify(result.user));
        } catch {
        }
        fetchLicense(true);
        setIsLoading(false);
        return { success: true, user: result.user };
      }

      setIsLoading(false);
      return result;
    } catch (err: any) {
      setIsLoading(false);
      return { success: false, error: err?.message || 'Login failed.' };
    }
  };

  const verifyMFA = async (code: string): Promise<LoginResult> => {
    setIsLoading(true);
    try {
      const result = await apiService.verifyMFA(code);
      if (result.success && result.user) {
        setUser(result.user);
        setIsAuthenticated(true);
        try {
          localStorage.setItem(LOCAL_STORAGE_SESSION_KEY, JSON.stringify(result.user));
        } catch {
        }
        fetchLicense(true);
      }
      setIsLoading(false);
      return result;
    } catch (err: any) {
      setIsLoading(false);
      return { success: false, error: err?.message || 'Verification failed.' };
    }
  };

  const logout = async (): Promise<void> => {
    setIsLoading(true);
    try {
      await apiService.logout();
    } catch {
    } finally {
      setUser(null);
      setIsAuthenticated(false);
      try {
        localStorage.removeItem(LOCAL_STORAGE_SESSION_KEY);
      } catch {
      }
      setIsLoading(false);
      window.location.hash = '#login';
    }
  };

  return (
    <AuthContext.Provider
      value={{
        isAuthenticated,
        isLoading,
        user,
        tier,
        isCommunity,
        isProfessional,
        isEnterprise,
        license,
        hasFeature,
        login,
        verifyMFA,
        logout,
        refreshSession,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

/* * * Hook providing direct access to current edition tier and feature entitlement checks. */
export const useEntitlements = () => {
  const auth = useAuth();
  return {
    tier: auth.tier,
    isCommunity: auth.isCommunity,
    isProfessional: auth.isProfessional,
    isEnterprise: auth.isEnterprise,
    license: auth.license,
    hasFeature: auth.hasFeature,
    user: auth.user,
    isAuthenticated: auth.isAuthenticated,
    refreshSession: auth.refreshSession,
  };
};
