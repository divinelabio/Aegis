interface SessionUser {
  id: number | string;
  username: string;
  roleId?: number | string;
  permissions: string[];
  edition?: string;
  features: string[];
}

interface VerifySessionResponse {
  status?: string;
  csrf_token?: string;
  id?: number | string;
  username?: string;
  role_id?: number | string;
  permissions?: string[];
  edition?: string;
  active_features?: string[];
}

interface LoginResult {
  success: boolean;
  error?: string;
}

interface ApiRequestFailure {
  status: number;
  code?: string;
  message: string;
  details?: unknown;
}

interface ApiRequestResult<T> {
  data: T | null;
  error: ApiRequestFailure | null;
}

interface ApiClient {
  sessionTimeout: number | null;
  expiryTimeout?: number | null;
  sessionWarningShown: boolean;
  SESSION_DURATION: number;
  WARNING_BEFORE: number;
  activeRequests: number;
  csrfToken: string | null;
  currentUser: SessionUser | null;
  showLoading(): void;
  hideLoading(): void;
  resetSessionTimer(): void;
  get<T = unknown>(endpoint: string, options?: RequestInit): Promise<T | null>;
  post<T = unknown>(endpoint: string, data?: unknown, options?: RequestInit): Promise<T | false>;
  put<T = unknown>(endpoint: string, data?: unknown, options?: RequestInit): Promise<T | false>;
  requestResult<T = unknown>(endpoint: string, method: string, data?: unknown, options?: RequestInit): Promise<ApiRequestResult<T>>;
  request<T = unknown>(endpoint: string, method: string, data?: unknown, options?: RequestInit): Promise<T | false>;
  delete(endpoint: string): Promise<boolean>;
  logout(): Promise<void>;
  login(username: string, password: string): Promise<LoginResult>;
  getModules<T = unknown>(): Promise<T | null>;
  getStats<T = unknown>(windowValue?: string): Promise<T | null>;
  getLogs<T = unknown>(windowValue?: string): Promise<T | null>;
  hasPermission(slug: string): boolean;
  hasFeature(featureId: string): boolean;
  checkSession(): Promise<boolean>;
}
