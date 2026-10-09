import {
  useState,
  useCallback,
  useEffect,
  type ReactNode,
} from 'react';
import { authApi, type UserProfile, type TokenResponse } from '../services/api';
import { AuthContext, type AuthState } from './auth-context-definition';

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>(() => {
    const storedToken = localStorage.getItem('access_token');
    const storedUser = localStorage.getItem('user');
    return {
      token: storedToken,
      user: storedUser ? (JSON.parse(storedUser) as UserProfile) : null,
      isAuthenticated: !!storedToken,
      isLoading: !!storedToken,
    };
  });

  // On mount, if we have a stored token, verify it's still valid via /auth/me
  useEffect(() => {
    if (!state.token) return;
    let cancelled = false;

    authApi
      .me()
      .then((res) => {
        if (cancelled) return;
        const user = res.data;
        localStorage.setItem('user', JSON.stringify(user));
        setState((prev) => ({
          ...prev,
          user,
          isAuthenticated: true,
          isLoading: false,
        }));
      })
      .catch(() => {
        if (cancelled) return;
        localStorage.removeItem('access_token');
        localStorage.removeItem('user');
        setState({
          token: null,
          user: null,
          isAuthenticated: false,
          isLoading: false,
        });
      });

    return () => {
      cancelled = true;
    };
  }, [state.token]);

  const login = useCallback(async (username: string, password: string) => {
    const loginResponse = await authApi.login({ username, password });
    const tokenData: TokenResponse = loginResponse.data;

    localStorage.setItem('access_token', tokenData.access_token);

    // Fetch full user profile
    const meResponse = await authApi.me();
    const user: UserProfile = meResponse.data;
    localStorage.setItem('user', JSON.stringify(user));

    setState({
      token: tokenData.access_token,
      user,
      isAuthenticated: true,
      isLoading: false,
    });
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user');
    setState({
      token: null,
      user: null,
      isAuthenticated: false,
      isLoading: false,
    });
  }, []);

  return (
    <AuthContext.Provider
      value={{
        ...state,
        login,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export default AuthProvider;
