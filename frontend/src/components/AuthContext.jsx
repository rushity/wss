import React, { createContext, useContext, useState, useEffect, useRef, useCallback } from 'react';

const AuthContext = createContext(null);

const TOKEN_KEY    = 'wss_token';
const REFRESH_KEY  = 'wss_refresh_token';

// Parse the expiry time from a JWT without any library
function getTokenExpiry(token) {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    return payload.exp ? payload.exp * 1000 : null; // convert to ms
  } catch {
    return null;
  }
}

export const AuthProvider = ({ children }) => {
  const [user, setUser]               = useState(null);
  const [token, setToken]             = useState(localStorage.getItem(TOKEN_KEY));
  const [refreshToken, setRefreshToken] = useState(localStorage.getItem(REFRESH_KEY));
  const [loading, setLoading]         = useState(true);
  const proactiveRefreshRef           = useRef(null); // holds the setTimeout handle

  // ── Core logout — clear everything ───────────────────────────────────────
  const doLogout = useCallback(() => {
    if (proactiveRefreshRef.current) clearTimeout(proactiveRefreshRef.current);
    setToken(null);
    setRefreshToken(null);
    setUser(null);
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(REFRESH_KEY);
  }, []);

  // ── Refresh access token (uses body refresh_token + HttpOnly cookie fallback)
  const refreshAccessToken = useCallback(async () => {
    const storedRefresh = localStorage.getItem(REFRESH_KEY);
    try {
      const res = await fetch('/api/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include', // send HttpOnly cookie as fallback
        body: JSON.stringify({ refresh_token: storedRefresh || '' }),
      });
      if (res.ok) {
        const data = await res.json();
        setToken(data.access_token);
        localStorage.setItem(TOKEN_KEY, data.access_token);
        if (data.refresh_token) {
          setRefreshToken(data.refresh_token);
          localStorage.setItem(REFRESH_KEY, data.refresh_token);
        }
        return data.access_token;
      }
      // Refresh failed — do NOT auto-logout. Just return null and let callers decide.
      return null;
    } catch {
      return null;
    }
  }, []);

  // ── Schedule a proactive refresh 5 minutes before the access token expires ──
  const scheduleProactiveRefresh = useCallback((accessToken) => {
    if (proactiveRefreshRef.current) clearTimeout(proactiveRefreshRef.current);
    const expiry = getTokenExpiry(accessToken);
    if (!expiry) return;

    const now       = Date.now();
    const refreshAt = expiry - 5 * 60 * 1000; // 5 min before expiry
    const delay     = Math.max(refreshAt - now, 10_000); // min 10s

    proactiveRefreshRef.current = setTimeout(async () => {
      const newToken = await refreshAccessToken();
      if (newToken) {
        scheduleProactiveRefresh(newToken); // reschedule for the new token
      }
      // If refresh failed but user is still browsing, keep them logged in
      // until they actually hit a 401 (e.g. backend was briefly down)
    }, delay);
  }, [refreshAccessToken]);

  // ── Fetch user profile from backend ───────────────────────────────────────
  const fetchProfile = useCallback(async (activeToken) => {
    try {
      const res = await fetch('/api/auth/profile', {
        headers: { 'Authorization': `Bearer ${activeToken}` },
      });
      if (res.ok) {
        const data = await res.json();
        setUser(data.user);
        setLoading(false);
        scheduleProactiveRefresh(activeToken);
        return;
      }
      if (res.status === 401) {
        // Try to silently refresh before giving up
        const newToken = await refreshAccessToken();
        if (newToken) {
          const retryRes = await fetch('/api/auth/profile', {
            headers: { 'Authorization': `Bearer ${newToken}` },
          });
          if (retryRes.ok) {
            const data = await retryRes.json();
            setUser(data.user);
            setLoading(false);
            scheduleProactiveRefresh(newToken);
            return;
          }
        }
        // Only logout if both the access token AND refresh failed (401 Unauthorized)
        doLogout();
        return;
      }
      
      // If backend is offline (502, 504), keep loading screen and retry
      if (res.status >= 500) {
        setTimeout(() => fetchProfile(activeToken), 2000);
        return;
      }
    } catch {
      // Network error — retry fetching the profile
      setTimeout(() => fetchProfile(activeToken), 2000);
    }
  }, [refreshAccessToken, scheduleProactiveRefresh, doLogout]);

  // ── Sync token changes to localStorage & fetch profile ────────────────────
  useEffect(() => {
    if (token) {
      localStorage.setItem(TOKEN_KEY, token);
      fetchProfile(token);
    } else {
      localStorage.removeItem(TOKEN_KEY);
      setUser(null);
      setLoading(false);
    }
  }, [token]); // intentionally only re-run when token changes

  // ── Login — called after successful credentials check ─────────────────────
  const login = useCallback((newToken, newRefreshToken, userData) => {
    if (proactiveRefreshRef.current) clearTimeout(proactiveRefreshRef.current);
    setToken(newToken);
    setRefreshToken(newRefreshToken);
    setUser(userData);
    localStorage.setItem(TOKEN_KEY, newToken);
    if (newRefreshToken) localStorage.setItem(REFRESH_KEY, newRefreshToken);
    scheduleProactiveRefresh(newToken);
  }, [scheduleProactiveRefresh]);

  const logout = useCallback(() => {
    doLogout();
  }, [doLogout]);

  const reloadUser = useCallback(() => {
    if (token) {
      fetchProfile(token);
    }
  }, [token, fetchProfile]);

  // ── Cleanup proactive refresh on unmount ──────────────────────────────────
  useEffect(() => {
    return () => {
      if (proactiveRefreshRef.current) clearTimeout(proactiveRefreshRef.current);
    };
  }, []);

  return (
    <AuthContext.Provider value={{ user, token, refreshToken, loading, login, logout, refreshAccessToken, reloadUser }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
