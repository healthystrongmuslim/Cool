import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { apiService } from '@/lib/api';
import { toast } from 'sonner';

interface AuthContextType {
  user: string | null;
  isAdmin: boolean;
  isAuthenticated: boolean;
  login: (username: string, password: string, isAdmin?: boolean) => Promise<boolean>;
  logout: () => void;
  tokenMinutesRemaining: number;
  loading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<string | null>(null);
  const [isAdmin, setIsAdmin] = useState(false);
  const [tokenMinutesRemaining, setTokenMinutesRemaining] = useState(0);
  const [loading, setLoading] = useState(true);
  const [lastActivity, setLastActivity] = useState(Date.now());

  const isAuthenticated = !!user;

  // Activity tracking for auto-logout
  useEffect(() => {
    const updateActivity = () => {
      setLastActivity(Date.now());
    };

    const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click'];
    events.forEach(event => {
      document.addEventListener(event, updateActivity, true);
    });

    return () => {
      events.forEach(event => {
        document.removeEventListener(event, updateActivity, true);
      });
    };
  }, []);

  // Auto-logout after 3 minutes of inactivity
  useEffect(() => {
    if (!isAuthenticated) return;

    const checkInactivity = () => {
      const inactiveTime = Date.now() - lastActivity;
      const threeMinutes = 3 * 60 * 1000; 

      if (inactiveTime > threeMinutes) {
        toast.warning('Session expired due to inactivity');
        logout();
      }
    };

    const interval = setInterval(checkInactivity, 30000); // Check every 30 seconds
    return () => clearInterval(interval);
  }, [isAuthenticated, lastActivity]);

  // Token status checker
  useEffect(() => {
    if (!isAuthenticated) return;

    const checkTokenStatus = async () => {
      try {
        const status = await apiService.getTokenStatus();
        setTokenMinutesRemaining(status.minutes_remaining);
        
        if (status.minutes_remaining <= 0) {
          toast.error('Session expired');
          logout();
        } else if (status.minutes_remaining <= 5) {
          toast.warning(`Session expires in ${status.minutes_remaining} minutes`);
        }
      } catch (error) {
        console.error('Token status check failed:', error);
      }
    };

    checkTokenStatus();
    const interval = setInterval(checkTokenStatus, 60000); // Check every minute
    return () => clearInterval(interval);
  }, [isAuthenticated]);

  // Initialize auth state
  useEffect(() => {
    const initAuth = async () => {
      const token = localStorage.getItem('auth_token');
      // We still read user from local storage for instant UI render, 
      // but we will verify it immediately.
      const storedUser = localStorage.getItem('user');

      if (token && storedUser) {
        try {
          // Validate token AND ROLE with backend
          // We cast to 'any' to read the new 'role' field if TS interface isn't updated yet
          const status = await apiService.getTokenStatus() as any;
          
          setUser(status.username);
          
          // SECURITY FIX: Trust the SERVER role, not localStorage
          const serverIsAdmin = status.role === 'admin';
          setIsAdmin(serverIsAdmin);
          
          // Correct localStorage to match reality (defeats the hack)
          localStorage.setItem('is_admin', serverIsAdmin.toString());
          
        } catch (error) {
          // If token is invalid, clear storage
          localStorage.removeItem('auth_token');
          localStorage.removeItem('user');
          localStorage.removeItem('is_admin');
        }
      }
      setLoading(false);
    };

    initAuth();
  }, []);

  const login = async (username: string, password: string, isAdminLogin = false): Promise<boolean> => {
    try {
      const response = isAdminLogin 
        ? await apiService.adminLogin({ username, password })
        : await apiService.login({ username, password });

      if (response.token) {
        const serverRole = (response as any).role;
        const verifiedIsAdmin = serverRole === 'admin' || (isAdminLogin && username === 'admin');

        localStorage.setItem('auth_token', response.token);
        localStorage.setItem('user', username);
        localStorage.setItem('is_admin', verifiedIsAdmin.toString());
        
        setUser(username);
        setIsAdmin(verifiedIsAdmin);
        setLastActivity(Date.now());
        
        toast.success(`Welcome ${username}!`);
        return true;
      }
      return false;
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Login failed');
      return false;
    }
  };

  const logout = async () => {
    try {
      await apiService.logout();
    } catch (error) {
      // Silent fail
    }

    localStorage.removeItem('auth_token');
    localStorage.removeItem('user');
    localStorage.removeItem('is_admin');
    
    setUser(null);
    setIsAdmin(false);
    setTokenMinutesRemaining(0);
    
    toast.info('Logged out successfully');
  };

  return (
    <AuthContext.Provider value={{
      user,
      isAdmin,
      isAuthenticated,
      login,
      logout,
      tokenMinutesRemaining,
      loading,
    }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};