import React from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from './AuthContext';

export const ProtectedRoute = ({ requiredRole, children }) => {
  const { token, loading, user } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-surface-container-lowest font-body-md text-on-surface-variant">
        <div className="flex flex-col items-center justify-center gap-lg animate-pulse">
          <img src="/logo.png" alt="LarShield Logo" className="h-16 object-contain" />
          <div className="flex items-center gap-sm">
            <span className="material-symbols-outlined animate-spin text-[20px] text-primary">sync</span>
            <span className="font-bold tracking-wide">Verifying LarShield Session...</span>
          </div>
        </div>
      </div>
    );
  }

  if (!token) return <Navigate to="/login" replace />;

  if (requiredRole) {
    const isMasterAuth = sessionStorage.getItem('superAdminAuth') === 'true';
    const isImpersonating = !!localStorage.getItem('original_admin_token');
    const role = user?.role;

    let hasPermission = false;
    if (Array.isArray(requiredRole)) {
      hasPermission = requiredRole.includes(role) || role === 'super_admin' || isMasterAuth;
    } else if (requiredRole === 'super_admin') {
      hasPermission = role === 'super_admin' || isMasterAuth || isImpersonating;
    } else if (requiredRole === 'admin') {
      hasPermission = role === 'admin' || role === 'super_admin' || isMasterAuth || isImpersonating;
    } else if (requiredRole === 'support_engineer') {
      hasPermission = role === 'support_engineer' || role === 'admin' || role === 'super_admin' || isMasterAuth;
    } else {
      hasPermission = role === requiredRole || role === 'super_admin' || isMasterAuth;
    }

    if (!hasPermission) {
      return <Navigate to="/dashboard" replace />;
    }
  }

  return children ? children : <Outlet />;
};
