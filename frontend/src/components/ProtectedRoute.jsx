import React from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from './AuthContext';

export const ProtectedRoute = ({ requiredRole }) => {
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

  if (requiredRole && (!user || user.role !== requiredRole)) {
    return <Navigate to="/dashboard" replace />;
  }

  return <Outlet />;
};
