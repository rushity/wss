import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { useAuth } from './AuthContext';

export const OrganizationSelector = () => {
  const { user } = useAuth();
  const location = useLocation();
  const [organizations, setOrganizations] = useState([]);
  const [impersonationToken, setImpersonationToken] = useState(null);

  useEffect(() => {
    setImpersonationToken(localStorage.getItem('original_admin_token'));
  }, [location.pathname]);

  useEffect(() => {
    const fetchOrgs = async () => {
      const adminToken = localStorage.getItem('original_admin_token') || localStorage.getItem('wss_token') || sessionStorage.getItem('wss_token');
      if (!adminToken) return;
      
      try {
        const res = await fetch('/api/auth/organizations', {
          headers: { 'Authorization': `Bearer ${adminToken}` }
        });
        if (res.ok) {
          const data = await res.json();
          setOrganizations(data.organizations || []);
        }
      } catch (err) {
        console.error("Failed to fetch organizations for dropdown", err);
      }
    };
    
    const isSuperAdmin = user?.role === 'super_admin' || user?.role === 'admin' || localStorage.getItem('original_admin_token');
    if (isSuperAdmin) {
      fetchOrgs();
    }
  }, [user]);

  const handleReturnToAdmin = () => {
    const orig = localStorage.getItem('original_admin_token');
    if (orig) {
      localStorage.removeItem('original_admin_token');
      localStorage.setItem('wss_token', orig);
      window.location.href = location.pathname;
    }
  };

  const isSuperAdmin = user?.role === 'admin' || user?.role === 'super_admin' || impersonationToken;
  if (!isSuperAdmin || organizations.length === 0) return null;

  return (
    <div className="flex items-center gap-2 bg-surface-container-low px-sm py-xs rounded-md border border-outline-variant">
      <span className="font-label-sm text-label-sm text-on-surface-variant uppercase">Select Org:</span>
      <select
        className="bg-surface-container border-none outline-none rounded-md px-xs py-xs font-label-sm text-on-surface focus:outline-none w-[180px] cursor-pointer"
        value={impersonationToken ? (user?.org_id || '') : ''}
        onChange={async (e) => {
          const targetOrgId = e.target.value;
          if (!targetOrgId) {
            handleReturnToAdmin();
            return;
          }
          
          try {
            const activeToken = localStorage.getItem('original_admin_token') || localStorage.getItem('wss_token');
            const res = await fetch(`/api/auth/impersonate/${targetOrgId}`, {
              method: 'POST',
              headers: { 'Authorization': `Bearer ${activeToken}` }
            });
            
            if (res.ok) {
              const data = await res.json();
              localStorage.setItem('original_admin_token', activeToken);
              localStorage.setItem('wss_token', data.access_token);
              window.location.href = location.pathname;
            }
          } catch (err) {
            console.error("Failed to impersonate from dropdown:", err);
          }
        }}
      >
        <option value="">-- All (Admin View) --</option>
        {organizations.map(org => (
          <option key={org.id} value={org.id}>{org.name}</option>
        ))}
      </select>
    </div>
  );
};
