import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../components/AuthContext';
import { CustomModal } from '../components/CustomModal';

const AdminPageContent = () => {
  const { token } = useAuth();
  const [users, setUsers] = useState([]);
  const [organizations, setOrganizations] = useState([]);
  const [scanAccess, setScanAccess] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  
  const [sortUserCol, setSortUserCol] = useState('Email');
  const [sortUserDir, setSortUserDir] = useState('asc');

  const [sortOrgCol, setSortOrgCol] = useState('Created');
  const [sortOrgDir, setSortOrgDir] = useState('desc');

  const [promptModal, setPromptModal] = useState({ isOpen: false, title: '', desc: '', inputs: [], onConfirm: null });
  const [promptValues, setPromptValues] = useState({});

  const closePrompt = () => {
    setPromptModal({ ...promptModal, isOpen: false });
    setPromptValues({});
  };

  const handlePromptChange = (key, val) => {
    setPromptValues(prev => ({ ...prev, [key]: val }));
  };

  const fetchUsers = useCallback(async () => {
    try {
      const res = await fetch('/api/auth/users', {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setUsers(data.users);
      } else {
        setError('Failed to load users. Admin privileges required.');
      }
    } catch {
      setError('Could not connect to API.');
    }
  }, [token]);

  const fetchOrganizations = useCallback(async () => {
    try {
      const res = await fetch('/api/auth/organizations', {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setOrganizations(data.organizations || []);
      }
    } catch {
      console.error('Could not load organizations');
    }
  }, [token]);

  const fetchScanAccess = useCallback(async () => {
    try {
      const res = await fetch('/api/admin/scan-access', {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setScanAccess(data.controls || []);
      }
    } catch {
      console.error('Could not load scan access config');
    }
  }, [token]);

  const updateScanAccess = async (scanType, requiredTier, isEnabled) => {
    setMessage('');
    setError('');
    try {
      const res = await fetch(`/api/admin/scan-access/${scanType}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ required_tier: requiredTier, is_enabled: isEnabled }),
      });
      if (res.ok) {
        setMessage(`${scanType} access updated successfully.`);
        fetchScanAccess();
      } else {
        const data = await res.json();
        setError(data.message || 'Failed to update access control.');
      }
    } catch {
      setError('Could not connect to API.');
    }
  };

  useEffect(() => {
    const fetchAll = () => {
      Promise.all([fetchUsers(), fetchScanAccess(), fetchOrganizations()]).finally(() => setLoading(false));
    };
    fetchAll();
    const interval = setInterval(fetchAll, 5000);
    return () => clearInterval(interval);
  }, [fetchUsers, fetchScanAccess, fetchOrganizations]);

  const handleRoleChange = async (userId, newRole) => {
    setMessage('');
    setError('');
    try {
      const res = await fetch(`/api/auth/users/${userId}/role`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ role: newRole }),
      });
      if (res.ok) {
        setMessage(`User role updated to ${newRole}.`);
        fetchUsers();
      } else {
        const data = await res.json();
        setError(data.message || 'Failed to update role.');
      }
    } catch {
      setError('Could not connect to API.');
    }
  };

  const handleUnlock = async (userId) => {
    setMessage('');
    setError('');
    try {
      const res = await fetch(`/api/auth/users/${userId}/unlock`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` },
      });
      if (res.ok) {
        setMessage('User account unlocked.');
        fetchUsers();
      } else {
        const data = await res.json();
        setError(data.message || 'Failed to unlock user.');
      }
    } catch {
      setError('Could not connect to API.');
    }
  };

  const handleAssignScans = (org) => {
    setPromptValues({ scan_type: 'Deep', count: '1' });
    setPromptModal({
      isOpen: true,
      title: 'Assign Custom Scans',
      desc: `Grant specific scan limits for ${org.name}`,
      inputs: [
        { 
          key: 'scan_type', 
          label: 'Scan Type', 
          type: 'select',
          options: ['Quick', 'Advanced', 'Deep'] 
        },
        { key: 'count', label: 'Number of Scans', placeholder: 'e.g., 5' }
      ],
      onConfirm: async (values) => {
        try {
          const res = await fetch(`/api/auth/organizations/${org.id}/quotas`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ scan_type: values.scan_type, count: parseInt(values.count) })
          });
          if (res.ok) {
            setMessage(`${values.count} ${values.scan_type} scans assigned to ${org.name}.`);
          } else {
            const data = await res.json();
            setError(data.message || 'Failed to assign scans.');
          }
        } catch {
          setError('Could not connect to API for assigning scans.');
        }
        closePrompt();
      }
    });
  };

  const handleImpersonate = async (orgId, orgName) => {
    try {
      const res = await fetch(`/api/auth/impersonate/${orgId}`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        localStorage.setItem('original_admin_token', token);
        localStorage.setItem('wss_token', data.access_token);
        window.location.href = '/dashboard';
      } else {
        const data = await res.json();
        setError(data.message || 'Failed to impersonate organization.');
      }
    } catch {
      setError('Could not connect to API for impersonation.');
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-2xl font-label-md text-label-md text-on-surface-variant">
        <span className="material-symbols-outlined animate-spin mr-sm">sync</span>
        Loading users...
      </div>
    );
  }

  const handleUserSort = (column) => {
    if (column === 'Actions' || column === 'Role') return;
    if (sortUserCol === column) {
      setSortUserDir(sortUserDir === 'asc' ? 'desc' : 'asc');
    } else {
      setSortUserCol(column);
      setSortUserDir('asc');
    }
  };

  const handleOrgSort = (column) => {
    if (column === 'Actions') return;
    if (sortOrgCol === column) {
      setSortOrgDir(sortOrgDir === 'asc' ? 'desc' : 'asc');
    } else {
      setSortOrgCol(column);
      setSortOrgDir('asc');
    }
  };

  const getSortedUsers = () => {
    return [...users].sort((a, b) => {
      let aVal, bVal;
      switch (sortUserCol) {
        case 'Email': aVal = a.email || ''; bVal = b.email || ''; break;
        case 'Status': aVal = a.locked_until ? 1 : 0; bVal = b.locked_until ? 1 : 0; break;
        default: return 0;
      }
      if (aVal < bVal) return sortUserDir === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortUserDir === 'asc' ? 1 : -1;
      return 0;
    });
  };

  const getSortedOrgs = () => {
    return [...organizations].sort((a, b) => {
      let aVal, bVal;
      switch (sortOrgCol) {
        case 'Tenant Name': aVal = a.name || ''; bVal = b.name || ''; break;
        case 'Tier': aVal = a.subscription_tier || ''; bVal = b.subscription_tier || ''; break;
        case 'Created': aVal = new Date(a.created_at || 0).getTime(); bVal = new Date(b.created_at || 0).getTime(); break;
        default: return 0;
      }
      if (aVal < bVal) return sortOrgDir === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortOrgDir === 'asc' ? 1 : -1;
      return 0;
    });
  };

  return (
    <div className="flex flex-col gap-gutter">
      <div className="border-b border-outline-variant bg-surface-container-lowest p-lg rounded-xl shadow-sm">
        <h1 className="font-display-lg text-display-lg text-on-surface mb-sm font-bold tracking-tight">Admin Panel</h1>
        <p className="font-body-lg text-body-lg text-on-surface-variant">Manage users, roles, and account access.</p>
      </div>

      {message && (
        <div className="flex gap-sm bg-green-500/10 border border-green-500/30 rounded-lg p-md text-green-600 font-body-sm text-body-sm items-center">
          <span className="material-symbols-outlined shrink-0 text-green-500">check_circle</span>
          <div>{message}</div>
        </div>
      )}

      {error && (
        <div className="flex gap-sm bg-error-container/20 border border-error/30 rounded-lg p-md text-error font-body-sm text-body-sm items-center">
          <span className="material-symbols-outlined shrink-0">error</span>
          <div>{error}</div>
        </div>
      )}

      <div className="bg-surface-container-lowest border border-outline-variant rounded-lg shadow-sm overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-outline-variant bg-surface-container-high select-none">
              {['Email', 'Role', 'Status', 'Actions'].map((h, i) => (
                <th 
                  key={h} 
                  onClick={() => handleUserSort(h)}
                  className={`text-left px-lg py-md font-label-sm text-label-sm text-on-surface-variant uppercase tracking-wider ${i === 3 ? 'text-right' : ''} ${(h !== 'Actions' && h !== 'Role') ? 'cursor-pointer hover:bg-surface-container-highest transition-colors group' : ''}`}
                >
                  <div className={`flex items-center gap-xs ${i === 3 ? 'justify-end' : ''}`}>
                    {h}
                    {(h !== 'Actions' && h !== 'Role') && (
                      <span className={`material-symbols-outlined text-[16px] opacity-0 group-hover:opacity-50 transition-opacity ${sortUserCol === h ? 'opacity-100 group-hover:opacity-100 text-primary' : ''}`}>
                        {sortUserCol === h && sortUserDir === 'desc' ? 'arrow_downward' : 'arrow_upward'}
                      </span>
                    )}
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {getSortedUsers().map((u) => (
              <tr key={u.id} className="border-b border-outline-variant/60 last:border-0 hover:bg-surface-container-high/50 transition-colors">
                <td className="px-lg py-md font-body-md text-on-surface">{u.email}</td>
                <td className="px-lg py-md">
                  <select
                    value={u.role || 'read_only'}
                    onChange={(e) => handleRoleChange(u.id, e.target.value)}
                    className="bg-surface-container border border-outline-variant rounded px-sm py-xs font-body-sm text-on-surface cursor-pointer"
                  >
                    <option value="super_admin">Super Admin</option>
                    <option value="admin">Admin</option>
                    <option value="support_engineer">Support Engineer</option>
                    <option value="org_admin">Organization</option>
                    <option value="soc_analyst">SOC Analyst</option>
                    <option value="executive">Executive</option>
                    <option value="read_only">Read Only</option>
                  </select>
                </td>
                <td className="px-lg py-md">
                  {u.locked_until ? (
                    <span className="inline-flex items-center gap-xs bg-error-container/20 text-error px-sm py-xs rounded font-label-sm text-label-sm">
                      <span className="material-symbols-outlined text-[16px]">lock</span>
                      Locked
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-xs bg-green-500/10 text-green-600 px-sm py-xs rounded font-label-sm text-label-sm">
                      <span className="material-symbols-outlined text-[16px]">check_circle</span>
                      Active
                    </span>
                  )}
                </td>
                <td className="px-lg py-md text-right">
                  {u.locked_until && (
                    <button
                      onClick={() => handleUnlock(u.id)}
                      className="bg-primary text-on-primary px-md py-xs rounded font-label-sm text-label-sm hover:opacity-90 transition-opacity border-0 cursor-pointer"
                    >
                      Unlock
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="mt-xl border-b border-outline-variant bg-surface-container-lowest p-lg rounded-xl shadow-sm">
        <h2 className="font-headline-md text-headline-md text-on-surface mb-sm font-bold tracking-tight">Organizations</h2>
        <p className="font-body-md text-body-md text-on-surface-variant mb-lg">
          View all tenants and use Impersonation to see their Dashboard, Analytics, and Vulnerabilities.
        </p>

        <div className="bg-surface-container-lowest border border-outline-variant rounded-lg shadow-sm overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-outline-variant bg-surface-container-high select-none">
                {['Tenant Name', 'Tier', 'Created', 'Actions'].map((h, i) => (
                  <th 
                    key={h} 
                    onClick={() => handleOrgSort(h)}
                    className={`text-left px-lg py-md font-label-sm text-label-sm text-on-surface-variant uppercase tracking-wider ${i === 3 ? 'text-right' : ''} ${h !== 'Actions' ? 'cursor-pointer hover:bg-surface-container-highest transition-colors group' : ''}`}
                  >
                    <div className={`flex items-center gap-xs ${i === 3 ? 'justify-end' : ''}`}>
                      {h}
                      {h !== 'Actions' && (
                        <span className={`material-symbols-outlined text-[16px] opacity-0 group-hover:opacity-50 transition-opacity ${sortOrgCol === h ? 'opacity-100 group-hover:opacity-100 text-primary' : ''}`}>
                          {sortOrgCol === h && sortOrgDir === 'desc' ? 'arrow_downward' : 'arrow_upward'}
                        </span>
                      )}
                    </div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {getSortedOrgs().map((org) => (
                <tr key={org.id} className="border-b border-outline-variant/60 last:border-0 hover:bg-surface-container-high/50 transition-colors">
                  <td className="px-lg py-md font-label-md font-bold text-on-surface">{org.name}</td>
                  <td className="px-lg py-md font-body-sm capitalize">{org.subscription_tier || 'Free'}</td>
                  <td className="px-lg py-md font-body-sm text-on-surface-variant">
                    {org.created_at ? new Date(org.created_at).toLocaleDateString() : 'N/A'}
                  </td>
                  <td className="px-lg py-md text-right">
                    <button
                      onClick={() => handleAssignScans(org)}
                      className="text-on-surface-variant hover:text-primary transition-colors bg-transparent border-0 cursor-pointer p-1 inline-flex items-center gap-xs mr-2"
                      title="Assign Custom Scans"
                    >
                      <span className="material-symbols-outlined text-[18px]">add_box</span>
                      <span className="font-label-sm">Assign Scans</span>
                    </button>
                    <button
                      onClick={() => handleImpersonate(org.id, org.name)}
                      className="text-on-surface-variant hover:text-primary transition-colors bg-transparent border-0 cursor-pointer p-1 inline-flex items-center gap-xs"
                      title="View Dashboard Data"
                    >
                      <span className="material-symbols-outlined text-[18px]">vpn_key</span>
                      <span className="font-label-sm">Impersonate</span>
                    </button>
                  </td>
                </tr>
              ))}
              {organizations.length === 0 && (
                <tr>
                  <td colSpan="4" className="px-lg py-xl text-center text-on-surface-variant font-body-md">
                    No organizations found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="mt-xl border-b border-outline-variant bg-surface-container-lowest p-lg rounded-xl shadow-sm">
        <h2 className="font-headline-md text-headline-md text-on-surface mb-sm font-bold tracking-tight">Scanner Modes & Access</h2>
        <p className="font-body-md text-body-md text-on-surface-variant mb-lg">
          Configure which subscription plans grant access to specific scan modes. You can also completely enable or disable scan modes globally.
        </p>

        <div className="flex flex-col gap-md">
          {(scanAccess || []).map((mode) => (
            <div key={mode.scan_type} className="bg-surface-container-low border border-outline-variant rounded-lg p-md flex items-center justify-between">
              <div className="flex flex-col">
                <span className="font-label-md text-label-md text-on-surface font-bold">{mode.scan_type} Scan</span>
                <span className="font-body-sm text-body-sm text-on-surface-variant">Global Access: {mode.is_enabled ? 'Enabled' : 'Disabled'}</span>
              </div>
              
              <div className="flex items-center gap-lg">
                <div className="flex flex-col gap-xs">
                  <label className="font-label-sm text-label-sm text-on-surface-variant uppercase tracking-wider font-semibold">
                    Minimum Plan Required
                  </label>
                  <select
                    value={mode.required_tier}
                    onChange={(e) => updateScanAccess(mode.scan_type, e.target.value, mode.is_enabled)}
                    className="bg-surface-container border border-outline-variant rounded px-sm py-xs font-body-sm text-on-surface cursor-pointer focus:outline-none focus:border-primary"
                  >
                    <option value="free">Free</option>
                    <option value="pro">Pro</option>
                    <option value="enterprise">Enterprise</option>
                  </select>
                </div>

                <div className="flex flex-col gap-xs">
                  <label className="font-label-sm text-label-sm text-on-surface-variant uppercase tracking-wider font-semibold">
                    Enable Scan Mode
                  </label>
                  <label className="flex items-center cursor-pointer">
                    <div className="relative">
                      <input 
                        type="checkbox" 
                        className="sr-only" 
                        checked={mode.is_enabled}
                        onChange={(e) => updateScanAccess(mode.scan_type, mode.required_tier, e.target.checked)}
                      />
                      <div className={`block w-10 h-6 rounded-full transition-colors ${mode.is_enabled ? 'bg-primary' : 'bg-surface-container-highest'}`}></div>
                      <div className={`dot absolute left-1 top-1 bg-white w-4 h-4 rounded-full transition-transform ${mode.is_enabled ? 'transform translate-x-4' : ''}`}></div>
                    </div>
                  </label>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <CustomModal 
        isOpen={promptModal.isOpen} 
        onClose={closePrompt}
        title={promptModal.title}
        description={promptModal.desc}
        footer={
          <>
            <button onClick={closePrompt} className="px-4 py-2 text-on-surface-variant hover:bg-surface-container rounded-lg font-bold border-0 bg-transparent cursor-pointer">Cancel</button>
            <button onClick={() => promptModal.onConfirm(promptValues)} className="px-4 py-2 bg-primary text-on-primary rounded-lg font-bold border-0 cursor-pointer">Confirm</button>
          </>
        }
      >
        <div className="flex flex-col gap-4">
          {promptModal.inputs.map(input => (
            <div key={input.key} className="flex flex-col">
              <label className="text-[12px] font-bold text-on-surface-variant mb-1">{input.label}</label>
              {input.type === 'select' ? (
                <select 
                  value={promptValues[input.key] || ''} 
                  onChange={(e) => handlePromptChange(input.key, e.target.value)}
                  className="bg-surface-container border border-outline-variant rounded-lg px-3 py-2 focus:border-primary outline-none text-on-surface"
                >
                  {input.options.map(opt => <option key={opt} value={opt}>{opt}</option>)}
                </select>
              ) : (
                <input 
                  type="text" 
                  value={promptValues[input.key] || ''} 
                  onChange={(e) => handlePromptChange(input.key, e.target.value)}
                  placeholder={input.placeholder}
                  className="bg-surface-container border border-outline-variant rounded-lg px-3 py-2 focus:border-primary outline-none text-on-surface"
                />
              )}
            </div>
          ))}
        </div>
      </CustomModal>
    </div>
  );
};

import { ErrorBoundary } from '../components/ErrorBoundary';

export const AdminPage = () => (
  <ErrorBoundary>
    <AdminPageContent />
  </ErrorBoundary>
);
