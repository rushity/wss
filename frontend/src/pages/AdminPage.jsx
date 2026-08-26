import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../components/AuthContext';
import { CustomModal } from '../components/CustomModal';
import { useNavigate } from 'react-router-dom';
import { 
  Shield, 
  Users, 
  Building2, 
  Activity, 
  ShieldAlert, 
  Plus, 
  Edit3, 
  Key, 
  Search, 
  RefreshCw, 
  Lock, 
  Unlock, 
  CheckCircle2, 
  AlertCircle, 
  Sliders, 
  FileText,
  BarChart3
} from 'lucide-react';
import { ErrorBoundary } from '../components/ErrorBoundary';

const AdminPageContent = () => {
  const { token, user } = useAuth();
  const navigate = useNavigate();

  const [activeTab, setActiveTab] = useState('members'); // 'members', 'orgs', 'scan_access', 'audit'
  const [users, setUsers] = useState([]);
  const [organizations, setOrganizations] = useState([]);
  const [scanAccess, setScanAccess] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [metrics, setMetrics] = useState(null);

  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  // Search & Filter States
  const [userSearch, setUserSearch] = useState('');
  const [userRoleFilter, setUserRoleFilter] = useState('all');
  const [userOrgFilter, setUserOrgFilter] = useState('all');
  
  const [orgSearch, setOrgSearch] = useState('');

  // Sorting States
  const [sortUserCol, setSortUserCol] = useState('Email');
  const [sortUserDir, setSortUserDir] = useState('asc');

  const [sortOrgCol, setSortOrgCol] = useState('Tenant Name');
  const [sortOrgDir, setSortOrgDir] = useState('asc');

  // Modal States
  const [promptModal, setPromptModal] = useState({ isOpen: false, title: '', desc: '', inputs: [], onConfirm: null });
  const [promptValues, setPromptValues] = useState({});

  const closePrompt = () => {
    setPromptModal({ ...promptModal, isOpen: false });
    setPromptValues({});
  };

  const handlePromptChange = (key, val) => {
    setPromptValues(prev => ({ ...prev, [key]: val }));
  };

  const fetchAllData = useCallback(async () => {
    setSyncing(true);
    try {
      const activeToken = localStorage.getItem('wss_token') || token;
      if (!activeToken) {
        setLoading(false);
        setSyncing(false);
        return;
      }

      const [statsRes, accessRes] = await Promise.all([
        fetch('/api/global-stats', { headers: { 'Authorization': `Bearer ${activeToken}` } }),
        fetch('/api/admin/scan-access', { headers: { 'Authorization': `Bearer ${activeToken}` } })
      ]);

      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setMetrics(statsData.metrics || null);
        setOrganizations(statsData.tenants || []);
        setUsers(statsData.users || []);
        setAuditLogs(statsData.audit_logs || []);
      }

      if (accessRes.ok) {
        const accessData = await accessRes.json();
        setScanAccess(accessData.controls || []);
      }
    } catch (err) {
      console.error('Failed to load admin data:', err);
      setError('Could not connect to backend server.');
    } finally {
      setLoading(false);
      setSyncing(false);
    }
  }, [token]);

  useEffect(() => {
    fetchAllData();
    const interval = setInterval(fetchAllData, 5000);
    return () => clearInterval(interval);
  }, [fetchAllData]);

  // User Actions
  const handleRoleChange = async (userId, newRole) => {
    setMessage('');
    setError('');
    try {
      const activeToken = localStorage.getItem('wss_token') || token;
      const res = await fetch(`/api/auth/users/${userId}/role`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${activeToken}`,
        },
        body: JSON.stringify({ role: newRole }),
      });
      if (res.ok) {
        setMessage(`User role successfully updated to ${newRole}.`);
        fetchAllData();
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
      const activeToken = localStorage.getItem('wss_token') || token;
      const res = await fetch(`/api/auth/users/${userId}/unlock`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${activeToken}` },
      });
      if (res.ok) {
        setMessage('User account unlocked successfully.');
        fetchAllData();
      } else {
        const data = await res.json();
        setError(data.message || 'Failed to unlock user.');
      }
    } catch {
      setError('Could not connect to API.');
    }
  };

  // Organization Actions
  const handleProvisionTenant = () => {
    setPromptValues({ tier: 'none', name: '', admin_email: '' });
    setPromptModal({
      isOpen: true,
      title: 'Add New Organization',
      desc: 'Create a new tenant organization in LarShield.',
      inputs: [
        { key: 'name', label: 'Organization Name', placeholder: 'Enter organization name...' },
        { 
          key: 'tier', 
          label: 'Subscription Tier', 
          type: 'select', 
          options: [
            { label: 'None', value: 'none' },
            { label: 'Quick', value: 'quick' },
            { label: 'Advanced', value: 'advanced' },
            { label: 'Deep', value: 'deep' },
            { label: 'Enterprise (Custom)', value: 'Enterprise(Custom)' }
          ] 
        },
        { key: 'admin_email', label: 'Admin Email (Optional)', placeholder: 'admin@company.com' }
      ],
      onConfirm: async (values) => {
        if (!values.name || !values.name.trim()) {
          setError('Organization name is required.');
          closePrompt();
          return;
        }
        try {
          const activeToken = localStorage.getItem('wss_token') || token;
          const res = await fetch('/api/auth/organizations', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${activeToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: values.name, tier: values.tier, admin_email: values.admin_email })
          });
          if (res.ok) {
            setMessage('Organization created successfully.');
            fetchAllData();
          } else {
            const data = await res.json();
            setError(data.message || 'Failed to create organization.');
          }
        } catch {
          setError('Could not connect to API to create organization.');
        }
        closePrompt();
      }
    });
  };

  const handleEditTenant = (org) => {
    const rawTier = (org.tier || org.subscription_tier || 'none');
    const isCustom = rawTier.toLowerCase().includes('custom') || rawTier.toLowerCase().includes('enterprise');
    const initialTier = isCustom 
      ? 'Enterprise(Custom)' 
      : ['none', 'quick', 'advanced', 'deep'].includes(rawTier.toLowerCase()) 
        ? rawTier.toLowerCase() 
        : 'none';

    setPromptValues({ name: org.name, tier: initialTier });
    setPromptModal({
      isOpen: true,
      title: 'Edit Organization',
      desc: `Modify subscription tier and name for ${org.name}`,
      inputs: [
        { key: 'name', label: 'Organization Name', placeholder: 'Enter organization name...' },
        { 
          key: 'tier', 
          label: 'Subscription Tier', 
          type: 'select', 
          options: [
            { label: 'None', value: 'none' },
            { label: 'Quick', value: 'quick' },
            { label: 'Advanced', value: 'advanced' },
            { label: 'Deep', value: 'deep' },
            { label: 'Enterprise (Custom)', value: 'Enterprise(Custom)' }
          ] 
        }
      ],
      onConfirm: async (values) => {
        try {
          const activeToken = localStorage.getItem('wss_token') || token;
          const res = await fetch(`/api/auth/organizations/${org.id}`, {
            method: 'PUT',
            headers: { 'Authorization': `Bearer ${activeToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: values.name, tier: values.tier })
          });
          if (res.ok) {
            setMessage('Organization updated successfully.');
            fetchAllData();
          } else {
            const data = await res.json();
            setError(data.message || 'Failed to update organization.');
          }
        } catch {
          setError('Could not connect to API to update organization.');
        }
        closePrompt();
      }
    });
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
        const addedCount = parseInt(values.count);
        if (isNaN(addedCount) || addedCount <= 0) {
          setError('Please enter a valid scan count.');
          closePrompt();
          return;
        }
        try {
          const activeToken = localStorage.getItem('wss_token') || token;
          const res = await fetch(`/api/auth/organizations/${org.id}/quotas`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${activeToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ scan_type: values.scan_type, count: addedCount })
          });
          if (res.ok) {
            setMessage(`${addedCount} ${values.scan_type} scan(s) assigned to ${org.name}.`);
            fetchAllData();
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
      const activeToken = localStorage.getItem('wss_token') || token;
      const res = await fetch(`/api/auth/impersonate/${orgId}`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${activeToken}` }
      });
      if (res.ok) {
        const data = await res.json();
        localStorage.setItem('original_admin_token', activeToken);
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

  const updateScanAccess = async (scanType, requiredTier, isEnabled) => {
    setMessage('');
    setError('');
    try {
      const activeToken = localStorage.getItem('wss_token') || token;
      const res = await fetch(`/api/admin/scan-access/${scanType}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${activeToken}`,
        },
        body: JSON.stringify({ required_tier: requiredTier, is_enabled: isEnabled }),
      });
      if (res.ok) {
        setMessage(`${scanType} scan access rules updated.`);
        fetchAllData();
      } else {
        const data = await res.json();
        setError(data.message || 'Failed to update scan access control.');
      }
    } catch {
      setError('Could not connect to API.');
    }
  };

  // User Filter & Sort Logic
  const getFilteredUsers = () => {
    return (users || []).filter(u => {
      const emailMatch = !userSearch || u.email?.toLowerCase().includes(userSearch.toLowerCase()) || u.org_name?.toLowerCase().includes(userSearch.toLowerCase());
      const roleMatch = userRoleFilter === 'all' || u.role === userRoleFilter;
      const orgMatch = userOrgFilter === 'all' || (
        userOrgFilter === 'no_org' ? (!u.org_id || u.org_name?.startsWith('No Org')) : String(u.org_id) === String(userOrgFilter)
      );
      return emailMatch && roleMatch && orgMatch;
    });
  };

  const getSortedUsers = () => {
    const list = getFilteredUsers();
    return list.sort((a, b) => {
      let aVal, bVal;
      switch (sortUserCol) {
        case 'Email': aVal = a.email || ''; bVal = b.email || ''; break;
        case 'Role': aVal = a.role || ''; bVal = b.role || ''; break;
        case 'Organization': aVal = a.org_name || ''; bVal = b.org_name || ''; break;
        case 'Status': aVal = a.locked_until ? 1 : 0; bVal = b.locked_until ? 1 : 0; break;
        default: aVal = a.email || ''; bVal = b.email || '';
      }
      if (aVal < bVal) return sortUserDir === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortUserDir === 'asc' ? 1 : -1;
      return 0;
    });
  };

  const handleUserSort = (col) => {
    if (col === 'Actions') return;
    if (sortUserCol === col) {
      setSortUserDir(sortUserDir === 'asc' ? 'desc' : 'asc');
    } else {
      setSortUserCol(col);
      setSortUserDir('asc');
    }
  };

  // Org Filter & Sort Logic
  const getFilteredOrgs = () => {
    return (organizations || []).filter(org => {
      return !orgSearch || org.name?.toLowerCase().includes(orgSearch.toLowerCase()) || org.tier?.toLowerCase().includes(orgSearch.toLowerCase());
    });
  };

  const getSortedOrgs = () => {
    const list = getFilteredOrgs();
    return list.sort((a, b) => {
      let aVal, bVal;
      switch (sortOrgCol) {
        case 'Tenant Name': aVal = a.name || ''; bVal = b.name || ''; break;
        case 'Tier': aVal = a.tier || a.subscription_tier || ''; bVal = b.tier || b.subscription_tier || ''; break;
        case 'Created': aVal = new Date(a.created || a.created_at || 0).getTime(); bVal = new Date(b.created || b.created_at || 0).getTime(); break;
        default: aVal = a.name || ''; bVal = b.name || '';
      }
      if (aVal < bVal) return sortOrgDir === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortOrgDir === 'asc' ? 1 : -1;
      return 0;
    });
  };

  const handleOrgSort = (col) => {
    if (col === 'Actions' || col === 'Quotas') return;
    if (sortOrgCol === col) {
      setSortOrgDir(sortOrgDir === 'asc' ? 'desc' : 'asc');
    } else {
      setSortOrgCol(col);
      setSortOrgDir('asc');
    }
  };

  if (loading) {
    return (
      <div className="flex h-[80vh] items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
      </div>
    );
  }

  const uniqueOrgsList = Array.from(new Set((users || []).map(u => u.org_name).filter(Boolean)));

  return (
    <div className="w-full text-on-surface animate-fade-in pb-xl">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between mb-xl gap-sm border-b border-outline-variant/60 pb-md">
        <div>
          <h1 className="font-extrabold text-on-surface tracking-tight text-[24px] m-0 flex items-center gap-1.5">
            Admin <span className="text-primary">Management Console</span>
          </h1>
          <p className="font-body-md text-on-surface-variant text-[13.5px] mt-1 m-0">
            Global client oversight, organization provisioning, user role management, and system logs.
          </p>
        </div>
        <div className="flex gap-sm flex-wrap items-center">
          <button 
            onClick={fetchAllData} 
            className="flex items-center px-3.5 py-1.5 bg-surface-container border border-outline-variant text-on-surface rounded-lg hover:bg-surface-container-high transition-colors font-bold text-[12.5px] cursor-pointer shadow-2xs"
          >
            <RefreshCw className={`w-3.5 h-3.5 mr-1.5 text-primary ${syncing ? 'animate-spin' : ''}`} /> Sync Metrics
          </button>
          <button 
            onClick={() => navigate('/organization')} 
            className="flex items-center px-3.5 py-1.5 bg-surface-container border border-outline-variant text-on-surface rounded-lg hover:bg-surface-container-high transition-colors font-bold text-[12.5px] cursor-pointer shadow-2xs"
          >
            <BarChart3 className="w-3.5 h-3.5 mr-1.5 text-primary" /> Org Dashboard
          </button>
          <button 
            onClick={() => navigate('/super-admin/logs')} 
            className="flex items-center px-3.5 py-1.5 bg-surface-container border border-outline-variant text-on-surface rounded-lg hover:bg-surface-container-high transition-colors font-bold text-[12.5px] cursor-pointer shadow-2xs"
          >
            <ShieldAlert className="w-3.5 h-3.5 mr-1.5 text-primary" /> Logs & Threats
          </button>
          <button 
            onClick={handleProvisionTenant} 
            className="flex items-center px-4 py-1.5 bg-primary text-white rounded-lg hover:brightness-110 transition-all font-bold text-[13px] border-0 cursor-pointer shadow-sm"
          >
            <Plus className="w-4 h-4 mr-1" /> Add Organization
          </button>
        </div>
      </div>

      {/* Notifications */}
      {message && (
        <div className="flex gap-2 bg-green-500/10 border border-green-500/30 rounded-xl p-3 mb-md text-green-400 font-bold text-[13px] items-center animate-fade-in">
          <CheckCircle2 className="w-4 h-4 shrink-0 text-green-500" />
          <span>{message}</span>
        </div>
      )}

      {error && (
        <div className="flex gap-2 bg-error/10 border border-error/30 rounded-xl p-3 mb-md text-error font-bold text-[13px] items-center animate-fade-in">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-md mb-xl">
        {[
          { title: 'TOTAL TENANTS', value: (metrics?.total_tenants || organizations.length).toString(), icon: Building2, color: 'text-blue-500', bg: 'bg-blue-500/10 border-blue-500/20' },
          { title: 'GLOBAL USERS', value: (metrics?.global_users || users.length).toString(), icon: Users, color: 'text-purple-500', bg: 'bg-purple-500/10 border-purple-500/20' },
          { title: 'ACTIVE LICENSES', value: (metrics?.active_licenses || 0).toString(), icon: Shield, color: 'text-green-500', bg: 'bg-green-500/10 border-green-500/20' },
          { title: 'ACTIVE SCANNERS', value: (metrics?.active_scanners || 0).toString(), icon: Activity, color: 'text-orange-500', bg: 'bg-orange-500/10 border-orange-500/20' }
        ].map((m, i) => (
          <div key={i} className="bg-surface-container-lowest border border-outline-variant p-lg rounded-2xl shadow-2xs hover:shadow-md transition-all group">
            <div className="flex justify-between items-center">
              <div>
                <p className="text-on-surface-variant font-bold text-[12px] uppercase tracking-wider mb-1.5">{m.title}</p>
                <h3 className="text-[30px] font-extrabold tracking-tight text-on-surface leading-none">{m.value}</h3>
              </div>
              <div className={`${m.bg} p-3 rounded-xl border group-hover:scale-110 transition-transform flex items-center justify-center`}>
                <m.icon className={`${m.color} w-6 h-6`} />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Tab Controls Bar */}
      <div className="flex items-center gap-2 mb-lg border-b border-outline-variant/60 pb-sm">
        <button
          onClick={() => setActiveTab('members')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg font-bold text-[13px] transition-all cursor-pointer border-0 ${
            activeTab === 'members' 
              ? 'bg-primary text-white shadow-md shadow-primary/20' 
              : 'bg-surface-container text-on-surface-variant hover:bg-surface-container-high'
          }`}
        >
          <Users className="w-4 h-4" /> Global Members ({users.length})
        </button>

        <button
          onClick={() => setActiveTab('orgs')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg font-bold text-[13px] transition-all cursor-pointer border-0 ${
            activeTab === 'orgs' 
              ? 'bg-primary text-white shadow-md shadow-primary/20' 
              : 'bg-surface-container text-on-surface-variant hover:bg-surface-container-high'
          }`}
        >
          <Building2 className="w-4 h-4" /> Organizations & Quotas ({organizations.length})
        </button>

        <button
          onClick={() => setActiveTab('scan_access')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg font-bold text-[13px] transition-all cursor-pointer border-0 ${
            activeTab === 'scan_access' 
              ? 'bg-primary text-white shadow-md shadow-primary/20' 
              : 'bg-surface-container text-on-surface-variant hover:bg-surface-container-high'
          }`}
        >
          <Sliders className="w-4 h-4" /> Scanner Modes & Access
        </button>

        <button
          onClick={() => setActiveTab('audit')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg font-bold text-[13px] transition-all cursor-pointer border-0 ${
            activeTab === 'audit' 
              ? 'bg-primary text-white shadow-md shadow-primary/20' 
              : 'bg-surface-container text-on-surface-variant hover:bg-surface-container-high'
          }`}
        >
          <FileText className="w-4 h-4" /> Audit Trail
        </button>
      </div>

      {/* Tab 1: Global Members */}
      {activeTab === 'members' && (
        <div className="bg-surface-container-lowest border border-outline-variant rounded-2xl shadow-sm overflow-hidden p-lg">
          <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-md mb-lg">
            <div>
              <h2 className="font-extrabold text-on-surface text-[18px] m-0">Global User Accounts</h2>
              <p className="text-on-surface-variant text-[13px] mt-0.5 m-0">Manage roles, permissions, and account status across all organizations.</p>
            </div>
            
            <div className="flex gap-sm flex-wrap w-full md:w-auto">
              <div className="relative flex-1 md:w-64">
                <Search className="w-4 h-4 absolute left-3 top-2.5 text-on-surface-variant" />
                <input 
                  type="text"
                  placeholder="Search email or org..."
                  value={userSearch}
                  onChange={e => setUserSearch(e.target.value)}
                  className="w-full bg-surface-container border border-outline-variant rounded-lg pl-9 pr-3 py-1.5 text-[13px] outline-none focus:border-primary text-on-surface font-medium"
                />
              </div>

              <select
                value={userRoleFilter}
                onChange={e => setUserRoleFilter(e.target.value)}
                className="bg-surface-container border border-outline-variant rounded-lg px-3 py-1.5 text-[13px] font-bold outline-none text-on-surface"
              >
                <option value="all">All Roles</option>
                <option value="super_admin">Super Admin</option>
                <option value="admin">Admin</option>
                <option value="support_engineer">Support Engineer</option>
                <option value="org_admin">Organization Admin</option>
                <option value="soc_analyst">SOC Analyst</option>
                <option value="executive_user">Executive</option>
                <option value="read_only">Read Only</option>
              </select>

              <select
                value={userOrgFilter}
                onChange={e => setUserOrgFilter(e.target.value)}
                className="bg-surface-container border border-outline-variant rounded-lg px-3 py-1.5 text-[13px] font-bold outline-none text-on-surface"
              >
                <option value="all">All Organizations</option>
                <option value="no_org">No Org (Global Role)</option>
                {organizations.map(org => <option key={org.id} value={org.id}>{org.name}</option>)}
              </select>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-outline-variant bg-surface-container-high/60 select-none">
                  {['Email', 'Role', 'Organization', 'Status', 'Actions'].map((col) => (
                    <th 
                      key={col}
                      onClick={() => handleUserSort(col)}
                      className={`px-4 py-3 text-[12px] font-bold uppercase tracking-wider text-on-surface-variant ${col === 'Actions' ? 'text-right' : 'cursor-pointer hover:text-primary'}`}
                    >
                      {col} {sortUserCol === col ? (sortUserDir === 'asc' ? '↑' : '↓') : ''}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {getSortedUsers().map((u) => (
                  <tr key={u.id} className="border-b border-outline-variant/40 hover:bg-surface-container-high/30 transition-colors">
                    <td className="px-4 py-3 font-bold text-[13.5px] text-on-surface">{u.email}</td>
                    <td className="px-4 py-3">
                      <select
                        value={u.role || 'read_only'}
                        onChange={(e) => handleRoleChange(u.id, e.target.value)}
                        className="bg-surface-container border border-outline-variant rounded-lg px-2.5 py-1 text-[12.5px] font-bold text-on-surface outline-none cursor-pointer"
                      >
                        <option value="super_admin">Super Admin</option>
                        <option value="admin">Admin</option>
                        <option value="support_engineer">Support Engineer</option>
                        <option value="org_admin">Org Admin</option>
                        <option value="soc_analyst">SOC Analyst</option>
                        <option value="executive_user">Executive</option>
                        <option value="read_only">Read Only</option>
                      </select>
                    </td>
                    <td className="px-4 py-3 text-[13px] font-medium text-on-surface-variant">
                      {u.org_name || 'No Org'}
                    </td>
                    <td className="px-4 py-3">
                      {u.locked_until ? (
                        <span className="inline-flex items-center gap-1 bg-error/10 text-error px-2.5 py-0.5 rounded-full text-[11.5px] font-bold">
                          <Lock className="w-3 h-3" /> Locked
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 bg-green-500/10 text-green-500 px-2.5 py-0.5 rounded-full text-[11.5px] font-bold">
                          <CheckCircle2 className="w-3 h-3" /> Active
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right">
                      {u.locked_until && (
                        <button
                          onClick={() => handleUnlock(u.id)}
                          className="px-3 py-1 bg-primary text-white rounded-lg text-[12px] font-bold hover:brightness-110 transition-all border-0 cursor-pointer shadow-xs inline-flex items-center gap-1"
                        >
                          <Unlock className="w-3 h-3" /> Unlock
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
                {getSortedUsers().length === 0 && (
                  <tr>
                    <td colSpan="5" className="text-center py-xl text-on-surface-variant font-medium text-[13px]">
                      No users match the current search filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 2: Organizations */}
      {activeTab === 'orgs' && (
        <div className="bg-surface-container-lowest border border-outline-variant rounded-2xl shadow-sm overflow-hidden p-lg">
          <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-md mb-lg">
            <div>
              <h2 className="font-extrabold text-on-surface text-[18px] m-0">Registered Organizations</h2>
              <p className="text-on-surface-variant text-[13px] mt-0.5 m-0">Provision tenant accounts, update subscription tiers, and allocate scan quotas.</p>
            </div>

            <div className="flex gap-sm w-full md:w-auto">
              <div className="relative flex-1 md:w-64">
                <Search className="w-4 h-4 absolute left-3 top-2.5 text-on-surface-variant" />
                <input 
                  type="text"
                  placeholder="Search organization name..."
                  value={orgSearch}
                  onChange={e => setOrgSearch(e.target.value)}
                  className="w-full bg-surface-container border border-outline-variant rounded-lg pl-9 pr-3 py-1.5 text-[13px] outline-none focus:border-primary text-on-surface font-medium"
                />
              </div>

              <button
                onClick={handleProvisionTenant}
                className="px-3.5 py-1.5 bg-primary text-white rounded-lg font-bold text-[13px] hover:brightness-110 transition-all border-0 cursor-pointer shadow-sm flex items-center gap-1 whitespace-nowrap"
              >
                <Plus className="w-4 h-4" /> Add Tenant
              </button>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-outline-variant bg-surface-container-high/60 select-none">
                  {['Tenant Name', 'Tier', 'Quotas', 'Created', 'Actions'].map((col) => (
                    <th 
                      key={col}
                      onClick={() => handleOrgSort(col)}
                      className={`px-4 py-3 text-[12px] font-bold uppercase tracking-wider text-on-surface-variant ${col === 'Actions' ? 'text-right' : 'cursor-pointer hover:text-primary'}`}
                    >
                      {col} {sortOrgCol === col ? (sortOrgDir === 'asc' ? '↑' : '↓') : ''}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {getSortedOrgs().map((org) => (
                  <tr key={org.id} className="border-b border-outline-variant/40 hover:bg-surface-container-high/30 transition-colors">
                    <td className="px-4 py-3 font-extrabold text-[14px] text-on-surface">{org.name}</td>
                    <td className="px-4 py-3 text-[13px] font-bold capitalize text-primary">
                      {org.tier || org.subscription_tier || 'Free'}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1.5 items-center">
                        {org.quotas?.map((q, idx) => {
                          const remaining = q.allocated_count === -1 ? '∞' : Math.max(0, q.allocated_count - (q.used_count || 0));
                          const style = q.scan_type === 'Deep' ? 'bg-orange-500/10 text-orange-400 border-orange-500/30' :
                            q.scan_type === 'Advanced' ? 'bg-purple-500/10 text-purple-400 border-purple-500/30' :
                              'bg-blue-500/10 text-blue-400 border-blue-500/30';
                          return (
                            <div key={idx} className={`text-[10.5px] font-extrabold px-2 py-0.5 rounded border flex items-center gap-1 shadow-2xs ${style}`}>
                              <span className="uppercase tracking-wider">{q.scan_type}:</span>
                              <span className="text-[12px]">{remaining}</span>
                            </div>
                          );
                        })}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-[12.5px] font-medium text-on-surface-variant">
                      {org.created ? org.created : (org.created_at ? new Date(org.created_at).toLocaleDateString() : 'N/A')}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => handleEditTenant(org)}
                          className="px-2.5 py-1 bg-surface-container border border-outline-variant text-on-surface rounded-lg hover:bg-surface-container-high transition-colors font-bold text-[12px] cursor-pointer flex items-center gap-1"
                        >
                          <Edit3 className="w-3.5 h-3.5 text-primary" /> Edit
                        </button>
                        <button
                          onClick={() => handleAssignScans(org)}
                          className="px-2.5 py-1 bg-surface-container border border-outline-variant text-on-surface rounded-lg hover:bg-surface-container-high transition-colors font-bold text-[12px] cursor-pointer flex items-center gap-1"
                        >
                          <Plus className="w-3.5 h-3.5 text-primary" /> Quotas
                        </button>
                        <button
                          onClick={() => handleImpersonate(org.id, org.name)}
                          className="px-2.5 py-1 bg-primary/10 text-primary border border-primary/20 rounded-lg hover:bg-primary/20 transition-colors font-bold text-[12px] cursor-pointer flex items-center gap-1"
                        >
                          <Key className="w-3.5 h-3.5" /> Impersonate
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
                {getSortedOrgs().length === 0 && (
                  <tr>
                    <td colSpan="5" className="text-center py-xl text-on-surface-variant font-medium text-[13px]">
                      No organizations found.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 3: Scanner Modes & Access */}
      {activeTab === 'scan_access' && (
        <div className="bg-surface-container-lowest border border-outline-variant rounded-2xl shadow-sm p-lg">
          <h2 className="font-extrabold text-on-surface text-[18px] mb-1">Scanner Engine Access Controls</h2>
          <p className="text-on-surface-variant text-[13.5px] mb-lg">
            Configure global subscription tier requirements and enable/disable specific scan engines platform-wide.
          </p>

          <div className="grid grid-cols-1 gap-md">
            {(scanAccess || []).map((mode) => (
              <div key={mode.scan_type} className="bg-surface-container-low border border-outline-variant/60 rounded-xl p-md flex flex-col md:flex-row md:items-center justify-between gap-md">
                <div>
                  <h4 className="font-extrabold text-on-surface text-[15px] m-0">{mode.scan_type} Scan Engine</h4>
                  <p className="text-on-surface-variant text-[12.5px] mt-0.5 m-0">
                    Status: <span className={mode.is_enabled ? 'text-green-400 font-bold' : 'text-error font-bold'}>{mode.is_enabled ? 'Globally Enabled' : 'Globally Disabled'}</span>
                  </p>
                </div>

                <div className="flex items-center gap-lg">
                  <div className="flex flex-col gap-1">
                    <label className="text-[11px] font-bold uppercase tracking-wider text-on-surface-variant">Required Plan Tier</label>
                    <select
                      value={mode.required_tier}
                      onChange={(e) => updateScanAccess(mode.scan_type, e.target.value, mode.is_enabled)}
                      className="bg-surface-container border border-outline-variant rounded-lg px-3 py-1.5 text-[13px] font-bold text-on-surface outline-none cursor-pointer"
                    >
                      <option value="quick">Quick</option>
                      <option value="advanced">Advanced</option>
                      <option value="deep">Deep</option>
                      <option value="Enterprise(Custom)">Enterprise(Custom)</option>
                    </select>
                  </div>

                  <div className="flex flex-col gap-1">
                    <label className="text-[11px] font-bold uppercase tracking-wider text-on-surface-variant">Engine Switch</label>
                    <button
                      onClick={() => updateScanAccess(mode.scan_type, mode.required_tier, !mode.is_enabled)}
                      className={`px-4 py-1.5 rounded-lg text-[12.5px] font-bold cursor-pointer transition-all border-0 ${
                        mode.is_enabled ? 'bg-green-500/20 text-green-400 hover:bg-green-500/30' : 'bg-error/20 text-error hover:bg-error/30'
                      }`}
                    >
                      {mode.is_enabled ? 'Enabled' : 'Disabled'}
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 4: Audit Trail Preview */}
      {activeTab === 'audit' && (
        <div className="bg-surface-container-lowest border border-outline-variant rounded-2xl shadow-sm p-lg">
          <div className="flex justify-between items-center mb-md">
            <div>
              <h2 className="font-extrabold text-on-surface text-[18px] m-0">Recent Audit Trail</h2>
              <p className="text-on-surface-variant text-[13px] mt-0.5 m-0">Security actions and administrative audit logs.</p>
            </div>
            <button 
              onClick={() => navigate('/super-admin/logs')} 
              className="px-3.5 py-1.5 bg-primary text-white rounded-lg font-bold text-[12.5px] hover:brightness-110 transition-all border-0 cursor-pointer flex items-center gap-1 shadow-xs"
            >
              <FileText className="w-3.5 h-3.5" /> Full Audit Logs
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-outline-variant bg-surface-container-high/60">
                  <th className="px-4 py-3 text-[12px] font-bold uppercase tracking-wider text-on-surface-variant">TIMESTAMP</th>
                  <th className="px-4 py-3 text-[12px] font-bold uppercase tracking-wider text-on-surface-variant">PERFORMED BY</th>
                  <th className="px-4 py-3 text-[12px] font-bold uppercase tracking-wider text-on-surface-variant">ACTION & DETAILS</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.slice(0, 10).map((log) => (
                  <tr key={log.id} className="border-b border-outline-variant/40 hover:bg-surface-container-high/30 transition-colors">
                    <td className="px-4 py-3 text-[12.5px] font-medium text-on-surface-variant whitespace-nowrap">
                      {log.timestamp || 'N/A'}
                    </td>
                    <td className="px-4 py-3 font-bold text-[13px] text-primary">
                      {log.user_email || log.admin_id || 'System'}
                    </td>
                    <td className="px-4 py-3 text-[13px] font-medium text-on-surface">
                      {log.action}
                    </td>
                  </tr>
                ))}
                {auditLogs.length === 0 && (
                  <tr>
                    <td colSpan="3" className="text-center py-xl text-on-surface-variant font-medium text-[13px]">
                      No audit logs available.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Modal for adding/editing tenant & assigning quotas */}
      <CustomModal 
        isOpen={promptModal.isOpen} 
        onClose={closePrompt}
        title={promptModal.title}
        description={promptModal.desc}
        footer={
          <>
            <button onClick={closePrompt} className="px-4 py-2 text-on-surface-variant hover:bg-surface-container rounded-lg font-bold border-0 bg-transparent cursor-pointer">Cancel</button>
            <button onClick={() => promptModal.onConfirm(promptValues)} className="px-4 py-2 bg-primary text-white rounded-lg font-bold border-0 cursor-pointer shadow-md shadow-primary/20">Confirm</button>
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
                  className="bg-surface-container border border-outline-variant rounded-lg px-3 py-2 focus:border-primary outline-none text-on-surface font-medium"
                >
                  {input.options.map(opt => (
                    typeof opt === 'object' ? (
                      <option key={opt.value} value={opt.value}>{opt.label}</option>
                    ) : (
                      <option key={opt} value={opt}>{opt}</option>
                    )
                  ))}
                </select>
              ) : (
                <input 
                  type="text" 
                  value={promptValues[input.key] || ''} 
                  onChange={(e) => handlePromptChange(input.key, e.target.value)}
                  placeholder={input.placeholder}
                  className="bg-surface-container border border-outline-variant rounded-lg px-3 py-2 focus:border-primary outline-none text-on-surface font-medium"
                />
              )}
            </div>
          ))}
        </div>
      </CustomModal>
    </div>
  );
};

export const AdminPage = () => (
  <ErrorBoundary>
    <AdminPageContent />
  </ErrorBoundary>
);
