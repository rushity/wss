import React, { useState, useEffect } from 'react';
import { useAuth } from '../components/AuthContext';
import { Link, useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { 
  Users, 
  Shield, 
  Search, 
  Filter, 
  X, 
  Edit, 
  Key, 
  Activity, 
  Layers, 
  Mail, 
  Calendar, 
  RefreshCw, 
  CheckCircle2, 
  AlertTriangle,
  Info
} from 'lucide-react';
import { CustomModal } from '../components/CustomModal';

const TablePagination = ({ currentPage, totalEntries, pageSize, onPageChange, onPageSizeChange }) => {
  const totalPages = Math.ceil(totalEntries / pageSize) || 1;
  const validCurrentPage = Math.min(Math.max(1, currentPage), totalPages);
  const startIndex = (validCurrentPage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, totalEntries);

  return (
    <div className="p-4 border-t border-outline-variant/60 bg-surface-container-lowest flex flex-col sm:flex-row items-center justify-between gap-3 text-[13px] text-on-surface-variant">
      <div className="flex items-center gap-2">
        <span className="font-medium">Rows per page:</span>
        <select
          value={pageSize}
          onChange={(e) => {
            onPageSizeChange(Number(e.target.value));
            onPageChange(1);
          }}
          className="bg-surface border border-outline-variant/60 text-on-surface rounded px-2 py-1 text-[12px] font-bold focus:outline-none cursor-pointer"
        >
          <option value={10}>10</option>
          <option value={25}>25</option>
          <option value={50}>50</option>
          <option value={100}>100</option>
        </select>
        <span className="ml-2 font-medium">
          {totalEntries === 0 ? '0 of 0 records' : `${startIndex + 1} - ${endIndex} of ${totalEntries} records`}
        </span>
      </div>

      <div className="flex items-center gap-1.5">
        <button
          onClick={() => onPageChange(Math.max(1, validCurrentPage - 1))}
          disabled={validCurrentPage === 1}
          className="px-3 py-1.5 rounded-lg border border-outline-variant/60 bg-surface hover:bg-surface-container-high text-on-surface font-bold text-[12px] disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer transition-colors"
        >
          Previous
        </button>

        <div className="flex items-center gap-1 px-1">
          {Array.from({ length: totalPages }, (_, i) => i + 1)
            .filter(p => p === 1 || p === totalPages || Math.abs(p - validCurrentPage) <= 1)
            .map((page, idx, arr) => {
              const prev = arr[idx - 1];
              return (
                <React.Fragment key={page}>
                  {prev && page - prev > 1 && <span className="px-1 text-on-surface-variant text-[12px]">...</span>}
                  <button
                    onClick={() => onPageChange(page)}
                    className={`w-7 h-7 rounded-lg text-[12px] font-bold transition-colors cursor-pointer ${
                      validCurrentPage === page
                        ? 'bg-primary text-on-primary shadow-2xs'
                        : 'bg-surface hover:bg-surface-container-high border border-outline-variant/60 text-on-surface'
                    }`}
                  >
                    {page}
                  </button>
                </React.Fragment>
              );
            })}
        </div>

        <button
          onClick={() => onPageChange(Math.min(totalPages, validCurrentPage + 1))}
          disabled={validCurrentPage === totalPages}
          className="px-3 py-1.5 rounded-lg border border-outline-variant/60 bg-surface hover:bg-surface-container-high text-on-surface font-bold text-[12px] disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer transition-colors"
        >
          Next
        </button>
      </div>
    </div>
  );
};

const MEMBER_ROLE_OPTIONS = [
  { label: 'Admin', value: 'admin' },
  { label: 'SOC Analyst', value: 'soc_analyst' },
  { label: 'Organization Admin', value: 'org_admin' },
  { label: 'Executive User', value: 'executive_user' },
  { label: 'Super Admin', value: 'super_admin' },
  { label: 'Support Engineer', value: 'support_engineer' },
  { label: 'Read Only', value: 'read_only' }
];

export const SupportEngineerPanel = () => {
  const { user, refreshAccessToken } = useAuth();
  const navigate = useNavigate();

  const authFetch = async (url, options = {}) => {
    let activeToken = localStorage.getItem('wss_token');
    const headers = {
      'Authorization': `Bearer ${activeToken}`,
      ...(options.headers || {})
    };

    let res = await fetch(url, { ...options, headers });

    if (res.status === 401 && refreshAccessToken) {
      const newToken = await refreshAccessToken();
      if (newToken) {
        headers['Authorization'] = `Bearer ${newToken}`;
        res = await fetch(url, { ...options, headers });
      }
    }
    return res;
  };

  const [organizations, setOrganizations] = useState([]);
  const [metrics, setMetrics] = useState({});
  const [auditLogs, setAuditLogs] = useState([]);
  const [users, setUsers] = useState([]);
  const [demoBookings, setDemoBookings] = useState([]);
  const [emailLogs, setEmailLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  const [activeTab, setActiveTab] = useState(() => {
    try {
      const params = new URLSearchParams(window.location.search);
      return params.get('tab') || 'organizations';
    } catch (e) {
      return 'organizations';
    }
  });

  // Table sorting states
  const [sortOrgCol, setSortOrgCol] = useState('Tenant Name');
  const [sortOrgDir, setSortOrgDir] = useState('asc');

  const [sortUserCol, setSortUserCol] = useState('Email');
  const [sortUserDir, setSortUserDir] = useState('asc');

  // Filter states for Global Members
  const [userSearch, setUserSearch] = useState('');
  const [userRoleFilter, setUserRoleFilter] = useState('all');
  const [userOrgFilter, setUserOrgFilter] = useState('all');

  // Pagination states
  const [orgPage, setOrgPage] = useState(1);
  const [orgPageSize, setOrgPageSize] = useState(25);

  const [userPage, setUserPage] = useState(1);
  const [userPageSize, setUserPageSize] = useState(25);

  const [auditPage, setAuditPage] = useState(1);
  const [auditPageSize, setAuditPageSize] = useState(25);

  const [bookingPage, setBookingPage] = useState(1);
  const [bookingPageSize, setBookingPageSize] = useState(25);

  const [emailPage, setEmailPage] = useState(1);
  const [emailPageSize, setEmailPageSize] = useState(25);

  // Custom Prompt Modal state for editing member roles/orgs (without password)
  const [promptModal, setPromptModal] = useState({ isOpen: false, title: '', desc: '', inputs: [], onConfirm: null });
  const [promptValues, setPromptValues] = useState({});
  const [confirmModal, setConfirmModal] = useState({ isOpen: false, title: '', desc: '', onConfirm: null });

  const closePrompt = () => { setPromptModal({ isOpen: false, title: '', desc: '', inputs: [], onConfirm: null }); setPromptValues({}); };
  const closeConfirm = () => setConfirmModal({ isOpen: false, title: '', desc: '', onConfirm: null });

  const handlePromptChange = (key, value) => setPromptValues(prev => ({ ...prev, [key]: value }));

  const fetchStats = async () => {
    setLoading(true);
    try {
      const activeToken = localStorage.getItem('wss_token');
      if (!activeToken) {
        setLoading(false);
        return;
      }
      const [globalRes, bookingsRes, emailLogsRes] = await Promise.all([
        authFetch('/api/auth/global-stats'),
        authFetch('/api/demo/bookings'),
        authFetch('/api/auth/email-logs')
      ]);

      if (globalRes && globalRes.ok) {
        const data = await globalRes.json();
        setOrganizations(Array.isArray(data.organizations) ? data.organizations : []);
        setMetrics(data.metrics || {});
        setAuditLogs(Array.isArray(data.audit_logs) ? data.audit_logs : []);
        setUsers(Array.isArray(data.users) ? data.users : []);
      }
      if (bookingsRes && bookingsRes.ok) {
        const data = await bookingsRes.json();
        setDemoBookings(Array.isArray(data.bookings) ? data.bookings : []);
      }
      if (emailLogsRes && emailLogsRes.ok) {
        const data = await emailLogsRes.json();
        setEmailLogs(Array.isArray(data.logs) ? data.logs : []);
      }
    } catch (err) {
      console.error("SupportEngineerPanel fetch error:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  const handleOrgSort = (column) => {
    if (column === 'Quotas' || column === 'Actions') return;
    if (sortOrgCol === column) {
      setSortOrgDir(sortOrgDir === 'asc' ? 'desc' : 'asc');
    } else {
      setSortOrgCol(column);
      setSortOrgDir('asc');
    }
  };

  const getSortedOrgs = () => {
    return [...(organizations || [])].sort((a, b) => {
      let aVal, bVal;
      switch (sortOrgCol) {
        case 'Tenant Name': aVal = a.name || ''; bVal = b.name || ''; break;
        case 'Tier': aVal = a.tier || a.subscription_tier || ''; bVal = b.tier || b.subscription_tier || ''; break;
        case 'Status': aVal = a.status || (a.is_active ? 'active' : 'inactive'); bVal = b.status || (b.is_active ? 'active' : 'inactive'); break;
        default: aVal = a.name || ''; bVal = b.name || '';
      }
      if (aVal < bVal) return sortOrgDir === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortOrgDir === 'asc' ? 1 : -1;
      return 0;
    });
  };

  const handleUserSort = (column) => {
    if (column === 'Actions') return;
    if (sortUserCol === column) {
      setSortUserDir(sortUserDir === 'asc' ? 'desc' : 'asc');
    } else {
      setSortUserCol(column);
      setSortUserDir('asc');
    }
  };

  const getFilteredUsers = () => {
    return (users || []).filter(u => {
      const emailMatch = !userSearch || u.email?.toLowerCase().includes(userSearch.toLowerCase());
      const roleMatch = userRoleFilter === 'all' || u.role === userRoleFilter;
      const orgMatch = userOrgFilter === 'all' || (
        userOrgFilter === 'no_org' ? !u.org_id : String(u.org_id) === String(userOrgFilter)
      );
      return emailMatch && roleMatch && orgMatch;
    });
  };

  const getSortedUsers = () => {
    const filtered = getFilteredUsers();
    return [...filtered].sort((a, b) => {
      let aVal, bVal;
      switch (sortUserCol) {
        case 'Email': aVal = a.email || ''; bVal = b.email || ''; break;
        case 'Role': aVal = a.role || ''; bVal = b.role || ''; break;
        case 'Organization': aVal = a.org_name || ''; bVal = b.org_name || ''; break;
        default: aVal = a.email || ''; bVal = b.email || '';
      }
      if (aVal < bVal) return sortUserDir === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortUserDir === 'asc' ? 1 : -1;
      return 0;
    });
  };

  const clearUserFilters = () => {
    setUserSearch('');
    setUserRoleFilter('all');
    setUserOrgFilter('all');
    setUserPage(1);
  };

  const handleImpersonate = (orgId, orgName) => {
    setConfirmModal({
      isOpen: true,
      title: 'Inspect Tenant Environment',
      desc: `Log in as administrator for ${orgName} to troubleshoot customer issue?`,
      onConfirm: async () => {
        try {
          const res = await authFetch(`/api/auth/impersonate/${orgId}`, {
            method: 'POST'
          });
          if (res.ok) {
            const data = await res.json();
            localStorage.setItem('original_admin_token', localStorage.getItem('wss_token'));
            localStorage.setItem('wss_token', data.access_token);
            window.location.href = '/dashboard';
          } else {
            toast.error('Failed to inspect tenant environment');
          }
        } catch (err) {
          toast.error('Network error during environment inspection');
        }
        closeConfirm();
      }
    });
  };

  // Support Engineer can edit role / org assignment, BUT NOT passwords
  const handleEditMember = (u) => {
    const orgOptions = [
      { label: 'None (Global)', value: '' },
      ...(organizations || []).map(o => ({ label: o.name, value: String(o.id) }))
    ];

    let initialOrgId = (u.org_id !== undefined && u.org_id !== null) ? String(u.org_id) : '';
    if (!initialOrgId && u.org_name && u.org_name !== 'No Org (Super Admin)' && organizations) {
      const match = organizations.find(o => o.name === u.org_name);
      if (match) initialOrgId = String(match.id);
    }

    setPromptValues({
      email: u.email,
      role: u.role || 'admin',
      org_id: initialOrgId
    });

    setPromptModal({
      isOpen: true,
      title: 'Edit Member Role & Organization',
      desc: `Update role or organization assignment for ${u.email}`,
      inputs: [
        { key: 'email', label: 'User Email', disabled: true },
        { key: 'role', label: 'Role', type: 'select', options: MEMBER_ROLE_OPTIONS },
        { key: 'org_id', label: 'Organization', type: 'select', options: orgOptions }
      ],
      onConfirm: async (vals) => {
        try {
          const res = await authFetch(`/api/auth/users/${u.id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              role: vals.role,
              org_id: vals.org_id || null
            })
          });
          const data = await res.json().catch(() => ({}));
          if (res.ok) {
            toast.success('Member role & organization updated successfully');
            fetchStats();
          } else {
            toast.error(data.message || 'Failed to update member');
          }
        } catch (err) {
          toast.error('Network error updating member');
        }
        closePrompt();
      }
    });
  };

  return (
    <div className="flex flex-col gap-lg w-full text-left font-body">
      
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-md border-b border-outline-variant pb-md">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="font-headline-md font-bold text-on-surface tracking-tight text-[22px] m-0">
              Support Engineer Operations
            </h1>
            <span className="px-2.5 py-0.5 rounded-full text-[11px] font-extrabold uppercase bg-blue-500/10 text-blue-600 border border-blue-500/30">
              SUPPORT CONSOLE
            </span>
          </div>
          <p className="font-body-md text-on-surface-variant text-[13.5px] mt-1 m-0">
            Client environment inspection, troubleshooting assistance, audit logs, and member role mappings.
          </p>
        </div>
        
        <div className="flex flex-wrap items-center gap-2">
          <button 
            onClick={fetchStats}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-surface-container border border-outline-variant hover:bg-surface-container-high text-on-surface rounded-lg font-bold text-[12.5px] cursor-pointer transition-all"
          >
            <RefreshCw className={`w-4 h-4 text-primary ${loading ? 'animate-spin' : ''}`} />
            Sync Metrics
          </button>
          <button 
            onClick={() => navigate('/dashboard')}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-primary/10 border border-primary/20 text-primary hover:bg-primary/20 rounded-lg font-bold text-[12.5px] cursor-pointer transition-all"
          >
            <Activity className="w-4 h-4" />
            Org Dashboard
          </button>
          <button 
            onClick={() => navigate('/super-admin/logs')}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-surface-container border border-outline-variant hover:bg-surface-container-high text-on-surface rounded-lg font-bold text-[12.5px] cursor-pointer transition-all"
          >
            <Shield className="w-4 h-4 text-primary" />
            Logs & Threats
          </button>
        </div>
      </div>

      {/* Tabs Navigation */}
      <div className="flex items-center gap-1 border-b border-outline-variant overflow-x-auto hide-scrollbar">
        {[
          { id: 'overview', label: 'Overview', icon: Activity },
          { id: 'organizations', label: 'Organizations', icon: Shield },
          { id: 'members', label: 'Members', icon: Users },
          { id: 'audit', label: 'Audit Logs', icon: Layers },
          { id: 'bookings', label: 'Bookings', icon: Calendar },
          { id: 'emails', label: 'Emails', icon: Mail }
        ].map(tab => {
          const IconComp = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2.5 font-bold text-[13.5px] border-b-2 transition-all cursor-pointer bg-transparent border-t-0 border-x-0 ${
                activeTab === tab.id
                  ? 'border-primary text-primary bg-primary/5 rounded-t-lg'
                  : 'border-transparent text-on-surface-variant hover:text-on-surface hover:bg-surface-container/50'
              }`}
            >
              <IconComp className="w-4 h-4" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* OVERVIEW TAB */}
      {activeTab === 'overview' && (
        <div className="flex flex-col gap-lg animate-fade-in">
          {/* Quick Metrics Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-md">
            <div className="bg-surface-container-lowest border border-outline-variant p-md rounded-2xl flex items-center justify-between shadow-2xs">
              <div>
                <div className="text-[12px] font-bold text-on-surface-variant uppercase tracking-wider">Total Tenants</div>
                <div className="text-2xl font-extrabold text-on-surface mt-1">{metrics.total_tenants || organizations.length || 0}</div>
              </div>
              <div className="w-10 h-10 rounded-xl bg-primary/10 text-primary flex items-center justify-center">
                <Shield className="w-5 h-5" />
              </div>
            </div>

            <div className="bg-surface-container-lowest border border-outline-variant p-md rounded-2xl flex items-center justify-between shadow-2xs">
              <div>
                <div className="text-[12px] font-bold text-on-surface-variant uppercase tracking-wider">Active Licenses</div>
                <div className="text-2xl font-extrabold text-on-surface mt-1">{metrics.active_licenses || 0}</div>
              </div>
              <div className="w-10 h-10 rounded-xl bg-emerald-500/10 text-emerald-600 flex items-center justify-center">
                <CheckCircle2 className="w-5 h-5" />
              </div>
            </div>

            <div className="bg-surface-container-lowest border border-outline-variant p-md rounded-2xl flex items-center justify-between shadow-2xs">
              <div>
                <div className="text-[12px] font-bold text-on-surface-variant uppercase tracking-wider">Global Users</div>
                <div className="text-2xl font-extrabold text-on-surface mt-1">{metrics.global_users || users.length || 0}</div>
              </div>
              <div className="w-10 h-10 rounded-xl bg-purple-500/10 text-purple-600 flex items-center justify-center">
                <Users className="w-5 h-5" />
              </div>
            </div>

            <div className="bg-surface-container-lowest border border-outline-variant p-md rounded-2xl flex items-center justify-between shadow-2xs">
              <div>
                <div className="text-[12px] font-bold text-on-surface-variant uppercase tracking-wider">Active Scanners</div>
                <div className="text-2xl font-extrabold text-on-surface mt-1">{metrics.active_scanners || 0}</div>
              </div>
              <div className="w-10 h-10 rounded-xl bg-blue-500/10 text-blue-600 flex items-center justify-center">
                <Activity className="w-5 h-5" />
              </div>
            </div>
          </div>

          {/* Operational Support Guidance Box */}
          <div className="bg-blue-500/5 border border-blue-500/20 rounded-2xl p-5 flex items-start gap-4">
            <div className="w-10 h-10 rounded-xl bg-blue-500/10 text-blue-600 flex items-center justify-center shrink-0 mt-0.5">
              <Info className="w-5 h-5" />
            </div>
            <div className="flex-1">
              <h3 className="font-bold text-on-surface text-[15px] m-0 mb-1">Support Engineer Scope & Guidelines</h3>
              <p className="text-on-surface-variant text-[13px] leading-relaxed m-0">
                You are currently in the Support Engineer Operations Console. You have full visibility into organizations, active scan quotas, global members, audit logs, and outbound communication logs to assist client troubleshooting.
              </p>
              <ul className="text-on-surface-variant text-[12.5px] mt-2 mb-0 pl-4 space-y-1">
                <li>• Use the <strong><Key className="w-3.5 h-3.5 inline mr-1 text-primary" /> Inspect</strong> action on any client organization to temporarily log in as their admin and diagnose issue reports.</li>
                <li>• You can edit member roles or organization assignments to assist configuration, but password changes are restricted for security.</li>
                <li>• Member and Organization creation/deletion are managed exclusively by Super Admins.</li>
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* ORGANIZATIONS TAB */}
      {activeTab === 'organizations' && (
        <div className="flex flex-col gap-md mb-xl animate-fade-in">
          <div className="flex justify-between items-center">
            <h2 className="font-headline-sm font-bold text-on-surface flex items-center text-[18px]">
              <Shield className="w-5 h-5 text-primary mr-2" /> Client Organizations Directory
            </h2>
          </div>

          <div className="bg-surface-container-lowest border border-outline-variant rounded-2xl overflow-hidden shadow-sm overflow-x-auto hide-scrollbar">
            {loading ? <div className="p-10 text-center text-on-surface-variant">Fetching directory...</div> : (
              <table className="w-full text-left text-sm border-collapse">
                <thead className="bg-surface-container text-on-surface-variant border-b border-outline-variant select-none">
                  <tr>
                    {['Tenant Name', 'Tier', 'Status', 'Quotas', 'Actions'].map((h, i) => (
                      <th 
                        key={h} 
                        onClick={() => handleOrgSort(h)}
                        className={`px-md py-sm font-bold text-[12px] uppercase tracking-wider ${i === 4 ? 'text-right' : ''} ${(h !== 'Actions' && h !== 'Quotas') ? 'cursor-pointer hover:bg-surface-container-highest transition-colors group' : ''}`}
                      >
                        <div className={`flex items-center gap-xs ${i === 4 ? 'justify-end' : ''}`}>
                          {h}
                        </div>
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-outline-variant">
                  {getSortedOrgs().slice((orgPage - 1) * orgPageSize, orgPage * orgPageSize).map((org) => (
                    <tr key={org.id} className="hover:bg-surface-container transition-colors group">
                      <td className="px-md py-sm"><div className="font-bold text-on-surface text-[14px]">{org.name}</div></td>
                      <td className="px-md py-sm"><span className="px-2 py-0.5 rounded border text-[11px] font-bold tracking-wide bg-surface-container-high border-outline-variant text-on-surface-variant">{org.tier || org.subscription_tier}</span></td>
                      <td className="px-md py-sm"><div className="flex items-center gap-xs text-[12.5px] font-bold"><span className={`w-2 h-2 rounded-full ${org.status === 'active' || org.is_active ? 'bg-green-500' : 'bg-red-500'}`}></span><span className={org.status === 'active' || org.is_active ? 'text-green-600 dark:text-green-500' : 'text-error'}>{org.status ? org.status.charAt(0).toUpperCase() + org.status.slice(1) : (org.is_active ? 'Active' : 'Inactive')}</span></div></td>
                      <td className="px-md py-sm">
                        <div className="flex flex-nowrap gap-2 items-center">
                          {org.quotas?.map((q, idx) => {
                            const remaining = q.allocated_count === -1 ? '∞' : Math.max(0, q.allocated_count - (q.used_count || 0));
                            const style = q.scan_type === 'Deep' ? 'bg-orange-500/10 text-orange-600 border-orange-500/30' :
                              q.scan_type === 'Advanced' ? 'bg-purple-500/10 text-purple-600 border-purple-500/30' :
                                'bg-blue-500/10 text-blue-600 border-blue-500/30';
                            return (
                              <div key={idx} className={`text-[10.5px] font-bold px-2 py-0.5 rounded border flex items-center gap-1 shadow-sm ${style}`}>
                                <span className="uppercase opacity-90 tracking-wider">{q.scan_type}:</span>
                                <span className="text-[12px]">{remaining}</span>
                              </div>
                            );
                          })}
                        </div>
                      </td>
                      <td className="px-md py-sm text-right">
                        <button onClick={() => handleImpersonate(org.id, org.name)} className="text-on-surface-variant hover:text-primary transition-colors bg-transparent border-0 cursor-pointer p-1" title="Inspect Customer Environment / Assist Troubleshooting">
                          <span className="material-symbols-outlined text-[18px]">vpn_key</span>
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <TablePagination
              currentPage={orgPage}
              totalEntries={organizations.length}
              pageSize={orgPageSize}
              onPageChange={setOrgPage}
              onPageSizeChange={setOrgPageSize}
            />
          </div>
        </div>
      )}

      {/* MEMBERS TAB */}
      {activeTab === 'members' && (
        <div className="flex flex-col gap-md mb-xl animate-fade-in">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-md mb-xs">
            <div>
              <h2 className="font-headline-sm font-bold text-on-surface flex items-center text-[18px]">
                <Users className="w-5 h-5 text-primary mr-2" /> Global Members
              </h2>
              <p className="text-[13px] text-on-surface-variant mt-0.5">
                Inspect user accounts, assign roles, and modify client organization mapping.
              </p>
            </div>
          </div>

          {/* Filter & Search Bar */}
          <div className="bg-surface-container-lowest border border-outline-variant/70 rounded-2xl p-4 flex flex-col md:flex-row items-center justify-between gap-3 shadow-2xs">
            <div className="flex flex-wrap items-center gap-3 w-full flex-1">
              <div className="relative w-full sm:w-72">
                <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant" />
                <input
                  type="text"
                  placeholder="Search email, org, role..."
                  value={userSearch}
                  onChange={(e) => {
                    setUserSearch(e.target.value);
                    setUserPage(1);
                  }}
                  className="w-full bg-surface border border-outline-variant/60 text-on-surface text-[13px] font-medium rounded-lg pl-9 pr-8 py-2 focus:outline-none focus:border-primary placeholder:text-on-surface-variant/50"
                />
                {userSearch && (
                  <button onClick={() => setUserSearch('')} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-on-surface-variant hover:text-on-surface bg-transparent border-0 cursor-pointer">
                    <X className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>

              <div className="flex items-center gap-2 w-full sm:w-auto">
                <Filter className="w-4 h-4 text-on-surface-variant shrink-0" />
                <select
                  value={userRoleFilter}
                  onChange={(e) => {
                    setUserRoleFilter(e.target.value);
                    setUserPage(1);
                  }}
                  className="bg-surface border border-outline-variant/60 text-on-surface text-[13px] font-medium rounded-lg px-3 py-2 focus:outline-none focus:border-primary cursor-pointer w-full sm:w-auto"
                >
                  <option value="all">All Roles</option>
                  {MEMBER_ROLE_OPTIONS.map(r => (
                    <option key={r.value} value={r.value}>{r.label}</option>
                  ))}
                </select>

                <select
                  value={userOrgFilter}
                  onChange={(e) => {
                    setUserOrgFilter(e.target.value);
                    setUserPage(1);
                  }}
                  className="bg-surface border border-outline-variant/60 text-on-surface text-[13px] font-medium rounded-lg px-3 py-2 focus:outline-none focus:border-primary cursor-pointer w-full sm:w-auto max-w-[200px] truncate"
                >
                  <option value="all">All Organizations</option>
                  <option value="no_org">No Org (Super Admin / Global)</option>
                  {(organizations || []).map(org => (
                    <option key={org.id} value={org.id}>{org.name}</option>
                  ))}
                </select>
              </div>

              {(userSearch || userRoleFilter !== 'all' || userOrgFilter !== 'all') && (
                <button
                  onClick={clearUserFilters}
                  className="text-error hover:underline text-[12.5px] font-bold flex items-center gap-1 cursor-pointer bg-transparent border-0 px-1 ml-auto"
                >
                  <X className="w-4 h-4" />
                  Reset Filters
                </button>
              )}
            </div>
          </div>

          <div className="bg-surface-container-lowest border border-outline-variant rounded-2xl overflow-hidden shadow-sm overflow-x-auto hide-scrollbar">
            {loading ? <div className="p-10 text-center text-on-surface-variant">Fetching users...</div> : getSortedUsers().length === 0 ? (
              <div className="p-12 text-center text-on-surface-variant">
                <Users className="w-8 h-8 text-on-surface-variant/40 mx-auto mb-2" />
                <p className="font-bold text-[14px] text-on-surface">No members match your filter criteria.</p>
                <p className="text-[12.5px] text-on-surface-variant mt-1">Try clearing your search terms or filter criteria.</p>
                {(userSearch || userRoleFilter !== 'all' || userOrgFilter !== 'all') && (
                  <button onClick={clearUserFilters} className="mt-3 px-3.5 py-1.5 bg-primary/10 text-primary font-bold text-[12px] rounded-lg border border-primary/20 hover:bg-primary/20 cursor-pointer">
                    Clear All Filters
                  </button>
                )}
              </div>
            ) : (
              <table className="w-full text-left text-sm border-collapse">
                <thead className="bg-surface-container text-on-surface-variant border-b border-outline-variant select-none">
                  <tr>
                    {['Email', 'Role', 'Organization', 'Actions'].map((h, i) => (
                      <th 
                        key={h} 
                        onClick={() => handleUserSort(h)}
                        className={`px-md py-sm font-bold text-[12px] uppercase tracking-wider ${i === 3 ? 'text-right' : ''} ${h !== 'Actions' ? 'cursor-pointer hover:bg-surface-container-highest transition-colors group' : ''}`}
                      >
                        <div className={`flex items-center gap-xs ${i === 3 ? 'justify-end' : ''}`}>
                          {h}
                        </div>
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-outline-variant">
                  {getSortedUsers().slice((userPage - 1) * userPageSize, userPage * userPageSize).map((u) => (
                    <tr key={u.id} className="hover:bg-surface-container transition-colors group">
                      <td className="px-md py-sm font-bold text-on-surface text-[14px]">{u.email}</td>
                      <td className="px-md py-sm">
                        <span className={`px-2.5 py-1 rounded-md border text-[11px] font-extrabold tracking-wide uppercase ${
                          u.role === 'super_admin' ? 'bg-purple-500/10 text-purple-500 border-purple-500/30' :
                          u.role === 'support_engineer' ? 'bg-blue-500/10 text-blue-500 border-blue-500/30' :
                          u.role === 'soc_analyst' ? 'bg-emerald-500/10 text-emerald-600 border-emerald-500/30' :
                          u.role === 'org_admin' || u.role === 'admin' ? 'bg-primary/10 text-primary border-primary/30' :
                          'bg-surface-container-high border-outline-variant text-on-surface-variant'
                        }`}>
                          {u.role ? u.role.replace(/_/g, ' ') : 'User'}
                        </span>
                      </td>
                      <td className="px-md py-sm text-[13px] font-semibold text-on-surface-variant">{u.org_name}</td>
                      <td className="px-md py-sm text-right flex justify-end gap-2">
                        <button
                          onClick={() => handleEditMember(u)}
                          className="text-on-surface-variant hover:text-primary transition-colors bg-transparent border-0 cursor-pointer p-1"
                          title="Edit Member Role & Organization"
                        >
                          <Edit className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <TablePagination
              currentPage={userPage}
              totalEntries={getSortedUsers().length}
              pageSize={userPageSize}
              onPageChange={setUserPage}
              onPageSizeChange={setUserPageSize}
            />
          </div>
        </div>
      )}

      {/* AUDIT LOGS TAB */}
      {activeTab === 'audit' && (
        <div className="flex flex-col gap-md mb-xl animate-fade-in">
          <h2 className="font-headline-sm font-bold text-on-surface flex items-center text-[18px] mb-md">
            <Layers className="w-5 h-5 text-primary mr-2" /> Global Audit Logs
          </h2>
          <div className="bg-surface-container-lowest border border-outline-variant rounded-2xl overflow-hidden shadow-sm overflow-x-auto">
            {auditLogs.length === 0 ? (
              <div className="p-xl text-center text-on-surface-variant font-bold">No audit logs available.</div>
            ) : (
              <>
                <table className="w-full text-left border-collapse">
                  <thead className="bg-surface border-b border-outline-variant text-on-surface-variant">
                    <tr>
                      <th className="px-md py-sm font-bold text-[12px] uppercase">Timestamp</th>
                      <th className="px-md py-sm font-bold text-[12px] uppercase">Action</th>
                      <th className="px-md py-sm font-bold text-[12px] uppercase">User Email</th>
                      <th className="px-md py-sm font-bold text-[12px] uppercase">Target</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-outline-variant">
                    {auditLogs.slice((auditPage - 1) * auditPageSize, auditPage * auditPageSize).map((log) => (
                      <tr key={log.id} className="hover:bg-surface-container transition-colors">
                        <td className="px-md py-sm text-on-surface-variant text-[12.5px]">{new Date(log.timestamp).toLocaleString()}</td>
                        <td className="px-md py-sm font-bold text-on-surface text-[13px]">{log.action}</td>
                        <td className="px-md py-sm font-semibold text-on-surface text-[13px]">{log.user_email}</td>
                        <td className="px-md py-sm font-semibold text-on-surface-variant text-[13px]">{log.target_name || log.target_id || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <TablePagination
                  currentPage={auditPage}
                  totalEntries={auditLogs.length}
                  pageSize={auditPageSize}
                  onPageChange={setAuditPage}
                  onPageSizeChange={setAuditPageSize}
                />
              </>
            )}
          </div>
        </div>
      )}

      {/* BOOKINGS TAB */}
      {activeTab === 'bookings' && (
        <div className="flex flex-col gap-md mb-xl animate-fade-in">
          <h2 className="font-headline-sm font-bold text-on-surface flex items-center text-[18px] mb-md">
            <Calendar className="w-5 h-5 text-primary mr-2" /> Demo Schedule Bookings
          </h2>
          <div className="bg-surface-container-lowest border border-outline-variant rounded-2xl overflow-hidden shadow-sm overflow-x-auto">
            {demoBookings.length === 0 ? (
              <div className="p-xl text-center text-on-surface-variant font-bold">No demo bookings yet.</div>
            ) : (
              <>
                <table className="w-full text-left border-collapse">
                  <thead className="bg-surface border-b border-outline-variant text-on-surface-variant">
                    <tr>
                      <th className="px-md py-sm font-bold text-[12px] uppercase">Client Email</th>
                      <th className="px-md py-sm font-bold text-[12px] uppercase">Meeting Date & Time</th>
                      <th className="px-md py-sm font-bold text-[12px] uppercase">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-outline-variant">
                    {demoBookings.slice((bookingPage - 1) * bookingPageSize, bookingPage * bookingPageSize).map((b) => (
                      <tr key={b.id} className="hover:bg-surface-container transition-colors">
                        <td className="px-md py-sm font-bold text-on-surface text-[13.5px]">{b.user_email}</td>
                        <td className="px-md py-sm text-on-surface-variant text-[13px]">{b.meeting_date} at {b.meeting_time}</td>
                        <td className="px-md py-sm">
                          <span className={`px-2 py-0.5 rounded text-[11px] font-bold uppercase ${b.status === 'confirmed' ? 'bg-green-500/10 text-green-600' : 'bg-blue-500/10 text-blue-600'}`}>
                            {b.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <TablePagination
                  currentPage={bookingPage}
                  totalEntries={demoBookings.length}
                  pageSize={bookingPageSize}
                  onPageChange={setBookingPage}
                  onPageSizeChange={setBookingPageSize}
                />
              </>
            )}
          </div>
        </div>
      )}

      {/* EMAILS TAB */}
      {activeTab === 'emails' && (
        <div className="flex flex-col gap-md mb-xl animate-fade-in">
          <h2 className="font-headline-sm font-bold text-on-surface flex items-center text-[18px] mb-md">
            <Mail className="w-5 h-5 text-primary mr-2" /> Outbound Email Logs
          </h2>
          <div className="bg-surface-container-lowest border border-outline-variant rounded-2xl overflow-hidden shadow-sm overflow-x-auto">
            {emailLogs.length === 0 ? (
              <div className="p-xl text-center text-on-surface-variant font-bold">No email logs available.</div>
            ) : (
              <>
                <table className="w-full text-left border-collapse">
                  <thead className="bg-surface border-b border-outline-variant text-on-surface-variant">
                    <tr>
                      <th className="px-md py-sm font-bold text-[12px] uppercase">Timestamp</th>
                      <th className="px-md py-sm font-bold text-[12px] uppercase">Recipient</th>
                      <th className="px-md py-sm font-bold text-[12px] uppercase">Subject</th>
                      <th className="px-md py-sm font-bold text-[12px] uppercase">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-outline-variant">
                    {emailLogs.slice((emailPage - 1) * emailPageSize, emailPage * emailPageSize).map((log) => (
                      <tr key={log.id} className="hover:bg-surface-container transition-colors">
                        <td className="px-md py-sm text-on-surface-variant text-[12.5px]">{new Date(log.sent_at).toLocaleString()}</td>
                        <td className="px-md py-sm font-bold text-on-surface text-[13px]">{log.recipient}</td>
                        <td className="px-md py-sm text-on-surface-variant text-[13px]">{log.subject}</td>
                        <td className="px-md py-sm">
                          <span className={`px-2 py-0.5 rounded text-[11px] font-bold uppercase ${log.status === 'sent' ? 'bg-green-500/10 text-green-600' : 'bg-red-500/10 text-red-600'}`}>
                            {log.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <TablePagination
                  currentPage={emailPage}
                  totalEntries={emailLogs.length}
                  pageSize={emailPageSize}
                  onPageChange={setEmailPage}
                  onPageSizeChange={setEmailPageSize}
                />
              </>
            )}
          </div>
        </div>
      )}

      {/* Prompt Modal for Editing Role/Org */}
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
                  {input.options.map(opt => {
                    const val = typeof opt === 'object' ? opt.value : opt;
                    const lbl = typeof opt === 'object' ? opt.label : opt;
                    return <option key={val} value={val}>{lbl}</option>;
                  })}
                </select>
              ) : (
                <input
                  type={input.type || "text"}
                  value={promptValues[input.key] || ''}
                  onChange={(e) => handlePromptChange(input.key, e.target.value)}
                  placeholder={input.placeholder}
                  disabled={input.disabled}
                  className={`bg-surface-container border border-outline-variant rounded-lg px-3 py-2 focus:border-primary outline-none text-on-surface ${input.disabled ? 'bg-surface-container-high text-on-surface-variant opacity-80 cursor-not-allowed' : ''}`}
                />
              )}
            </div>
          ))}
        </div>
      </CustomModal>

      {/* Confirm Modal */}
      <CustomModal
        isOpen={confirmModal.isOpen}
        onClose={closeConfirm}
        title={confirmModal.title}
        description={confirmModal.desc}
        footer={
          <>
            <button onClick={closeConfirm} className="px-4 py-2 text-on-surface-variant hover:bg-surface-container rounded-lg font-bold border-0 bg-transparent cursor-pointer">Cancel</button>
            <button onClick={confirmModal.onConfirm} className="px-4 py-2 bg-primary text-white rounded-lg font-bold border-0 cursor-pointer">Confirm</button>
          </>
        }
      />

    </div>
  );
};

export default SupportEngineerPanel;
