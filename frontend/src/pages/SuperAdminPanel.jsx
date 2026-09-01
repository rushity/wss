import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../components/AuthContext';
import { CustomModal } from '../components/CustomModal';
import { Building2, Users, CreditCard, Shield, Trash2, Plus, Server, Activity, Database, HardDrive, RefreshCw, BarChart2, Edit, Download, Eye, Search, X } from 'lucide-react';
import toast from 'react-hot-toast';

const DEFAULT_BILLING_TIERS = [
  { id: 'quick', name: 'Quick Scan', badge: 'QUICK', monthly_price: 499, yearly_price: 4990 },
  { id: 'advanced', name: 'Advanced Scan', badge: 'ADVANCED', monthly_price: 4499, yearly_price: 44990 },
  { id: 'deep', name: 'Deep Scan', badge: 'DEEP', monthly_price: 9999, yearly_price: 99990 },
  { id: 'enterprise', name: 'Custom Solutions', badge: 'ENTERPRISE', monthly_price: 0, yearly_price: 0 }
];

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
          disabled={validCurrentPage >= totalPages}
          className="px-3 py-1.5 rounded-lg border border-outline-variant/60 bg-surface hover:bg-surface-container-high text-on-surface font-bold text-[12px] disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer transition-colors"
        >
          Next
        </button>
      </div>
    </div>
  );
};

const BillingTierCard = ({ tier, onSave }) => {
  const [monthly, setMonthly] = useState(((tier.monthly_price || 0) / 100).toFixed(2));
  const [yearly, setYearly] = useState(((tier.yearly_price || 0) / 100).toFixed(2));
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  const handleSave = async () => {
    setSaving(true);
    if (onSave) {
      await onSave(tier.id, Math.round(parseFloat(monthly || 0) * 100), Math.round(parseFloat(yearly || 0) * 100));
    }
    setSaving(false);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const getAccentClass = (id) => {
    const key = (id || '').toLowerCase();
    if (key.includes('quick')) return 'bg-[#4285f4]';
    if (key.includes('advanced')) return 'bg-[#a855f7]';
    if (key.includes('deep')) return 'bg-[#f97316]';
    if (key.includes('enterprise') || key.includes('custom')) return 'bg-[#f97316]';
    return 'bg-primary';
  };

  const getBadge = (tier) => {
    if (tier.badge) return tier.badge;
    const key = (tier.id || '').toLowerCase();
    if (key.includes('quick')) return 'QUICK';
    if (key.includes('advanced')) return 'ADVANCED';
    if (key.includes('deep')) return 'DEEP';
    if (key.includes('enterprise') || key.includes('custom')) return 'ENTERPRISE';
    return (tier.id || '').toUpperCase();
  };

  const getDisplayName = (tier) => {
    if (tier.name && tier.name !== tier.id) return tier.name;
    const key = (tier.id || '').toLowerCase();
    if (key.includes('quick')) return 'Quick Scan';
    if (key.includes('advanced')) return 'Advanced Scan';
    if (key.includes('deep')) return 'Deep Scan';
    if (key.includes('enterprise') || key.includes('custom')) return 'Custom Solutions';
    return tier.name || tier.id;
  };

  return (
    <div className="bg-surface-container-lowest border border-outline-variant/70 rounded-2xl p-6 flex flex-col justify-between shadow-2xs relative overflow-hidden">
      {/* Accent Top Border */}
      <div className={`absolute top-0 left-0 right-0 h-[5px] ${getAccentClass(tier.id)}`}></div>

      <div>
        <div className="flex flex-col items-start gap-1 pt-1 mb-5">
          <h3 className="font-headline-sm text-[18px] font-bold text-on-surface">
            {getDisplayName(tier)}
          </h3>
          <span className="text-[11px] font-mono font-medium text-on-surface-variant uppercase tracking-wider bg-[#e5e5e5] px-2.5 py-0.5 rounded">
            {getBadge(tier)}
          </span>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div className="flex flex-col gap-1.5">
            <label className="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider">MONTHLY PRICE</label>
            <div className="bg-[#e5e5e5] border border-outline-variant/40 rounded-lg px-3 py-2 flex items-center gap-2">
              <span className="font-mono font-bold text-on-surface text-sm">$</span>
              <input
                type="number"
                step="0.01"
                min="0"
                value={monthly}
                onChange={e => setMonthly(e.target.value)}
                className="bg-transparent border-0 outline-none w-full font-mono font-bold text-on-surface text-sm"
              />
            </div>
          </div>

          <div className="flex flex-col gap-1.5">
            <label className="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider">YEARLY PRICE</label>
            <div className="bg-[#e5e5e5] border border-outline-variant/40 rounded-lg px-3 py-2 flex items-center gap-2">
              <span className="font-mono font-bold text-on-surface text-sm">$</span>
              <input
                type="number"
                step="0.01"
                min="0"
                value={yearly}
                onChange={e => setYearly(e.target.value)}
                className="bg-transparent border-0 outline-none w-full font-mono font-bold text-on-surface text-sm"
              />
            </div>
          </div>
        </div>
      </div>

      <div className="border-t border-outline-variant/30 mt-5 pt-4 flex justify-end">
        <button
          onClick={handleSave}
          disabled={saving}
          className={`px-5 py-2 border rounded-lg font-bold text-[13px] transition-all flex items-center gap-2 cursor-pointer shadow-2xs ${
            saved
              ? 'bg-green-500 text-white border-green-500'
              : 'border-[#2563eb]/40 text-[#2563eb] hover:border-[#2563eb] bg-surface-container-lowest hover:bg-blue-50/20'
          }`}
        >
          {saving ? (
            <span className="material-symbols-outlined animate-spin text-[16px]">sync</span>
          ) : saved ? (
            <span className="material-symbols-outlined text-[16px]">check_circle</span>
          ) : (
            <span className="material-symbols-outlined text-[16px] text-[#2563eb]">save</span>
          )}
          <span>{saving ? 'Saving...' : saved ? 'Saved!' : 'Save Changes'}</span>
        </button>
      </div>
    </div>
  );
};

// Helper functions for Reschedule Modal Date & Time
const parseToISODate = (dateStr) => {
  if (!dateStr) return new Date().toISOString().split('T')[0];
  if (/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) return dateStr;
  const parsed = new Date(dateStr);
  if (!isNaN(parsed.getTime())) {
    const yyyy = parsed.getFullYear();
    const mm = String(parsed.getMonth() + 1).padStart(2, '0');
    const dd = String(parsed.getDate()).padStart(2, '0');
    return `${yyyy}-${mm}-${dd}`;
  }
  return new Date().toISOString().split('T')[0];
};

const formatToReadableDate = (isoStr) => {
  if (!isoStr) return '';
  if (!/^\d{4}-\d{2}-\d{2}$/.test(isoStr)) return isoStr;
  const [yyyy, mm, dd] = isoStr.split('-');
  const parsed = new Date(parseInt(yyyy, 10), parseInt(mm, 10) - 1, parseInt(dd, 10));
  if (!isNaN(parsed.getTime())) {
    return parsed.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });
  }
  return isoStr;
};

const parseToISOTime = (timeStr) => {
  if (!timeStr) return '09:00';
  if (/^\d{2}:\d{2}$/.test(timeStr)) return timeStr;
  const match = timeStr.match(/(\d{1,2}):(\d{2})\s*(AM|PM)?/i);
  if (match) {
    let hours = parseInt(match[1], 10);
    const minutes = match[2];
    const ampm = match[3] ? match[3].toUpperCase() : null;
    if (ampm === 'PM' && hours < 12) hours += 12;
    if (ampm === 'AM' && hours === 12) hours = 0;
    return `${String(hours).padStart(2, '0')}:${minutes}`;
  }
  return '09:00';
};

const formatTo12HrTime = (isoTime) => {
  if (!isoTime) return '';
  if (/AM|PM/i.test(isoTime)) return isoTime;
  const [hStr, mStr] = isoTime.split(':');
  if (hStr !== undefined && mStr !== undefined) {
    let h = parseInt(hStr, 10);
    const ampm = h >= 12 ? 'PM' : 'AM';
    h = h % 12 || 12;
    return `${String(h).padStart(2, '0')}:${mStr} ${ampm}`;
  }
  return isoTime;
};

const SuperAdminPanel = () => {
  const { user, refreshAccessToken, loading: authLoading } = useAuth();

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
  const [recentPayments, setRecentPayments] = useState([]);
  const [trends, setTrends] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [users, setUsers] = useState([]);
  const [demoBookings, setDemoBookings] = useState([]);
  const [emailLogs, setEmailLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState(() => {
    try {
      const params = new URLSearchParams(window.location.search);
      const tabFromUrl = params.get('tab');
      const storedTab = localStorage.getItem('superAdminActiveTab');
      return tabFromUrl || storedTab || 'overview';
    } catch (e) {
      return 'overview';
    }
  });

  useEffect(() => {
    try {
      localStorage.setItem('superAdminActiveTab', activeTab);
    } catch (e) {}
  }, [activeTab]);

  const [sortOrgCol, setSortOrgCol] = useState('Tenant Name');
  const [sortOrgDir, setSortOrgDir] = useState('asc');

  const [sortUserCol, setSortUserCol] = useState('Email');
  const [sortUserDir, setSortUserDir] = useState('asc');

  // Filter states for Global Members
  const [userSearch, setUserSearch] = useState('');
  const [userRoleFilter, setUserRoleFilter] = useState('all');
  const [userOrgFilter, setUserOrgFilter] = useState('all');

  const [sortBillCol, setSortBillCol] = useState('Date');
  const [sortBillDir, setSortBillDir] = useState('desc');

  // Pagination state for SuperAdmin tables
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

  const [bookingSearch, setBookingSearch] = useState('');
  const [bookingStatusFilter, setBookingStatusFilter] = useState('all');

  const getFilteredBookings = () => {
    return (demoBookings || []).filter(b => {
      if (!b) return false;
      const q = (bookingSearch || '').toLowerCase().trim();
      const emailMatch = !bookingSearch || 
        (b.email || '').toLowerCase().includes(q) || 
        (b.company_size || '').toLowerCase().includes(q) ||
        (b.meeting_date || '').toLowerCase().includes(q);
      
      const statusMatch = bookingStatusFilter === 'all' || (b.status || 'pending') === bookingStatusFilter;
      return emailMatch && statusMatch;
    });
  };

  // Payments Filtering
  const [paymentSearch, setPaymentSearch] = useState('');
  const [paymentStatusFilter, setPaymentStatusFilter] = useState('all');

  const getFilteredBills = () => {
    return (recentPayments || []).filter(p => {
      const q = paymentSearch.toLowerCase().trim();
      const matchSearch = !paymentSearch || 
        (p.org_name || '').toLowerCase().includes(q) ||
        (p.stripe_payment_id || p.id || '').toLowerCase().includes(q) ||
        (p.tier_id || '').toLowerCase().includes(q);
      const matchStatus = paymentStatusFilter === 'all' || (p.status || '').toLowerCase() === paymentStatusFilter.toLowerCase();
      return matchSearch && matchStatus;
    });
  };

  const getSortedBills = () => {
    const filtered = getFilteredBills();
    return [...filtered].sort((a, b) => {
      let aVal, bVal;
      switch (sortBillCol) {
        case 'Date': aVal = new Date(a.created_at || Date.now()).getTime(); bVal = new Date(b.created_at || Date.now()).getTime(); break;
        case 'Organization / User': aVal = a.org_name || ''; bVal = b.org_name || ''; break;
        case 'Tier': aVal = a.tier_id || ''; bVal = b.tier_id || ''; break;
        case 'Amount': aVal = a.amount || 0; bVal = b.amount || 0; break;
        case 'Status': aVal = a.status || ''; bVal = b.status || ''; break;
        default: return 0;
      }
      if (aVal < bVal) return sortBillDir === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortBillDir === 'asc' ? 1 : -1;
      return 0;
    });
  };

  // Organizations Filtering
  const [orgSearch, setOrgSearch] = useState('');
  const [orgTierFilter, setOrgTierFilter] = useState('all');
  const [orgStatusFilter, setOrgStatusFilter] = useState('all');

  const getFilteredOrgs = () => {
    return (organizations || []).filter(org => {
      const q = orgSearch.toLowerCase().trim();
      const matchSearch = !orgSearch || (org.name || '').toLowerCase().includes(q) || (org.id || '').toLowerCase().includes(q);
      const rawTier = (org.tier || org.subscription_tier || '').toLowerCase();
      const matchTier = orgTierFilter === 'all' || rawTier.includes(orgTierFilter.toLowerCase());
      const orgStatus = (org.status || (org.is_active ? 'active' : 'inactive')).toLowerCase();
      const matchStatus = orgStatusFilter === 'all' || orgStatus === orgStatusFilter.toLowerCase();
      return matchSearch && matchTier && matchStatus;
    });
  };

  const getSortedOrgs = () => {
    const filtered = getFilteredOrgs();
    return [...filtered].sort((a, b) => {
      let aVal, bVal;
      switch (sortOrgCol) {
        case 'Tenant Name': aVal = a.name || ''; bVal = b.name || ''; break;
        case 'Tier': aVal = a.tier || a.subscription_tier || ''; bVal = b.tier || b.subscription_tier || ''; break;
        case 'Status': aVal = a.status || (a.is_active ? 'active' : 'inactive'); bVal = b.status || (b.is_active ? 'active' : 'inactive'); break;
        default: return 0;
      }
      if (aVal < bVal) return sortOrgDir === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortOrgDir === 'asc' ? 1 : -1;
      return 0;
    });
  };

  // Audit Logs Filtering
  const [auditSearch, setAuditSearch] = useState('');

  const getFilteredAuditLogs = () => {
    return (auditLogs || []).filter(log => {
      if (!auditSearch) return true;
      const q = auditSearch.toLowerCase().trim();
      return (log.action || '').toLowerCase().includes(q) ||
        (log.user_email || log.admin_id || '').toLowerCase().includes(q) ||
        (log.target_name || log.target_id || '').toLowerCase().includes(q);
    });
  };

  // Outbound Email Logs Filtering
  const [emailSearch, setEmailSearch] = useState('');
  const [emailStatusFilter, setEmailStatusFilter] = useState('all');

  const getFilteredEmails = () => {
    return (emailLogs || []).filter(e => {
      const q = emailSearch.toLowerCase().trim();
      const matchSearch = !emailSearch ||
        (e.recipient || '').toLowerCase().includes(q) ||
        (e.subject || '').toLowerCase().includes(q);
      const matchStatus = emailStatusFilter === 'all' || (e.status || '').toLowerCase() === emailStatusFilter.toLowerCase();
      return matchSearch && matchStatus;
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
      if (userSearch) {
        const q = userSearch.toLowerCase().trim();
        const emailMatch = (u.email || '').toLowerCase().includes(q);
        const roleMatch = (u.role || '').toLowerCase().includes(q);
        const orgMatch = (u.org_name || '').toLowerCase().includes(q);
        if (!emailMatch && !roleMatch && !orgMatch) return false;
      }

      if (userRoleFilter !== 'all') {
        if ((u.role || '').toLowerCase() !== userRoleFilter.toLowerCase()) return false;
      }

      if (userOrgFilter !== 'all') {
        if (userOrgFilter === 'no_org') {
          if (u.org_id || (u.org_name && !u.org_name.startsWith('No Org'))) return false;
        } else {
          if (String(u.org_id) !== String(userOrgFilter) && u.org_name !== userOrgFilter) return false;
        }
      }

      return true;
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
        default: return 0;
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

  const handleBillSort = (column) => {
    if (column === 'Invoice') return;
    if (sortBillCol === column) {
      setSortBillDir(sortBillDir === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBillCol(column);
      setSortBillDir('asc');
    }
  };

  const [metrics, setMetrics] = useState({
    total_tenants: 0,
    active_licenses: 0,
    global_users: 0,
    active_scanners: 0,
    total_scanners: 15,
    arr: 0,
    db_connections: 0,
    db_query_time: 0,
    queue_size: 0,
    active_threads: 0
  });

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
        setRecentPayments(Array.isArray(data.recent_payments) ? data.recent_payments : []);
        setTrends(Array.isArray(data.trends) ? data.trends : []);
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
      console.error('Failed to fetch global stats', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  // Modal States
  const [pricingModalOpen, setPricingModalOpen] = useState(false);
  const [activeScansModalOpen, setActiveScansModalOpen] = useState(false);

  // Custom Prompts & Confirms
  const [confirmModal, setConfirmModal] = useState({ isOpen: false, title: '', desc: '', onConfirm: null, type: 'primary' });
  const [promptModal, setPromptModal] = useState({ isOpen: false, title: '', desc: '', inputs: [], onConfirm: null });
  const [promptValues, setPromptValues] = useState({});
  const [showPasswordPrompt, setShowPasswordPrompt] = useState({});
  const [viewInvoice, setViewInvoice] = useState(null);
  const [rescheduleModal, setRescheduleModal] = useState({
    isOpen: false,
    bookingId: null,
    email: '',
    meetingDate: '',
    isoDate: '',
    meetingTime: '',
    isoTime: '',
    status: 'rescheduled'
  });

  const closeConfirm = () => setConfirmModal({ isOpen: false, title: '', desc: '', onConfirm: null, type: 'primary' });
  const closePrompt = () => { setPromptModal({ isOpen: false, title: '', desc: '', inputs: [], onConfirm: null }); setPromptValues({}); setShowPasswordPrompt({}); };

  const handlePromptChange = (key, value) => setPromptValues(prev => ({ ...prev, [key]: value }));

  const handleSuspend = (orgId, currentStatus) => {
    const action = currentStatus === 'suspended' ? 'activate' : 'suspend';
    setConfirmModal({
      isOpen: true,
      title: `${action === 'activate' ? 'Activate' : 'Suspend'} Tenant`,
      desc: `Are you sure you want to ${action} this tenant?`,
      type: action === 'suspend' ? 'error' : 'primary',
      onConfirm: async () => {
        try {
          const res = await fetch(`/api/auth/organizations/${orgId}/suspend`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('wss_token')}` }
          });
          if (res.ok) fetchStats();
        } catch (err) { }
        closeConfirm();
      }
    });
  };

  const handleDeleteTenant = (orgId, orgName) => {
    setConfirmModal({
      isOpen: true,
      title: 'Delete Tenant',
      desc: `Are you sure you want to completely delete ${orgName}? This action cannot be undone.`,
      type: 'error',
      onConfirm: async () => {
        try {
          const res = await fetch(`/api/auth/organizations/${orgId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('wss_token')}` }
          });
          if (res.ok) {
            toast.success('Tenant deleted successfully');
            fetchStats();
          } else {
            toast.error('Failed to delete tenant');
          }
        } catch (err) {
          toast.error('Network error');
        }
        closeConfirm();
      }
    });
  };

  const handleImpersonate = (orgId, orgName) => {
    setConfirmModal({
      isOpen: true,
      title: 'Impersonate Tenant',
      desc: `Log in as administrator for ${orgName}?`,
      type: 'primary',
      onConfirm: async () => {
        try {
          const res = await fetch(`/api/auth/impersonate/${orgId}`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('wss_token')}` }
          });
          if (res.ok) {
            const data = await res.json();
            localStorage.setItem('original_admin_token', localStorage.getItem('wss_token'));
            localStorage.setItem('wss_token', data.access_token);
            window.location.href = '/dashboard';
          }
        } catch (err) { }
        closeConfirm();
      }
    });
  };

  const [tiers, setTiers] = useState([]);
  const [fetchingTiers, setFetchingTiers] = useState(false);

  const openPricingModal = async () => {
    setPricingModalOpen(true);
    setFetchingTiers(true);
    try {
      const res = await fetch('/api/billing/tiers', { headers: { 'Authorization': `Bearer ${localStorage.getItem('wss_token')}` } });
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data) && data.length > 0) {
          setTiers(data);
        } else {
          setTiers(DEFAULT_BILLING_TIERS);
        }
      } else {
        setTiers(DEFAULT_BILLING_TIERS);
      }
    } catch (err) {
      setTiers(DEFAULT_BILLING_TIERS);
    }
    setFetchingTiers(false);
  };

  const handleUpdateTier = async (tierId, monthly, yearly) => {
    try {
      await fetch(`/api/billing/tiers/${tierId}`, {
        method: 'PUT',
        headers: { 'Authorization': `Bearer ${localStorage.getItem('wss_token')}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ monthly_price: parseInt(monthly), yearly_price: parseInt(yearly) })
      });
      fetchStats();
    } catch (err) { }
  };

  const [activeScans, setActiveScans] = useState([]);
  const [fetchingActiveScans, setFetchingActiveScans] = useState(false);

  const openActiveScansModal = async () => {
    setActiveScansModalOpen(true);
    setFetchingActiveScans(true);
    try {
      const res = await fetch('/api/scans/active', { headers: { 'Authorization': `Bearer ${localStorage.getItem('wss_token')}` } });
      if (res.ok) {
        const data = await res.json();
        setActiveScans(data.scans || []);
      }
    } catch (err) { }
    setFetchingActiveScans(false);
  };

  const handleKillScan = (scanId) => {
    setConfirmModal({
      isOpen: true,
      title: 'Terminate Scan',
      desc: 'Are you sure you want to forcibly terminate this scan?',
      type: 'error',
      onConfirm: async () => {
        try {
          await fetch(`/api/scans/${scanId}/terminate`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('wss_token')}` }
          });
          openActiveScansModal();
        } catch (err) { }
        closeConfirm();
      }
    });
  };

  const handleProvisionTenant = () => {
    setPromptValues({ tier: 'none', name: '', admin_email: '' });
    setPromptModal({
      isOpen: true,
      title: 'Add New Organization',
      desc: 'Create a new tenant organization.',
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
            { label: 'Enterprise(Custom)', value: 'Enterprise(Custom)' }
          ] 
        },
        { key: 'admin_email', label: 'Admin Email (Optional)', placeholder: 'admin@company.com' }
      ],
      onConfirm: async (values) => {
        try {
          const res = await fetch('/api/auth/organizations', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('wss_token')}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: values.name, tier: values.tier, admin_email: values.admin_email })
          });
          if (res.ok) {
            toast.success('Organization created successfully');
            fetchStats();
          } else {
            toast.error('Failed to create organization');
          }
        } catch (err) {
          toast.error('Network error creating organization');
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
          toast.error('Please enter a valid scan count');
          return;
        }
        try {
          const res = await fetch(`/api/auth/organizations/${org.id}/quotas`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('wss_token')}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ scan_type: values.scan_type, count: addedCount })
          });
          if (res.ok) {
            toast.success(`${addedCount} ${values.scan_type} scan(s) assigned successfully!`);
            // Optimistic instant state update
            setOrganizations(prevOrgs => prevOrgs.map(o => {
              if (o.id === org.id) {
                const existingQuotas = o.quotas || [];
                let found = false;
                const updatedQuotas = existingQuotas.map(q => {
                  if (q.scan_type?.toLowerCase() === values.scan_type?.toLowerCase()) {
                    found = true;
                    return {
                      ...q,
                      allocated_count: q.allocated_count === -1 ? -1 : (q.allocated_count || 0) + addedCount
                    };
                  }
                  return q;
                });
                if (!found) {
                  updatedQuotas.push({ scan_type: values.scan_type, allocated_count: addedCount, used_count: 0 });
                }
                return { ...o, quotas: updatedQuotas };
              }
              return o;
            }));
            fetchStats();
          } else {
            const data = await res.json();
            toast.error(data.message || 'Failed to assign scans.');
          }
        } catch (err) {
          toast.error('Network error assigning scans.');
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

    setPromptValues({ 
      name: org.name, 
      tier: initialTier
    });
    setPromptModal({
      isOpen: true,
      title: 'Edit Organization',
      desc: `Modify settings for ${org.name}`,
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
            { label: 'Enterprise(Custom)', value: 'Enterprise(Custom)' }
          ] 
        }
      ],
      onConfirm: async (values) => {
        try {
          const res = await fetch(`/api/auth/organizations/${org.id}`, {
            method: 'PUT',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('wss_token')}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: values.name, tier: values.tier })
          });
          if (res.ok) {
            toast.success('Organization updated successfully');
            fetchStats();
          } else {
            toast.error('Failed to update organization');
          }
        } catch (err) {
          toast.error('Network error updating organization');
        }
        closePrompt();
      }
    });
  };

  // Member CRUD
  const MEMBER_ROLE_OPTIONS = (user?.role === 'admin'
    ? [
        { label: 'Admin', value: 'admin' },
        { label: 'SOC Analyst', value: 'soc_analyst' },
        { label: 'Organization Admin', value: 'org_admin' },
        { label: 'Executive User', value: 'executive_user' },
        { label: 'Support Engineer', value: 'support_engineer' },
        { label: 'Read Only', value: 'read_only' }
      ]
    : [
        { label: 'Admin', value: 'admin' },
        { label: 'SOC Analyst', value: 'soc_analyst' },
        { label: 'Organization Admin', value: 'org_admin' },
        { label: 'Executive User', value: 'executive_user' },
        { label: 'Super Admin', value: 'super_admin' },
        { label: 'Support Engineer', value: 'support_engineer' },
        { label: 'Read Only', value: 'read_only' }
      ]
  );

  const handleAddMember = () => {
    const orgOptions = [
      { label: 'None (Global)', value: '' },
      ...(organizations || []).map(o => ({ label: o.name, value: String(o.id) }))
    ];

    setPromptValues({ email: '', password: '', role: 'admin', org_id: '' });
    setPromptModal({
      isOpen: true,
      title: 'Add Member',
      desc: 'Invite or add a new global platform member.',
      inputs: [
        { key: 'email', label: 'User Email', placeholder: 'user@example.com' },
        { key: 'password', label: 'Password (Optional - Auto-generated if left blank)', placeholder: 'Set initial password...', type: 'password', showRules: true },
        { key: 'role', label: 'Role', type: 'select', options: MEMBER_ROLE_OPTIONS },
        { key: 'org_id', label: 'Organization', type: 'select', options: orgOptions }
      ],
      onConfirm: async (values) => {
        if (!values.email || !values.email.trim()) {
          toast.error('Please enter a valid user email');
          return;
        }
        const pwd = values.password ? values.password.trim() : '';
        if (pwd && (pwd.length < 8 || !/[A-Z]/.test(pwd) || !/[a-z]/.test(pwd) || !/[^A-Za-z0-9]/.test(pwd))) {
          toast.error('Password must meet all 4 security requirements (8+ chars, 1 uppercase, 1 lowercase, 1 special character).');
          return;
        }
        try {
          const res = await authFetch('/api/auth/users', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              email: values.email.trim(),
              role: values.role,
              org_id: values.org_id || null,
              password: pwd || null
            })
          });
          const data = await res.json().catch(() => ({}));
          if (res.ok) {
            toast.success('Member added successfully');
            fetchStats();
          } else {
            toast.error(data.message || 'Failed to add member');
          }
        } catch (err) {
          toast.error('Network error adding member');
        }
        closePrompt();
      }
    });
  };

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

    const isSupport = user?.role === 'support_engineer';

    setPromptValues({
      email: u.email,
      role: u.role || 'admin',
      org_id: initialOrgId,
      password: ''
    });

    const modalInputs = [
      { key: 'email', label: 'User Email', disabled: true }
    ];

    if (!isSupport) {
      modalInputs.push({
        key: 'password',
        label: 'New Password (Leave blank to keep current password)',
        placeholder: 'Type new password to update...',
        type: 'password',
        showRules: true
      });
    }

    modalInputs.push(
      { key: 'role', label: 'Role', type: 'select', options: MEMBER_ROLE_OPTIONS },
      { key: 'org_id', label: 'Organization', type: 'select', options: orgOptions }
    );

    setPromptModal({
      isOpen: true,
      title: isSupport ? 'Edit Member Role & Organization' : 'Edit Member & Password',
      desc: isSupport ? `Update role & organization mapping for ${u.email}` : `Update details & credentials for ${u.email}`,
      inputs: modalInputs,
      onConfirm: async (vals) => {
        const pwd = vals.password ? vals.password.trim() : '';
        if (pwd && !isSupport && (pwd.length < 8 || !/[A-Z]/.test(pwd) || !/[a-z]/.test(pwd) || !/[^A-Za-z0-9]/.test(pwd))) {
          toast.error('Password must meet all 4 security requirements (8+ chars, 1 uppercase, 1 lowercase, 1 special character).');
          return;
        }
        try {
          const res = await authFetch(`/api/auth/users/${u.id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              role: vals.role,
              org_id: vals.org_id || null,
              password: (!isSupport && pwd) ? pwd : null
            })
          });
          const data = await res.json().catch(() => ({}));
          if (res.ok) {
            toast.success('Member details updated successfully');
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

  const handleDownloadInvoice = (payment) => {
    const invoiceHtml = `
      <html>
        <head>
          <title>Invoice - ${payment.id}</title>
          <style>
            body { font-family: sans-serif; padding: 40px; color: #333; }
            h1 { color: #2563eb; margin-bottom: 5px; }
            .header { border-bottom: 2px solid #eee; padding-bottom: 20px; margin-bottom: 20px; }
            .row { display: flex; justify-content: space-between; margin-bottom: 10px; font-size: 14px; }
            .total { font-size: 20px; font-weight: bold; margin-top: 30px; border-top: 2px solid #eee; padding-top: 20px; }
          </style>
        </head>
        <body>
          <div class="header">
            <h1>LarShield</h1>
            <p style="margin: 0; color: #666;">Payment Receipt & Invoice</p>
          </div>
          <div class="row"><strong>Date:</strong> <span>${new Date(payment.created_at).toLocaleString()}</span></div>
          <div class="row"><strong>Organization:</strong> <span>${payment.org_name}</span></div>
          <div class="row"><strong>Email:</strong> <span>${payment.user_email}</span></div>
          <div class="row"><strong>Subscription Tier:</strong> <span><span style="text-transform: capitalize;">${payment.tier_id}</span> Plan</span></div>
          <div class="row"><strong>Status:</strong> <span style="color: ${payment.status === 'successful' ? 'green' : 'red'}">${payment.status.toUpperCase()}</span></div>
          <div class="row total">
            <strong>Total Amount:</strong> 
            <span>${payment.currency === 'INR' ? '₹' : '$'}${payment.amount.toLocaleString(undefined, { minimumFractionDigits: 2 })}</span>
          </div>
          <script>window.print();</script>
        </body>
      </html>
    `;
    const blob = new Blob([invoiceHtml], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    window.open(url, '_blank');
  };

  const isSupportEngineer = user?.role === 'support_engineer';
  const isSuperAdmin = user?.role === 'super_admin' || user?.role === 'admin' || sessionStorage.getItem('superAdminAuth') === 'true';

  if (authLoading || loading) {
    return (
      <div className="flex h-[70vh] items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <span className="material-symbols-outlined animate-spin text-3xl text-primary">sync</span>
          <span className="font-bold text-on-surface-variant text-sm">Verifying Management Session...</span>
        </div>
      </div>
    );
  }

  if (!isSuperAdmin && !isSupportEngineer) {
    return (
      <div className="min-h-[60vh] flex flex-col items-center justify-center text-center p-6">
        <div className="w-16 h-16 rounded-full bg-red-500/10 text-error flex items-center justify-center mb-4">
          <span className="material-symbols-outlined text-3xl">lock</span>
        </div>
        <h2 className="text-xl font-bold text-on-surface mb-2">Access Restricted</h2>
        <p className="text-on-surface-variant text-sm max-w-md mb-6 leading-relaxed">
          You do not have administrative permissions to access LarShield Global Management.
        </p>
        <div className="flex gap-3">
          <Link to="/dashboard" className="px-4 py-2 bg-primary text-white rounded-lg font-bold text-sm no-underline shadow-md">
            Go to Dashboard
          </Link>
          <Link to="/larshield-superadmin" className="px-4 py-2 bg-surface-container border border-outline-variant text-on-surface rounded-lg font-bold text-sm no-underline">
            Super Admin Login
          </Link>
        </div>
      </div>
    );
  }

  const handleUpdateBookingStatus = async (bookingId, status) => {
    try {
      const res = await fetch(`/api/demo/bookings/${bookingId}`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('wss_token')}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ status })
      });
      if (res.ok) {
        toast.success(`Booking status updated to ${status}`);
        fetchStats();
      } else {
        toast.error("Failed to update booking status");
      }
    } catch (err) {
      toast.error("Network error updating booking");
    }
  };

  const handleCancelBooking = (booking) => {
    setConfirmModal({
      isOpen: true,
      title: 'Cancel Demo Booking',
      desc: `Are you sure you want to cancel the demo call booking for ${booking.email || 'this lead'}?`,
      type: 'error',
      onConfirm: async () => {
        await handleUpdateBookingStatus(booking.id, 'cancelled');
        closeConfirm();
      }
    });
  };

  const handleOpenReschedule = (booking) => {
    const rawDate = booking.meeting_date || '';
    const rawTime = booking.meeting_time || '';
    const isoDate = parseToISODate(rawDate);
    const isoTime = parseToISOTime(rawTime);
    const formattedDate = formatToReadableDate(isoDate);
    const formattedTime = formatTo12HrTime(isoTime);

    setRescheduleModal({
      isOpen: true,
      bookingId: booking.id,
      email: booking.email,
      meetingDate: formattedDate,
      isoDate: isoDate,
      meetingTime: formattedTime,
      isoTime: isoTime,
      status: booking.status === 'pending' || !booking.status ? 'rescheduled' : booking.status
    });
  };

  const handleSaveReschedule = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch(`/api/demo/bookings/${rescheduleModal.bookingId}`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('wss_token')}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          meeting_date: rescheduleModal.meetingDate || formatToReadableDate(rescheduleModal.isoDate),
          meeting_time: rescheduleModal.meetingTime || formatTo12HrTime(rescheduleModal.isoTime),
          status: rescheduleModal.status
        })
      });
      if (res.ok) {
        toast.success("Demo booking rescheduled successfully!");
        setRescheduleModal({ isOpen: false, bookingId: null, email: '', meetingDate: '', isoDate: '', meetingTime: '', isoTime: '', status: 'rescheduled' });
        fetchStats();
      } else {
        toast.error("Failed to reschedule demo booking");
      }
    } catch (err) {
      toast.error("Error rescheduling booking");
    }
  };

  const handleDeleteBooking = (booking) => {
    const bookingId = typeof booking === 'object' ? booking.id : booking;
    const email = typeof booking === 'object' && booking.email ? booking.email : '';
    setConfirmModal({
      isOpen: true,
      title: 'Delete Demo Lead',
      desc: email 
        ? `Are you sure you want to permanently delete the demo lead for ${email}?`
        : 'Are you sure you want to permanently delete this demo booking lead?',
      type: 'error',
      onConfirm: async () => {
        try {
          const res = await fetch(`/api/demo/bookings/${bookingId}`, {
            method: 'DELETE',
            headers: {
              'Authorization': `Bearer ${localStorage.getItem('wss_token')}`
            }
          });
          if (res.ok) {
            toast.success("Demo lead deleted successfully");
            fetchStats();
          } else {
            toast.error("Failed to delete demo lead");
          }
        } catch (err) {
          toast.error("Error deleting lead");
        }
        closeConfirm();
      }
    });
  };

  return (
    <div className="w-full text-on-surface animate-fade-in">
      {/* Support Engineer Information Banner */}
      {isSupportEngineer && (
        <div className="mb-lg p-md bg-blue-500/10 border border-blue-500/30 rounded-2xl flex flex-col md:flex-row items-start md:items-center justify-between gap-md text-blue-400">
          <div className="flex items-center gap-md">
            <span className="material-symbols-outlined text-[32px] text-blue-400 shrink-0">support_agent</span>
            <div>
              <div className="font-bold text-[16px] text-blue-300">Support Engineer Portal (Client Support)</div>
              <div className="text-[13px] opacity-90 text-blue-200/80 mt-0.5">
                <strong>Permissions:</strong> Can view customer environments, assist troubleshooting (impersonation), and inspect logs & active scans.
                <span className="text-amber-400 font-semibold ml-1">(Cannot delete organizations or change subscription pricing).</span>
              </div>
            </div>
          </div>
          <span className="px-3 py-1 bg-blue-600 text-white font-bold text-[11px] uppercase tracking-wider rounded-full shrink-0 shadow-sm">
            Support Role
          </span>
        </div>
      )}

      {/* Header Section */}
      <div className="flex flex-col xl:flex-row xl:items-center justify-between mb-xl gap-4">
        <div className="shrink-0">
          <h1 className="text-[28px] font-extrabold font-display tracking-tight brand-gradient">
            {isSupportEngineer ? 'Support Engineer Operations' : 'LarShield Global Management'}
          </h1>
          <p className="text-on-surface-variant text-[14px] mt-1">
            {isSupportEngineer
              ? 'Client environment inspection, troubleshooting assistance, and system logs.'
              : 'Centralized oversight for all client organizations and scanning nodes.'}
          </p>
        </div>
        <div className="flex gap-2 flex-wrap xl:flex-nowrap justify-start xl:justify-end">
          <button onClick={fetchStats} className="flex items-center px-3 py-2 bg-surface-container border border-outline-variant text-on-surface rounded-lg hover:bg-surface-container-high transition-colors font-bold text-[13px] whitespace-nowrap cursor-pointer">
            <RefreshCw className={`w-4 h-4 mr-2 text-primary ${loading ? 'animate-spin' : ''}`} /> Sync Metrics
          </button>
          {!isSupportEngineer && (
            <button onClick={openPricingModal} className="flex items-center px-3 py-2 bg-surface-container border border-outline-variant text-on-surface rounded-lg hover:bg-surface-container-high transition-colors font-bold text-[13px] whitespace-nowrap cursor-pointer">
              <CreditCard className="w-4 h-4 mr-2 text-primary" /> Manage Pricing
            </button>
          )}
          <Link to="/organization" className="flex items-center px-3 py-2 bg-surface-container border border-outline-variant text-on-surface rounded-lg hover:bg-surface-container-high transition-colors font-bold text-[13px] whitespace-nowrap cursor-pointer" style={{ textDecoration: 'none' }}>
            <BarChart2 className="w-4 h-4 mr-2 text-primary" /> Org Dashboard
          </Link>
          <Link to="/super-admin/logs" className="flex items-center px-3 py-2 bg-surface-container border border-outline-variant text-on-surface rounded-lg hover:bg-surface-container-high transition-colors font-bold text-[13px] whitespace-nowrap cursor-pointer" style={{ textDecoration: 'none' }}>
            <Activity className="w-4 h-4 mr-2 text-primary" /> Logs & Threats
          </Link>
          {!isSupportEngineer && (
            <button onClick={handleProvisionTenant} className="flex items-center px-3 py-2 bg-primary text-white rounded-lg hover:brightness-110 transition-all font-bold text-[13px] whitespace-nowrap border-0 cursor-pointer shadow-md shadow-primary/20">
              <Plus className="w-4 h-4 mr-2" /> Add Organization
            </button>
          )}
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-4 mb-8 border-b border-outline-variant pb-2 overflow-x-auto hide-scrollbar">
        {['overview', 'organizations', 'members', 'audit', 'bookings', 'emails'].map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 font-bold text-[14px] rounded-lg transition-colors capitalize ${activeTab === tab ? 'bg-primary text-white shadow-md' : 'bg-transparent text-on-surface-variant hover:text-on-surface hover:bg-surface-container'
              } border-0 cursor-pointer`}
          >
            {tab === 'audit' ? 'Audit Logs' : tab.replace('_', ' ')}
          </button>
        ))}
      </div>

      {activeTab === 'overview' && (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-md mb-xl">
            <div className="bg-surface-container-lowest border border-outline-variant p-md rounded-2xl shadow-sm hover:shadow-md hover:border-primary/30 transition-all group">
              <div className="flex justify-between items-start">
                <div>
                  <p className="text-on-surface-variant font-bold text-[12px] uppercase tracking-wider mb-1">Total Tenants</p>
                  <h3 className="text-[32px] font-extrabold tracking-tight text-on-surface group-hover:text-primary transition-colors">{metrics.total_tenants}</h3>
                </div>
                <div className="bg-primary/10 p-2 rounded-xl border border-primary/20 group-hover:scale-110 transition-transform"><Building2 className="text-primary w-6 h-6" /></div>
              </div>
            </div>
            <div className="bg-surface-container-lowest border border-outline-variant p-md rounded-2xl shadow-sm hover:shadow-md hover:border-primary/30 transition-all group">
              <div className="flex justify-between items-start">
                <div>
                  <p className="text-on-surface-variant font-bold text-[12px] uppercase tracking-wider mb-1">Active Licenses</p>
                  <h3 className="text-[32px] font-extrabold tracking-tight text-on-surface group-hover:text-primary transition-colors">{metrics.active_licenses}</h3>
                </div>
                <div className="bg-primary/10 p-2 rounded-xl border border-primary/20 group-hover:scale-110 transition-transform"><CreditCard className="text-primary w-6 h-6" /></div>
              </div>
            </div>
            <div className="bg-surface-container-lowest border border-outline-variant p-md rounded-2xl shadow-sm hover:shadow-md hover:border-primary/30 transition-all group">
              <div className="flex justify-between items-start">
                <div>
                  <p className="text-on-surface-variant font-bold text-[12px] uppercase tracking-wider mb-1">Global Users</p>
                  <h3 className="text-[32px] font-extrabold tracking-tight text-on-surface group-hover:text-primary transition-colors">{metrics.global_users}</h3>
                </div>
                <div className="bg-primary/10 p-2 rounded-xl border border-primary/20 group-hover:scale-110 transition-transform"><Users className="text-primary w-6 h-6" /></div>
              </div>
            </div>
            <div className="bg-surface-container-lowest border border-outline-variant p-md rounded-2xl shadow-sm hover:shadow-md hover:border-primary/30 transition-all group">
              <div className="flex justify-between items-start">
                <div>
                  <p className="text-on-surface-variant font-bold text-[12px] uppercase tracking-wider mb-1">Active Scanners</p>
                  <h3 className="text-[32px] font-extrabold tracking-tight text-on-surface group-hover:text-primary transition-colors">{metrics.active_scanners}<span className="text-[18px] text-on-surface-variant font-medium">/{metrics.total_scanners}</span></h3>
                </div>
                <div className="bg-primary/10 p-2 rounded-xl border border-primary/20 group-hover:scale-110 transition-transform"><Server className="text-primary w-6 h-6" /></div>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-xl">
            <div className="lg:col-span-1 flex flex-col gap-md">
              <h2 className="font-headline-sm font-bold text-on-surface flex items-center text-[18px]"><Activity className="w-5 h-5 text-primary mr-2" /> Node Infrastructure</h2>
              <div className="bg-surface-container-lowest border border-outline-variant rounded-2xl p-md flex flex-col gap-sm shadow-sm">
                <div className="flex justify-between items-center pb-sm border-b border-outline-variant/50">
                  <div className="flex items-center gap-xs text-[13px] font-bold text-on-surface"><Database className="w-4 h-4 text-primary" /> PostgreSQL Cluster</div>
                  <span className="text-[11px] font-bold bg-green-500/10 text-green-600 px-2 py-0.5 rounded border border-green-500/20">HEALTHY</span>
                </div>
                <div className="flex justify-between items-center text-[12.5px]"><span className="text-on-surface-variant font-semibold">Connections</span><span className="font-bold text-on-surface">{metrics.db_connections || 0} / 500</span></div>
              </div>
              <div className="bg-surface-container-lowest border border-outline-variant rounded-2xl p-md flex flex-col gap-sm shadow-sm">
                <div className="flex justify-between items-center pb-sm border-b border-outline-variant/50">
                  <div className="flex items-center gap-xs text-[13px] font-bold text-on-surface"><HardDrive className="w-4 h-4 text-primary" /> Celery Workers</div>
                  <span className={`text-[11px] font-bold px-2 py-0.5 rounded border ${metrics.queue_size > 5 ? 'bg-yellow-500/10 text-yellow-600 border-yellow-500/20' : 'bg-green-500/10 text-green-600 border-green-500/20'}`}>{metrics.queue_size > 5 ? 'HEAVY LOAD' : 'NORMAL'}</span>
                </div>
                <div className="flex justify-between items-center text-[12.5px]"><span className="text-on-surface-variant font-semibold">Queue Size</span><span className="font-bold text-on-surface">{metrics.queue_size || 0} scans</span></div>
              </div>
              <button onClick={openActiveScansModal} className="w-full mt-2 bg-surface-container border border-outline-variant text-primary py-2 rounded-lg text-[13px] font-bold hover:bg-primary/10 hover:border-primary/30 cursor-pointer transition-colors flex items-center justify-center gap-xs">
                <Eye className="w-4 h-4 text-primary mr-1" /> Inspect Active Scans
              </button>
            </div>

            <div className="lg:col-span-2">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 mt-xl mb-md">
                <h2 className="font-headline-sm font-bold text-on-surface flex items-center text-[18px] m-0">
                  <span className="material-symbols-outlined text-primary mr-2 text-[20px]">receipt_long</span> Global Transaction History
                </h2>
                <div className="flex gap-2 flex-wrap items-center">
                  <div className="relative">
                    <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-on-surface-variant" />
                    <input 
                      type="text"
                      placeholder="Search org, tier..."
                      value={paymentSearch}
                      onChange={e => setPaymentSearch(e.target.value)}
                      className="bg-surface-container border border-outline-variant/60 rounded-lg pl-8 pr-7 py-1 text-[12.5px] outline-none text-on-surface w-48"
                    />
                    {paymentSearch && (
                      <button onClick={() => setPaymentSearch('')} className="absolute right-2 top-2 text-on-surface-variant hover:text-on-surface border-0 bg-transparent cursor-pointer">
                        <X className="w-3 h-3" />
                      </button>
                    )}
                  </div>
                  <select
                    value={paymentStatusFilter}
                    onChange={e => setPaymentStatusFilter(e.target.value)}
                    className="bg-surface-container border border-outline-variant/60 text-on-surface text-[12.5px] font-medium rounded-lg px-2.5 py-1 outline-none cursor-pointer"
                  >
                    <option value="all">All Statuses</option>
                    <option value="succeeded">Succeeded / Paid</option>
                    <option value="failed">Failed</option>
                    <option value="pending">Pending</option>
                  </select>
                </div>
              </div>
              <div className="bg-surface-container-lowest border border-outline-variant rounded-2xl overflow-hidden shadow-sm">
                {loading ? <div className="p-10 text-center text-on-surface-variant text-[14px]">Fetching logs...</div> : (
                  <div className="overflow-x-auto max-h-[400px] hide-scrollbar">
                    <table className="w-full text-left text-sm border-collapse">
                      <thead className="bg-surface-container text-on-surface-variant border-b border-outline-variant sticky top-0 select-none">
                        <tr>
                          {['Date', 'Organization / User', 'Tier', 'Amount', 'Status', 'Invoice'].map((h, i) => (
                            <th 
                              key={h} 
                              onClick={() => handleBillSort(h)}
                              className={`px-md py-sm font-bold text-[12px] uppercase tracking-wider ${i === 5 ? 'text-right' : ''} ${h !== 'Invoice' ? 'cursor-pointer hover:bg-surface-container-highest transition-colors group' : ''}`}
                            >
                              <div className={`flex items-center gap-xs ${i === 5 ? 'justify-end' : ''}`}>
                                {h}
                                {h !== 'Invoice' && (
                                  <span className={`material-symbols-outlined text-[16px] opacity-0 group-hover:opacity-50 transition-opacity ${sortBillCol === h ? 'opacity-100 group-hover:opacity-100 text-primary' : ''}`}>
                                    {sortBillCol === h && sortBillDir === 'desc' ? 'arrow_downward' : 'arrow_upward'}
                                  </span>
                                )}
                              </div>
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-outline-variant">
                        {recentPayments.length === 0 ? <tr><td colSpan="6" className="p-10 text-center text-on-surface-variant">No recent transactions.</td></tr> : getSortedBills().map(p => (
                          <tr key={p.id} className="hover:bg-surface-container transition-colors">
                            <td className="px-md py-sm text-[13px] text-on-surface-variant">{new Date(p.created_at).toLocaleDateString()}</td>
                            <td className="px-md py-sm"><div className="font-bold text-on-surface text-[13px]">{p.org_name}</div></td>
                            <td className="px-md py-sm"><span className="text-[12px] font-bold capitalize text-primary bg-primary/10 px-2 py-0.5 rounded border border-primary/20">{p.tier_id}</span></td>
                            <td className="px-md py-sm font-bold text-[13.5px] text-on-surface">{p.currency === 'INR' ? '₹' : '$'}{p.amount.toLocaleString(undefined, { minimumFractionDigits: 2 })}</td>
                            <td className="px-md py-sm"><div className="flex items-center gap-xs text-[12.5px] font-bold"><span className={`w-2 h-2 rounded-full ${p.status === 'successful' ? 'bg-green-500' : 'bg-error'}`}></span><span className={p.status === 'successful' ? 'text-green-600 dark:text-green-500' : 'text-error'}>{p.status === 'successful' ? 'Success' : 'Failed'}</span></div></td>
                            <td className="px-md py-sm text-right">
                              <div className="flex items-center justify-end gap-1">
                                <button onClick={() => setViewInvoice(p)} className="text-on-surface-variant hover:text-primary transition-colors bg-transparent border-0 cursor-pointer p-1" title="View Invoice">
                                  <Eye className="w-5 h-5" />
                                </button>
                                <button onClick={() => handleDownloadInvoice(p)} className="text-on-surface-variant hover:text-primary transition-colors bg-transparent border-0 cursor-pointer p-1" title="Download Invoice">
                                  <Download className="w-5 h-5" />
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>

            <div className="lg:col-span-2 mt-md">
              <div className="flex justify-between items-center mb-md">
                <h2 className="font-headline-sm font-bold text-on-surface flex items-center text-[18px]">
                  <span className="material-symbols-outlined text-primary mr-2 text-[20px]">history</span> System Audit Logs
                </h2>
                <button onClick={() => setActiveTab('audit')} className="text-primary font-bold text-[13px] hover:underline bg-transparent border-0 cursor-pointer">
                  View All
                </button>
              </div>
              <div className="bg-surface-container-lowest border border-outline-variant rounded-2xl overflow-hidden shadow-sm">
                {loading ? <div className="p-10 text-center text-on-surface-variant text-[14px]">Fetching logs...</div> : (
                  <div className="overflow-x-auto max-h-[400px] hide-scrollbar">
                    <table className="w-full text-left text-sm border-collapse">
                      <thead className="bg-surface-container text-on-surface-variant border-b border-outline-variant sticky top-0">
                        <tr>
                          <th className="px-md py-sm font-bold text-[12px] uppercase tracking-wider">Date & Time</th>
                          <th className="px-md py-sm font-bold text-[12px] uppercase tracking-wider">Admin User</th>
                          <th className="px-md py-sm font-bold text-[12px] uppercase tracking-wider">Action / Event</th>
                          <th className="px-md py-sm font-bold text-[12px] uppercase tracking-wider">Organization / Target</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-outline-variant">
                        {auditLogs.length === 0 ? <tr><td colSpan="4" className="p-10 text-center text-on-surface-variant">No audit logs found.</td></tr> : auditLogs.slice(0, 5).map(log => (
                          <tr key={log.id} className="hover:bg-surface-container transition-colors">
                            <td className="px-md py-sm text-[13px] text-on-surface-variant">{new Date(log.created_at || log.timestamp).toLocaleString()}</td>
                            <td className="px-md py-sm"><div className="font-bold text-on-surface text-[13px]">{log.user_email}</div></td>
                            <td className="px-md py-sm text-[13px] text-on-surface-variant font-medium">
                              {log.action.includes('Terminated') ? <span className="text-error font-bold">{log.action}</span> : log.action}
                            </td>
                            <td className="px-md py-sm font-bold text-[13px] text-on-surface">{log.target_name || log.target_id || '-'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          </div>
        </>
      )}

      {activeTab === 'organizations' && (
        <div className="flex flex-col gap-md mb-xl animate-fade-in">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-md mb-md">
            <h2 className="font-headline-sm font-bold text-on-surface flex items-center text-[18px] m-0">
              <Shield className="w-5 h-5 text-primary mr-2" /> Client Organizations Directory
            </h2>

            <div className="flex items-center gap-2 flex-wrap">
              <div className="relative">
                <Search className="w-4 h-4 absolute left-3 top-2 text-on-surface-variant" />
                <input 
                  type="text"
                  placeholder="Search tenant name..."
                  value={orgSearch}
                  onChange={e => { setOrgSearch(e.target.value); setOrgPage(1); }}
                  className="bg-surface border border-outline-variant/60 text-on-surface text-[13px] font-medium rounded-lg pl-9 pr-8 py-1.5 outline-none focus:border-primary w-48"
                />
                {orgSearch && (
                  <button onClick={() => { setOrgSearch(''); setOrgPage(1); }} className="absolute right-2.5 top-2 text-on-surface-variant hover:text-on-surface border-0 bg-transparent cursor-pointer">
                    <X className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>

              <select
                value={orgTierFilter}
                onChange={e => { setOrgTierFilter(e.target.value); setOrgPage(1); }}
                className="bg-surface border border-outline-variant/60 text-on-surface text-[13px] font-medium rounded-lg px-3 py-1.5 outline-none focus:border-primary cursor-pointer"
              >
                <option value="all">All Tiers</option>
                <option value="quick">Quick</option>
                <option value="advanced">Advanced</option>
                <option value="deep">Deep</option>
                <option value="enterprise">Enterprise</option>
                <option value="free">Free</option>
              </select>

              <select
                value={orgStatusFilter}
                onChange={e => { setOrgStatusFilter(e.target.value); setOrgPage(1); }}
                className="bg-surface border border-outline-variant/60 text-on-surface text-[13px] font-medium rounded-lg px-3 py-1.5 outline-none focus:border-primary cursor-pointer"
              >
                <option value="all">All Statuses</option>
                <option value="active">Active</option>
                <option value="inactive">Inactive</option>
              </select>

              {(orgSearch || orgTierFilter !== 'all' || orgStatusFilter !== 'all') && (
                <button
                  onClick={() => { setOrgSearch(''); setOrgTierFilter('all'); setOrgStatusFilter('all'); setOrgPage(1); }}
                  className="text-error hover:underline text-[12.5px] font-bold flex items-center gap-1 cursor-pointer bg-transparent border-0 px-1"
                >
                  <X className="w-4 h-4" />
                  Reset
                </button>
              )}
            </div>
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
                          {(h !== 'Actions' && h !== 'Quotas') && (
                            <span className={`material-symbols-outlined text-[16px] opacity-0 group-hover:opacity-50 transition-opacity ${sortOrgCol === h ? 'opacity-100 group-hover:opacity-100 text-primary' : ''}`}>
                              {sortOrgCol === h && sortOrgDir === 'desc' ? 'arrow_downward' : 'arrow_upward'}
                            </span>
                          )}
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
                        <div className="flex flex-wrap gap-1.5 items-center">
                          {org.quotas?.map((q, idx) => {
                            const remaining = q.allocated_count === -1 ? '∞' : Math.max(0, q.allocated_count - (q.used_count || 0));
                            const style = q.scan_type === 'Deep' ? 'bg-orange-500/10 text-orange-600 border-orange-500/30' :
                              q.scan_type === 'Advanced' ? 'bg-purple-500/10 text-purple-600 border-purple-500/30' :
                              q.scan_type === 'Quick' ? 'bg-blue-500/10 text-blue-600 border-blue-500/30' :
                              'bg-emerald-500/10 text-emerald-600 border-emerald-500/30';
                            return (
                              <div key={idx} className={`text-[10.5px] font-bold px-2 py-0.5 rounded border flex items-center gap-1 shadow-sm ${style}`}>
                                <span className="uppercase opacity-90 tracking-wider">{q.scan_type}:</span>
                                <span className="text-[12px]">{remaining}</span>
                              </div>
                            );
                          })}
                        </div>
                      </td>
                      <td className="px-md py-sm text-right whitespace-nowrap">
                        <div className="inline-flex items-center justify-end gap-1 whitespace-nowrap">
                          <button onClick={() => handleImpersonate(org.id, org.name)} className="text-on-surface-variant hover:text-primary transition-colors bg-transparent border-0 cursor-pointer p-1" title="View Customer Environment / Assist Troubleshooting">
                            <span className="material-symbols-outlined text-[18px]">vpn_key</span>
                          </button>
                          {!isSupportEngineer && (
                            <>
                              <button onClick={() => handleAssignScans(org)} className="text-on-surface-variant hover:text-primary transition-colors bg-transparent border-0 cursor-pointer p-1" title="Assign Custom Scans">
                                <span className="material-symbols-outlined text-[18px]">add_box</span>
                              </button>
                              <button onClick={() => handleEditTenant(org)} className="text-on-surface-variant hover:text-primary transition-colors bg-transparent border-0 cursor-pointer p-1" title="Edit Tenant">
                                <span className="material-symbols-outlined text-[18px]">edit</span>
                              </button>
                              <button onClick={() => handleSuspend(org.id, org.status)} className="text-on-surface-variant hover:text-error transition-colors bg-transparent border-0 cursor-pointer p-1" title="Suspend Tenant">
                                <span className="material-symbols-outlined text-[18px]">{org.status === 'suspended' ? 'play_arrow' : 'pause_circle'}</span>
                              </button>
                              <button onClick={() => handleDeleteTenant(org.id, org.name)} className="text-on-surface-variant hover:text-error transition-colors bg-transparent border-0 cursor-pointer p-1" title="Delete Tenant">
                                <span className="material-symbols-outlined text-[18px]">delete</span>
                              </button>
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <TablePagination
              currentPage={orgPage}
              totalEntries={getSortedOrgs().length}
              pageSize={orgPageSize}
              onPageChange={setOrgPage}
              onPageSizeChange={setOrgPageSize}
            />
          </div>
        </div>
      )}

      {activeTab === 'members' && (
        <div className="flex flex-col gap-md mb-xl animate-fade-in">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-md mb-xs">
            <div>
              <h2 className="font-headline-sm font-bold text-on-surface flex items-center text-[18px]">
                <Users className="w-5 h-5 text-primary mr-2" /> Global Members
              </h2>
              <p className="text-[13px] text-on-surface-variant mt-0.5">
                Centralized user management, role assignments, and client org mapping.
              </p>
            </div>
            {!isSupportEngineer && (
              <button onClick={handleAddMember} className="flex items-center px-4 py-2 bg-primary text-white rounded-lg hover:brightness-110 transition-all font-bold text-[13.5px] border-0 cursor-pointer shadow-md shadow-primary/20 shrink-0">
                <Plus className="w-4 h-4 mr-2" /> Add Member
              </button>
            )}
          </div>

          {/* Filter & Search Bar */}
          <div className="bg-surface-container-lowest border border-outline-variant/70 rounded-2xl p-4 flex flex-col md:flex-row items-center justify-between gap-3 shadow-2xs">
            <div className="flex flex-wrap items-center gap-3 w-full flex-1">
              {/* Search Input */}
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
                  className="w-full pl-9 pr-8 py-2 bg-surface border border-outline-variant/60 rounded-lg text-[13px] text-on-surface focus:outline-none focus:border-primary"
                />
                {userSearch && (
                  <button
                    onClick={() => { setUserSearch(''); setUserPage(1); }}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-on-surface-variant hover:text-on-surface bg-transparent border-0 cursor-pointer p-0.5"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>

              {/* Filter by Role */}
              <div className="flex items-center gap-1.5 w-full sm:w-auto">
                <span className="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider shrink-0">Role:</span>
                <select
                  value={userRoleFilter}
                  onChange={(e) => {
                    setUserRoleFilter(e.target.value);
                    setUserPage(1);
                  }}
                  className="bg-surface border border-outline-variant/60 text-on-surface text-[13px] font-medium rounded-lg px-3 py-2 focus:outline-none focus:border-primary cursor-pointer w-full sm:w-auto"
                >
                  <option value="all">All Roles</option>
                  <option value="admin">Admin</option>
                  <option value="soc_analyst">SOC Analyst</option>
                  <option value="org_admin">Organization Admin</option>
                  <option value="executive_user">Executive User</option>
                  {user?.role !== 'admin' && <option value="super_admin">Super Admin</option>}
                  <option value="support_engineer">Support Engineer</option>
                  <option value="read_only">Read Only</option>
                </select>
              </div>

              {/* Filter by Organization */}
              <div className="flex items-center gap-1.5 w-full sm:w-auto">
                <span className="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider shrink-0">Organization:</span>
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

              {/* Reset Button */}
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
                          {h !== 'Actions' && (
                            <span className={`material-symbols-outlined text-[16px] opacity-0 group-hover:opacity-50 transition-opacity ${sortUserCol === h ? 'opacity-100 group-hover:opacity-100 text-primary' : ''}`}>
                              {sortUserCol === h && sortUserDir === 'desc' ? 'arrow_downward' : 'arrow_upward'}
                            </span>
                          )}
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
                          title={isSupportEngineer ? "Edit Member Role & Organization" : "Edit Member Details & Password"}
                        >
                          <Edit className="w-4 h-4" />
                        </button>
                        {!isSupportEngineer && (
                          <button onClick={() => {
                            setConfirmModal({
                              isOpen: true,
                              title: 'Delete Member',
                              desc: `Are you sure you want to delete ${u.email}?`,
                              type: 'error',
                              onConfirm: async () => {
                                try {
                                  const res = await authFetch(`/api/auth/users/${u.id}`, {
                                    method: 'DELETE'
                                  });
                                  if (res.ok) {
                                    toast.success('Member deleted successfully');
                                    fetchStats();
                                  } else {
                                    toast.error('Failed to delete member');
                                  }
                                } catch (err) {
                                  toast.error('Network error deleting member');
                                }
                                closeConfirm();
                              }
                            });
                          }} className="text-on-surface-variant hover:text-error transition-colors bg-transparent border-0 cursor-pointer p-1" title="Delete Member"><Trash2 className="w-4 h-4" /></button>
                        )}
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

      {activeTab === 'audit' && (
        <div className="flex flex-col gap-md mb-xl animate-fade-in">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-md mb-md">
            <h2 className="font-headline-sm font-bold text-on-surface flex items-center text-[18px] m-0">
              <span className="material-symbols-outlined text-primary mr-2">history</span> Full System Audit Logs
            </h2>
            <div className="relative w-full md:w-72">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-on-surface-variant" />
              <input 
                type="text"
                placeholder="Search event, admin email, or target..."
                value={auditSearch}
                onChange={e => { setAuditSearch(e.target.value); setAuditPage(1); }}
                className="w-full bg-surface border border-outline-variant/60 text-on-surface text-[13px] font-medium rounded-lg pl-9 pr-8 py-1.5 outline-none focus:border-primary"
              />
              {auditSearch && (
                <button onClick={() => { setAuditSearch(''); setAuditPage(1); }} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-on-surface-variant hover:text-on-surface border-0 bg-transparent cursor-pointer p-0.5">
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>

          <div className="bg-surface-container-lowest border border-outline-variant rounded-2xl overflow-hidden shadow-sm">
            {loading ? <div className="p-10 text-center text-on-surface-variant">Fetching logs...</div> : (
              <>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm border-collapse">
                    <thead className="bg-surface-container text-on-surface-variant border-b border-outline-variant">
                      <tr>
                        <th className="px-md py-sm font-bold text-[12px] uppercase tracking-wider">Date & Time</th>
                        <th className="px-md py-sm font-bold text-[12px] uppercase tracking-wider">Admin User</th>
                        <th className="px-md py-sm font-bold text-[12px] uppercase tracking-wider">Action / Event</th>
                        <th className="px-md py-sm font-bold text-[12px] uppercase tracking-wider">Organization / Target</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-outline-variant">
                      {getFilteredAuditLogs().length === 0 ? (
                        <tr><td colSpan="4" className="p-10 text-center text-on-surface-variant font-bold">No audit logs match your search.</td></tr>
                      ) : (
                        getFilteredAuditLogs().slice((auditPage - 1) * auditPageSize, auditPage * auditPageSize).map((log) => (
                          <tr key={log.id} className="hover:bg-surface-container transition-colors">
                            <td className="px-md py-sm text-[13px] text-on-surface-variant">{new Date(log.created_at || log.timestamp).toLocaleString()}</td>
                            <td className="px-md py-sm"><div className="font-bold text-on-surface text-[13px]">{log.user_email}</div></td>
                            <td className="px-md py-sm text-[13px] text-on-surface-variant font-medium">
                              {log.action.includes('Terminated') ? <span className="text-error font-bold">{log.action}</span> : log.action}
                            </td>
                            <td className="px-md py-sm font-bold text-[13px] text-on-surface">{log.target_name || log.target_id || '-'}</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
                <TablePagination
                  currentPage={auditPage}
                  totalEntries={getFilteredAuditLogs().length}
                  pageSize={auditPageSize}
                  onPageChange={setAuditPage}
                  onPageSizeChange={setAuditPageSize}
                />
              </>
            )}
          </div>
        </div>
      )}

      {activeTab === 'bookings' && (
        <div className="flex flex-col gap-md mb-xl animate-fade-in">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-md mb-xs">
            <h2 className="font-headline-sm font-bold text-on-surface flex items-center text-[18px]"><span className="material-symbols-outlined text-primary mr-2">event</span> Demo Bookings & Leads</h2>
            <div className="text-[12.5px] font-bold text-on-surface-variant">
              Total Leads: <span className="text-primary font-extrabold">{getFilteredBookings().length}</span>
            </div>
          </div>

          <div className="bg-surface border border-outline-variant rounded-2xl overflow-hidden shadow-sm">
            {/* Filter Controls Bar */}
            <div className="p-md bg-surface-container-high/40 border-b border-outline-variant/60 flex flex-col md:flex-row justify-between items-start md:items-center gap-md">
              <div className="flex items-center gap-sm flex-wrap w-full md:w-auto">
                <div className="relative flex-1 md:w-64">
                  <Search className="w-4 h-4 absolute left-3 top-2.5 text-on-surface-variant" />
                  <input 
                    type="text"
                    placeholder="Search email, company size, date..."
                    value={bookingSearch}
                    onChange={(e) => { setBookingSearch(e.target.value); setBookingPage(1); }}
                    className="w-full bg-surface border border-outline-variant/60 rounded-lg pl-9 pr-8 py-1.5 text-[13px] outline-none focus:border-primary text-on-surface font-medium"
                  />
                  {bookingSearch && (
                    <button
                      onClick={() => { setBookingSearch(''); setBookingPage(1); }}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-on-surface-variant hover:text-on-surface bg-transparent border-0 cursor-pointer p-0.5"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>

                <div className="flex items-center gap-1.5">
                  <span className="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider shrink-0">Status:</span>
                  <select
                    value={bookingStatusFilter}
                    onChange={(e) => { setBookingStatusFilter(e.target.value); setBookingPage(1); }}
                    className="bg-surface border border-outline-variant/60 text-on-surface text-[13px] font-medium rounded-lg px-3 py-1.5 focus:outline-none focus:border-primary cursor-pointer"
                  >
                    <option value="all">All Statuses</option>
                    <option value="pending">Pending</option>
                    <option value="completed">Completed</option>
                    <option value="rescheduled">Rescheduled</option>
                    <option value="cancelled">Cancelled</option>
                  </select>
                </div>

                {(bookingSearch || bookingStatusFilter !== 'all') && (
                  <button
                    onClick={() => { setBookingSearch(''); setBookingStatusFilter('all'); setBookingPage(1); }}
                    className="text-error hover:underline text-[12.5px] font-bold flex items-center gap-1 cursor-pointer bg-transparent border-0 px-1 ml-auto md:ml-0"
                  >
                    <X className="w-4 h-4" />
                    Reset Filters
                  </button>
                )}
              </div>
            </div>

            {getFilteredBookings().length === 0 ? (
              <div className="p-xl text-center text-on-surface-variant font-bold">No demo bookings match your filter criteria.</div>
            ) : (
              <>
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse">
                    <thead className="bg-surface-container-lowest border-b border-outline-variant">
                      <tr>
                        <th className="px-md py-sm font-bold text-[12px] uppercase tracking-wider">Email</th>
                        <th className="px-md py-sm font-bold text-[12px] uppercase tracking-wider">Size</th>
                        <th className="px-md py-sm font-bold text-[12px] uppercase tracking-wider">Date & Time</th>
                        <th className="px-md py-sm font-bold text-[12px] uppercase tracking-wider">Status</th>
                        <th className="px-md py-sm font-bold text-[12px] uppercase tracking-wider">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-outline-variant">
                      {getFilteredBookings().slice((bookingPage - 1) * bookingPageSize, bookingPage * bookingPageSize).map(b => {
                        const statusStyle =
                          b.status === 'completed'
                            ? 'bg-green-500/10 text-green-600 border-green-500/30'
                            : b.status === 'cancelled'
                            ? 'bg-red-500/10 text-red-600 border-red-500/30'
                            : b.status === 'rescheduled'
                            ? 'bg-blue-500/10 text-blue-600 border-blue-500/30'
                            : 'bg-orange-500/10 text-orange-600 border-orange-500/30';

                        const statusLabel =
                          b.status === 'completed' ? 'Completed / Conducted' :
                          b.status === 'cancelled' ? 'Cancelled / Not Conducted' :
                          b.status === 'rescheduled' ? 'Rescheduled' : 'Pending';

                        return (
                          <tr key={b.id} className="hover:bg-surface-container-lowest transition-colors">
                            <td className="px-md py-sm font-bold text-on-surface text-[13px]">{b.email}</td>
                            <td className="px-md py-sm text-on-surface-variant text-[13px]">{b.company_size?.replace('Company Size: ', '')}</td>
                            <td className="px-md py-sm text-on-surface-variant text-[13px]">
                              {b.meeting_date} <br/>
                              <span className="text-[11px] font-bold text-primary">{b.meeting_time}</span>
                            </td>
                            <td className="px-md py-sm">
                              <span className={`px-2.5 py-1 rounded-full text-[11px] font-bold uppercase tracking-wider border ${statusStyle}`}>
                                {statusLabel}
                              </span>
                            </td>
                            <td className="px-md py-sm">
                              <div className="flex items-center gap-1.5 flex-wrap">
                                {b.status !== 'completed' && (
                                  <button
                                    onClick={() => handleUpdateBookingStatus(b.id, 'completed')}
                                    className="bg-green-600 text-white border-0 py-1 px-2.5 rounded font-bold cursor-pointer text-[11px] hover:bg-green-700 transition-all flex items-center gap-1 shadow-xs"
                                    title="Mark Demo as Completed"
                                  >
                                    <span className="material-symbols-outlined text-[14px]">check_circle</span>
                                    Complete
                                  </button>
                                )}
                                {b.status !== 'cancelled' && (
                                  <button
                                    onClick={() => handleCancelBooking(b)}
                                    className="bg-red-500/10 text-red-600 hover:bg-red-600 hover:text-white border border-red-500/30 py-1 px-2.5 rounded font-bold cursor-pointer text-[11px] transition-all flex items-center gap-1"
                                    title="Mark as Cancelled or Couldn't Show Demo"
                                  >
                                    <span className="material-symbols-outlined text-[14px]">cancel</span>
                                    Cancelled
                                  </button>
                                )}
                                <button
                                  onClick={() => handleOpenReschedule(b)}
                                  className="bg-blue-500/10 text-blue-600 hover:bg-blue-600 hover:text-white border border-blue-500/30 py-1 px-2.5 rounded font-bold cursor-pointer text-[11px] transition-all flex items-center gap-1"
                                  title="Reschedule Date & Time"
                                >
                                  <span className="material-symbols-outlined text-[14px]">edit_calendar</span>
                                  Reschedule
                                </button>
                                <button
                                  onClick={() => handleDeleteBooking(b)}
                                  className="text-on-surface-variant hover:text-red-600 border-0 bg-transparent p-1 cursor-pointer transition-colors"
                                  title="Delete Lead"
                                >
                                  <span className="material-symbols-outlined text-[16px]">delete</span>
                                </button>
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                <TablePagination
                  currentPage={bookingPage}
                  totalEntries={getFilteredBookings().length}
                  pageSize={bookingPageSize}
                  onPageChange={setBookingPage}
                  onPageSizeChange={setBookingPageSize}
                />
              </>
            )}
          </div>
        </div>
      )}

      {activeTab === 'emails' && (
        <div className="flex flex-col gap-md mb-xl animate-fade-in">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-md mb-md">
            <h2 className="font-headline-sm font-bold text-on-surface flex items-center text-[18px] m-0">
              <span className="material-symbols-outlined text-primary mr-2">mail</span> Outbound Email Logs
            </h2>
            <div className="flex items-center gap-2 flex-wrap">
              <div className="relative">
                <Search className="w-4 h-4 absolute left-3 top-2.5 text-on-surface-variant" />
                <input 
                  type="text"
                  placeholder="Search recipient or subject..."
                  value={emailSearch}
                  onChange={e => { setEmailSearch(e.target.value); setEmailPage(1); }}
                  className="bg-surface border border-outline-variant/60 text-on-surface text-[13px] font-medium rounded-lg pl-9 pr-8 py-1.5 outline-none focus:border-primary w-56"
                />
                {emailSearch && (
                  <button onClick={() => { setEmailSearch(''); setEmailPage(1); }} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-on-surface-variant hover:text-on-surface border-0 bg-transparent cursor-pointer p-0.5">
                    <X className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
              <select
                value={emailStatusFilter}
                onChange={e => { setEmailStatusFilter(e.target.value); setEmailPage(1); }}
                className="bg-surface border border-outline-variant/60 text-on-surface text-[13px] font-medium rounded-lg px-3 py-1.5 outline-none focus:border-primary cursor-pointer"
              >
                <option value="all">All Statuses</option>
                <option value="sent">Sent</option>
                <option value="failed">Failed</option>
              </select>
              {(emailSearch || emailStatusFilter !== 'all') && (
                <button
                  onClick={() => { setEmailSearch(''); setEmailStatusFilter('all'); setEmailPage(1); }}
                  className="text-error hover:underline text-[12.5px] font-bold flex items-center gap-1 cursor-pointer bg-transparent border-0 px-1"
                >
                  <X className="w-4 h-4" />
                  Reset
                </button>
              )}
            </div>
          </div>

          <div className="bg-surface border border-outline-variant rounded-2xl overflow-hidden shadow-sm">
            {getFilteredEmails().length === 0 ? (
              <div className="p-xl text-center text-on-surface-variant font-bold">No emails match your filter criteria.</div>
            ) : (
              <>
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse">
                    <thead className="bg-surface-container-lowest border-b border-outline-variant">
                      <tr>
                        <th className="px-md py-sm font-bold text-[12px] uppercase tracking-wider">Timestamp</th>
                        <th className="px-md py-sm font-bold text-[12px] uppercase tracking-wider">Recipient</th>
                        <th className="px-md py-sm font-bold text-[12px] uppercase tracking-wider">Subject</th>
                        <th className="px-md py-sm font-bold text-[12px] uppercase tracking-wider">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-outline-variant">
                      {getFilteredEmails().slice((emailPage - 1) * emailPageSize, emailPage * emailPageSize).map(log => (
                        <tr key={log.id} className="hover:bg-surface-container-lowest transition-colors">
                          <td className="px-md py-sm text-on-surface-variant text-[13px]">{new Date(log.sent_at).toLocaleString()}</td>
                          <td className="px-md py-sm font-bold text-on-surface text-[13px]">{log.recipient}</td>
                          <td className="px-md py-sm text-on-surface-variant text-[13px]">{log.subject}</td>
                          <td className="px-md py-sm">
                            <span className={`px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wider ${log.status === 'sent' ? 'bg-green-500/10 text-green-600' : 'bg-red-500/10 text-red-600'}`}>
                              {log.status}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <TablePagination
                  currentPage={emailPage}
                  totalEntries={getFilteredEmails().length}
                  pageSize={emailPageSize}
                  onPageChange={setEmailPage}
                  onPageSizeChange={setEmailPageSize}
                />
              </>
            )}
          </div>
        </div>
      )}

      {/* Pricing Modal using CustomModal */}
      <CustomModal
        isOpen={pricingModalOpen}
        onClose={() => setPricingModalOpen(false)}
        title="Dynamic Billing Control"
        description="Manage subscription tiers and pricing across the platform."
        maxWidth="max-w-4xl"
      >
        {fetchingTiers ? (
          <div className="flex flex-col items-center justify-center py-2xl text-on-surface-variant font-label-md">
            <span className="material-symbols-outlined animate-spin text-[32px] mb-xs text-primary">sync</span>
            Loading Billing Data...
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-md">
            {tiers.map(tier => (
              <BillingTierCard key={tier.id} tier={tier} onSave={handleUpdateTier} />
            ))}
          </div>
        )}
      </CustomModal>

      {/* Active Scans Modal */}
      <CustomModal isOpen={activeScansModalOpen} onClose={() => setActiveScansModalOpen(false)} title="Active Scans">
        {fetchingActiveScans ? <div className="text-center py-xl">Loading...</div> : activeScans.length === 0 ? <div className="text-center py-xl">No active scans.</div> : (
          <div className="flex flex-col gap-md">
            {activeScans.map(scan => (
              <div key={scan.id} className="bg-surface border border-outline-variant rounded-xl p-md flex flex-col sm:flex-row justify-between items-center gap-md">
                <div><div className="font-bold">{scan.target_url}</div><div className="text-xs">Org ID: {scan.org_id}</div></div>
                <button onClick={() => handleKillScan(scan.id)} className="bg-error/10 text-error border border-error/20 py-1.5 px-3 rounded font-bold cursor-pointer border-0">Terminate</button>
              </div>
            ))}
          </div>
        )}
      </CustomModal>

      {/* Prompt Modal */}
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
              ) : input.type === 'password' ? (
                <div>
                  <div className="relative">
                    <input
                      type={showPasswordPrompt[input.key] ? "text" : "password"}
                      value={promptValues[input.key] || ''}
                      onChange={(e) => handlePromptChange(input.key, e.target.value)}
                      placeholder={input.placeholder}
                      disabled={input.disabled}
                      className="w-full bg-surface-container border border-outline-variant rounded-lg pl-3 pr-10 py-2 focus:border-primary outline-none text-on-surface text-sm"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPasswordPrompt(prev => ({ ...prev, [input.key]: !prev[input.key] }))}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-on-surface-variant hover:text-primary bg-transparent border-0 cursor-pointer p-1 flex items-center justify-center"
                      title={showPasswordPrompt[input.key] ? "Hide password" : "Show password"}
                    >
                      <span className="material-symbols-outlined text-[18px]">
                        {showPasswordPrompt[input.key] ? 'visibility_off' : 'visibility'}
                      </span>
                    </button>
                  </div>
                  {input.showRules && (promptValues[input.key] || '').length > 0 && (
                    <div className="flex flex-col gap-1.5 p-3 bg-surface-container-high/60 border border-outline-variant/60 rounded-xl text-xs mt-2 animate-fade-in">
                      <div className={`flex items-center gap-2 font-medium transition-colors ${(promptValues[input.key] || '').length >= 8 ? 'text-green-600 dark:text-green-500 font-bold' : 'text-on-surface-variant'}`}>
                        <span className="material-symbols-outlined text-[16px]">
                          {(promptValues[input.key] || '').length >= 8 ? 'check_circle' : 'radio_button_unchecked'}
                        </span>
                        <span>At least 8 characters</span>
                      </div>
                      <div className={`flex items-center gap-2 font-medium transition-colors ${/[A-Z]/.test(promptValues[input.key] || '') ? 'text-green-600 dark:text-green-500 font-bold' : 'text-on-surface-variant'}`}>
                        <span className="material-symbols-outlined text-[16px]">
                          {/[A-Z]/.test(promptValues[input.key] || '') ? 'check_circle' : 'radio_button_unchecked'}
                        </span>
                        <span>One uppercase letter</span>
                      </div>
                      <div className={`flex items-center gap-2 font-medium transition-colors ${/[a-z]/.test(promptValues[input.key] || '') ? 'text-green-600 dark:text-green-500 font-bold' : 'text-on-surface-variant'}`}>
                        <span className="material-symbols-outlined text-[16px]">
                          {/[a-z]/.test(promptValues[input.key] || '') ? 'check_circle' : 'radio_button_unchecked'}
                        </span>
                        <span>One lowercase letter</span>
                      </div>
                      <div className={`flex items-center gap-2 font-medium transition-colors ${/[^A-Za-z0-9]/.test(promptValues[input.key] || '') ? 'text-green-600 dark:text-green-500 font-bold' : 'text-on-surface-variant'}`}>
                        <span className="material-symbols-outlined text-[16px]">
                          {/[^A-Za-z0-9]/.test(promptValues[input.key] || '') ? 'check_circle' : 'radio_button_unchecked'}
                        </span>
                        <span>One special character</span>
                      </div>
                    </div>
                  )}
                </div>
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
            <button onClick={confirmModal.onConfirm} className={`px-4 py-2 text-white rounded-lg font-bold border-0 cursor-pointer ${confirmModal.type === 'error' ? 'bg-error' : 'bg-primary'}`}>Confirm</button>
          </>
        }
      />

      {/* Invoice View Modal */}
      <CustomModal
        isOpen={!!viewInvoice}
        onClose={() => setViewInvoice(null)}
        title="Invoice Details"
        footer={
          <>
            <button onClick={() => setViewInvoice(null)} className="px-4 py-2 text-on-surface-variant hover:bg-surface-container rounded-lg font-bold border-0 bg-transparent cursor-pointer">Close</button>
            <button onClick={() => { handleDownloadInvoice(viewInvoice); setViewInvoice(null); }} className="px-4 py-2 bg-primary text-white flex items-center gap-2 rounded-lg font-bold border-0 cursor-pointer">
              <Download className="w-4 h-4" /> Download PDF
            </button>
          </>
        }
      >
        {viewInvoice && (
          <div className="flex flex-col gap-4 text-on-surface">
            <div className="flex justify-between items-end border-b border-outline-variant pb-4 mb-2">
              <div>
                <h1 className="text-2xl font-bold text-primary m-0">LarShield</h1>
                <p className="text-on-surface-variant m-0 text-sm mt-1">Payment Receipt & Invoice</p>
              </div>
              <div className="text-right">
                <div className="text-sm font-bold opacity-80 uppercase tracking-wider">Date</div>
                <div>{new Date(viewInvoice.created_at).toLocaleString()}</div>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4 bg-surface-container-low p-4 rounded-lg">
              <div>
                <div className="text-xs text-on-surface-variant font-bold uppercase mb-1">Billed To</div>
                <div className="font-bold">{viewInvoice.org_name}</div>
                <div className="text-sm opacity-80">{viewInvoice.user_email}</div>
              </div>
              <div className="text-right">
                <div className="text-xs text-on-surface-variant font-bold uppercase mb-1">Status</div>
                <div className={`font-bold uppercase ${viewInvoice.status === 'successful' ? 'text-green-600' : 'text-error'}`}>{viewInvoice.status}</div>
              </div>
            </div>

            <table className="w-full text-left mt-4">
              <thead>
                <tr className="border-b border-outline-variant">
                  <th className="py-2 text-sm font-bold text-on-surface-variant uppercase">Description</th>
                  <th className="py-2 text-sm font-bold text-on-surface-variant uppercase text-right">Amount</th>
                </tr>
              </thead>
              <tbody>
                <tr className="border-b border-outline-variant/30">
                  <td className="py-3">
                    <span className="capitalize font-bold">{viewInvoice.tier_id}</span> Subscription Plan
                  </td>
                  <td className="py-3 text-right">
                    {viewInvoice.currency === 'INR' ? '₹' : '$'}{viewInvoice.amount.toLocaleString(undefined, { minimumFractionDigits: 2 })}
                  </td>
                </tr>
              </tbody>
            </table>

            <div className="flex justify-between items-center border-t border-outline-variant pt-4 mt-2">
              <div className="text-sm text-on-surface-variant font-bold uppercase">Total Amount</div>
              <div className="text-xl font-bold">
                {viewInvoice.currency === 'INR' ? '₹' : '$'}{viewInvoice.amount.toLocaleString(undefined, { minimumFractionDigits: 2 })}
              </div>
            </div>
          </div>
        )}
      </CustomModal>

      {/* Reschedule Demo Call Modal using CustomModal */}
      <CustomModal
        isOpen={rescheduleModal.isOpen}
        onClose={() => setRescheduleModal({ ...rescheduleModal, isOpen: false })}
        title="Reschedule Demo Call"
        description="Select a new meeting date, time slot, and update booking status."
        maxWidth="max-w-lg"
      >
        <form onSubmit={handleSaveReschedule} className="flex flex-col gap-4 text-left">
          <div>
            <label className="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider block mb-1">Lead Email</label>
            <input
              type="text"
              disabled
              value={rescheduleModal.email}
              className="w-full bg-surface-container border border-outline-variant/60 rounded-lg p-2.5 text-xs text-on-surface-variant font-bold cursor-not-allowed"
            />
          </div>

          <div>
            <div className="flex justify-between items-center mb-1">
              <label className="text-xs font-bold text-on-surface block">New Meeting Date</label>
              {rescheduleModal.meetingDate && (
                <span className="text-[11px] font-bold text-primary bg-primary/10 px-2 py-0.5 rounded border border-primary/20 flex items-center gap-1">
                  <span className="material-symbols-outlined text-[13px]">calendar_today</span>
                  {rescheduleModal.meetingDate}
                </span>
              )}
            </div>
            <input
              type="date"
              required
              value={rescheduleModal.isoDate}
              onChange={(e) => {
                const newIso = e.target.value;
                setRescheduleModal(prev => ({
                  ...prev,
                  isoDate: newIso,
                  meetingDate: formatToReadableDate(newIso)
                }));
              }}
              className="w-full border border-outline-variant rounded-lg p-2.5 text-xs text-on-surface bg-surface-container-lowest focus:border-primary outline-none cursor-pointer"
            />
          </div>

          <div>
            <div className="flex justify-between items-center mb-1">
              <label className="text-xs font-bold text-on-surface block">New Meeting Time</label>
              {rescheduleModal.meetingTime && (
                <span className="text-[11px] font-bold text-primary bg-primary/10 px-2 py-0.5 rounded border border-primary/20 flex items-center gap-1">
                  <span className="material-symbols-outlined text-[13px]">schedule</span>
                  {rescheduleModal.meetingTime}
                </span>
              )}
            </div>

            {/* Time Picker */}
            <input
              type="time"
              required
              value={rescheduleModal.isoTime}
              onChange={(e) => {
                const newIso = e.target.value;
                setRescheduleModal(prev => ({
                  ...prev,
                  isoTime: newIso,
                  meetingTime: formatTo12HrTime(newIso)
                }));
              }}
              className="w-full border border-outline-variant rounded-lg p-2.5 text-xs text-on-surface bg-surface-container-lowest focus:border-primary outline-none cursor-pointer mb-2"
            />

            {/* Quick Time Slots */}
            <div className="flex flex-col gap-1">
              <span className="text-[10px] font-bold text-on-surface-variant uppercase tracking-wider">Quick Select Time Slot:</span>
              <div className="grid grid-cols-4 gap-1.5">
                {['09:00 AM', '10:00 AM', '11:00 AM', '02:00 PM', '04:00 PM', '05:00 PM', '06:00 PM', '09:30 PM'].map((slot) => {
                  const isSelected = rescheduleModal.meetingTime === slot;
                  return (
                    <button
                      key={slot}
                      type="button"
                      onClick={() => {
                        setRescheduleModal(prev => ({
                          ...prev,
                          meetingTime: slot,
                          isoTime: parseToISOTime(slot)
                        }));
                      }}
                      className={`py-1.5 px-1 text-center text-[10.5px] font-bold border rounded-lg transition-all cursor-pointer ${
                        isSelected
                          ? 'bg-primary text-white border-primary shadow-xs'
                          : 'bg-surface-container-low border-outline-variant/60 text-on-surface-variant hover:bg-surface-container-high'
                      }`}
                    >
                      {slot}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          <div>
            <label className="text-xs font-bold text-on-surface block mb-1">Update Booking Status</label>
            <select
              value={rescheduleModal.status}
              onChange={(e) => setRescheduleModal({ ...rescheduleModal, status: e.target.value })}
              className="w-full border border-outline-variant rounded-lg p-2.5 text-xs text-on-surface bg-surface-container-lowest focus:border-primary outline-none cursor-pointer"
            >
              <option value="rescheduled">Rescheduled</option>
              <option value="pending">Pending</option>
              <option value="completed">Completed / Conducted</option>
              <option value="cancelled">Cancelled / Not Conducted</option>
            </select>
          </div>

          <div className="flex justify-end gap-2 pt-3 border-t border-outline-variant">
            <button
              type="button"
              onClick={() => setRescheduleModal({ ...rescheduleModal, isOpen: false })}
              className="px-4 py-2 rounded-lg text-xs font-bold text-on-surface-variant hover:bg-surface-container cursor-pointer bg-transparent border border-outline-variant"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-2 rounded-lg text-xs font-bold text-white bg-primary hover:brightness-110 shadow-sm cursor-pointer border-0 flex items-center gap-1"
            >
              <span className="material-symbols-outlined text-[16px]">save</span>
              Save & Update
            </button>
          </div>
        </form>
      </CustomModal>
    </div>
  );
};

export default SuperAdminPanel;
