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
  Info,
  Building2,
  CreditCard,
  Server,
  Database,
  HardDrive,
  Eye, 
  Download, 
  Receipt,
  Trash2,
  CheckCircle,
  XCircle,
  BarChart3
} from 'lucide-react';
import { CustomModal } from '../components/CustomModal';

const parseToISODate = (str) => {
  if (!str) return '';
  const d = new Date(str);
  if (!isNaN(d.getTime())) return d.toISOString().split('T')[0];
  return '';
};

const parseToISOTime = (str) => {
  if (!str) return '';
  const match = str.match(/(\d+):(\d+)\s*(AM|PM)?/i);
  if (match) {
    let hours = parseInt(match[1], 10);
    const minutes = match[2];
    const ampm = match[3];
    if (ampm) {
      if (ampm.toUpperCase() === 'PM' && hours < 12) hours += 12;
      if (ampm.toUpperCase() === 'AM' && hours === 12) hours = 0;
    }
    return `${String(hours).padStart(2, '0')}:${minutes}`;
  }
  return '';
};

const formatToReadableDate = (isoDate) => {
  if (!isoDate) return '';
  const [y, m, d] = isoDate.split('-');
  const months = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
  return `${months[parseInt(m, 10) - 1]} ${parseInt(d, 10)}, ${y}`;
};

const formatTo12HrTime = (isoTime) => {
  if (!isoTime) return '';
  const [h, m] = isoTime.split(':');
  let hours = parseInt(h, 10);
  const ampm = hours >= 12 ? 'PM' : 'AM';
  hours = hours % 12 || 12;
  return `${String(hours).padStart(2, '0')}:${m} ${ampm}`;
};

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
  const [recentPayments, setRecentPayments] = useState([]);
  const [demoBookings, setDemoBookings] = useState([]);
  const [emailLogs, setEmailLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  const [activeTab, setActiveTab] = useState(() => {
    try {
      const params = new URLSearchParams(window.location.search);
      const tabFromUrl = params.get('tab');
      const storedTab = localStorage.getItem('supportEngineerActiveTab');
      return tabFromUrl || storedTab || 'overview';
    } catch (e) {
      return 'overview';
    }
  });

  useEffect(() => {
    try {
      localStorage.setItem('supportEngineerActiveTab', activeTab);
    } catch (e) {}
  }, [activeTab]);

  // Billing Sorting State
  const [sortBillCol, setSortBillCol] = useState('Date');
  const [sortBillDir, setSortBillDir] = useState('desc');

  // Table sorting states
  const [sortOrgCol, setSortOrgCol] = useState('Tenant Name');
  const [sortOrgDir, setSortOrgDir] = useState('asc');

  const [sortUserCol, setSortUserCol] = useState('Email');
  const [sortUserDir, setSortUserDir] = useState('asc');

  // Filter states for Global Members
  const [userSearch, setUserSearch] = useState('');
  const [userRoleFilter, setUserRoleFilter] = useState('all');
  const [userOrgFilter, setUserOrgFilter] = useState('all');

  // Filter states for Bookings
  const [bookingSearch, setBookingSearch] = useState('');
  const [bookingStatusFilter, setBookingStatusFilter] = useState('all');

  const getFilteredBookings = () => {
    return (demoBookings || []).filter(b => {
      const displayEmail = b.email || b.user_email || '';
      const emailMatch = !bookingSearch || 
        displayEmail.toLowerCase().includes(bookingSearch.toLowerCase()) || 
        (b.company_size || '').toLowerCase().includes(bookingSearch.toLowerCase()) ||
        (b.meeting_date || '').toLowerCase().includes(bookingSearch.toLowerCase());
      
      const statusMatch = bookingStatusFilter === 'all' || (b.status || 'pending') === bookingStatusFilter;
      return emailMatch && statusMatch;
    });
  };

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

  // Active Scans & Invoice Modals
  const [activeScansModalOpen, setActiveScansModalOpen] = useState(false);
  const [activeScans, setActiveScans] = useState([]);
  const [fetchingActiveScans, setFetchingActiveScans] = useState(false);
  const [viewInvoice, setViewInvoice] = useState(null);

  // Custom Prompt Modal state for editing member roles/orgs (without password)
  const [promptModal, setPromptModal] = useState({ isOpen: false, title: '', desc: '', inputs: [], onConfirm: null });
  const [promptValues, setPromptValues] = useState({});
  const [confirmModal, setConfirmModal] = useState({ isOpen: false, title: '', desc: '', onConfirm: null, type: 'primary' });

  const closePrompt = () => { setPromptModal({ isOpen: false, title: '', desc: '', inputs: [], onConfirm: null }); setPromptValues({}); };
  const closeConfirm = () => setConfirmModal({ isOpen: false, title: '', desc: '', onConfirm: null, type: 'primary' });

  const [rescheduleModal, setRescheduleModal] = useState({ isOpen: false, bookingId: null, email: '', meetingDate: '', isoDate: '', meetingTime: '', isoTime: '', status: 'rescheduled' });

  const handleUpdateBookingStatus = async (bookingId, status) => {
    try {
      const res = await authFetch(`/api/demo/bookings/${bookingId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
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
      desc: `Are you sure you want to cancel the demo call booking for ${booking.email || booking.user_email || 'this lead'}?`,
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
      email: booking.email || booking.user_email,
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
      const res = await authFetch(`/api/demo/bookings/${rescheduleModal.bookingId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
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
    const email = typeof booking === 'object' && (booking.email || booking.user_email) ? (booking.email || booking.user_email) : '';
    setConfirmModal({
      isOpen: true,
      title: 'Delete Demo Lead',
      desc: email 
        ? `Are you sure you want to permanently delete the demo lead for ${email}?`
        : 'Are you sure you want to permanently delete this demo booking lead?',
      type: 'error',
      onConfirm: async () => {
        try {
          const res = await authFetch(`/api/demo/bookings/${bookingId}`, {
            method: 'DELETE'
          });
          if (res.ok) {
            toast.success("Demo booking lead deleted successfully!");
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
        setRecentPayments(Array.isArray(data.recent_payments) ? data.recent_payments : []);
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

  const openActiveScansModal = async () => {
    setActiveScansModalOpen(true);
    setFetchingActiveScans(true);
    try {
      const res = await authFetch('/api/scans/active');
      if (res.ok) {
        const data = await res.json();
        setActiveScans(data.scans || []);
      }
    } catch (err) {
      console.error("Error fetching active scans:", err);
    }
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
          await authFetch(`/api/scans/${scanId}/terminate`, { method: 'POST' });
          toast.success('Scan terminated successfully');
          openActiveScansModal();
        } catch (err) {
          toast.error('Failed to terminate scan');
        }
        closeConfirm();
      }
    });
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

  const getSortedBills = () => {
    return [...(recentPayments || [])].sort((a, b) => {
      let aVal, bVal;
      switch (sortBillCol) {
        case 'Date': aVal = new Date(a.created_at).getTime(); bVal = new Date(b.created_at).getTime(); break;
        case 'Organization / User': aVal = a.org_name || ''; bVal = b.org_name || ''; break;
        case 'Tier': aVal = a.tier_id || ''; bVal = b.tier_id || ''; break;
        case 'Amount': aVal = a.amount || 0; bVal = b.amount || 0; break;
        case 'Status': aVal = a.status || ''; bVal = b.status || ''; break;
        default: aVal = new Date(a.created_at).getTime(); bVal = new Date(b.created_at).getTime();
      }
      if (aVal < bVal) return sortBillDir === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortBillDir === 'asc' ? 1 : -1;
      return 0;
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
      type: 'primary',
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
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-md border-b border-outline-variant/60 pb-md">
        <div>
          <h1 className="font-extrabold text-on-surface tracking-tight text-[24px] m-0 flex items-center gap-1.5">
            Support Engineer <span className="text-primary">Operations</span>
          </h1>
          <p className="font-body-md text-on-surface-variant text-[13.5px] mt-1 m-0">
            Client environment inspection, troubleshooting assistance, and system logs.
          </p>
        </div>
        
        <div className="flex flex-wrap items-center gap-2">
          <button 
            onClick={fetchStats}
            className="flex items-center gap-1.5 px-3.5 py-1.5 bg-surface-container border border-outline-variant hover:bg-surface-container-high text-on-surface rounded-lg font-bold text-[12.5px] cursor-pointer transition-all shadow-2xs"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-primary ${loading ? 'animate-spin' : ''}`} />
            Sync Metrics
          </button>
          <button 
            onClick={() => navigate('/organization')}
            className="flex items-center gap-1.5 px-3.5 py-1.5 bg-surface-container border border-outline-variant hover:bg-surface-container-high text-on-surface rounded-lg font-bold text-[12.5px] cursor-pointer transition-all shadow-2xs"
          >
            <BarChart3 className="w-3.5 h-3.5 text-primary" />
            Org Dashboard
          </button>
          <button 
            onClick={() => navigate('/super-admin/logs')}
            className="flex items-center gap-1.5 px-3.5 py-1.5 bg-surface-container border border-outline-variant hover:bg-surface-container-high text-on-surface rounded-lg font-bold text-[12.5px] cursor-pointer transition-all shadow-2xs"
          >
            <Activity className="w-3.5 h-3.5 text-primary" />
            Logs & Threats
          </button>
        </div>
      </div>

      {/* Tabs Navigation (Pill Design matching screenshot) */}
      <div className="flex items-center gap-2 border-b border-outline-variant/60 pb-3 overflow-x-auto hide-scrollbar">
        {[
          { id: 'overview', label: 'Overview' },
          { id: 'organizations', label: 'Organizations' },
          { id: 'members', label: 'Members' },
          { id: 'audit', label: 'Audit Logs' },
          { id: 'bookings', label: 'Bookings' },
          { id: 'emails', label: 'Emails' }
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2 font-bold text-[13.5px] rounded-lg transition-all cursor-pointer border-0 ${
              activeTab === tab.id
                ? 'bg-primary text-white shadow-sm'
                : 'text-on-surface-variant hover:text-on-surface bg-transparent hover:bg-surface-container/50'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* OVERVIEW TAB */}
      {activeTab === 'overview' && (
        <div className="flex flex-col gap-lg animate-fade-in">
          {/* Quick Metrics Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-md">
            <div className="bg-surface-container-lowest border border-outline-variant p-md rounded-2xl flex items-center justify-between shadow-2xs hover:shadow-md transition-all group">
              <div>
                <div className="text-[12px] font-bold text-on-surface-variant uppercase tracking-wider">Total Tenants</div>
                <div className="text-2xl font-extrabold text-on-surface mt-1">{metrics.total_tenants || organizations.length || 0}</div>
              </div>
              <div className="w-10 h-10 rounded-xl bg-primary/10 text-primary flex items-center justify-center group-hover:scale-110 transition-transform">
                <Building2 className="w-5 h-5" />
              </div>
            </div>

            <div className="bg-surface-container-lowest border border-outline-variant p-md rounded-2xl flex items-center justify-between shadow-2xs hover:shadow-md transition-all group">
              <div>
                <div className="text-[12px] font-bold text-on-surface-variant uppercase tracking-wider">Active Licenses</div>
                <div className="text-2xl font-extrabold text-on-surface mt-1">{metrics.active_licenses || 0}</div>
              </div>
              <div className="w-10 h-10 rounded-xl bg-emerald-500/10 text-emerald-600 flex items-center justify-center group-hover:scale-110 transition-transform">
                <CreditCard className="w-5 h-5" />
              </div>
            </div>

            <div className="bg-surface-container-lowest border border-outline-variant p-md rounded-2xl flex items-center justify-between shadow-2xs hover:shadow-md transition-all group">
              <div>
                <div className="text-[12px] font-bold text-on-surface-variant uppercase tracking-wider">Global Users</div>
                <div className="text-2xl font-extrabold text-on-surface mt-1">{metrics.global_users || users.length || 0}</div>
              </div>
              <div className="w-10 h-10 rounded-xl bg-purple-500/10 text-purple-600 flex items-center justify-center group-hover:scale-110 transition-transform">
                <Users className="w-5 h-5" />
              </div>
            </div>

            <div className="bg-surface-container-lowest border border-outline-variant p-md rounded-2xl flex items-center justify-between shadow-2xs hover:shadow-md transition-all group">
              <div>
                <div className="text-[12px] font-bold text-on-surface-variant uppercase tracking-wider">Active Scanners</div>
                <div className="text-2xl font-extrabold text-on-surface mt-1">{metrics.active_scanners || 0}<span className="text-sm text-on-surface-variant font-medium">/{metrics.total_scanners || 50}</span></div>
              </div>
              <div className="w-10 h-10 rounded-xl bg-blue-500/10 text-blue-600 flex items-center justify-center group-hover:scale-110 transition-transform">
                <Server className="w-5 h-5" />
              </div>
            </div>
          </div>

          {/* Infrastructure Node & System Health Cards */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-md">
            <div className="flex flex-col gap-md">
              <h2 className="font-headline-sm font-bold text-on-surface flex items-center text-[16.5px]">
                <Activity className="w-4 h-4 text-primary mr-2" /> Node Infrastructure & Health
              </h2>
              
              <div className="bg-surface-container-lowest border border-outline-variant rounded-2xl p-md flex flex-col gap-sm shadow-2xs">
                <div className="flex justify-between items-center pb-xs border-b border-outline-variant/50">
                  <div className="flex items-center gap-2 text-[13px] font-bold text-on-surface">
                    <Database className="w-4 h-4 text-primary" /> Database Cluster Connection Load
                  </div>
                  <span className="text-[11px] font-bold bg-green-500/10 text-green-600 px-2 py-0.5 rounded border border-green-500/20">
                    HEALTHY
                  </span>
                </div>
                <div className="flex justify-between items-center text-[12.5px]">
                  <span className="text-on-surface-variant font-semibold">Active Connections</span>
                  <span className="font-bold text-on-surface">{metrics.db_connections || 14} / 500</span>
                </div>
              </div>

              <div className="bg-surface-container-lowest border border-outline-variant rounded-2xl p-md flex flex-col gap-sm shadow-2xs">
                <div className="flex justify-between items-center pb-xs border-b border-outline-variant/50">
                  <div className="flex items-center gap-2 text-[13px] font-bold text-on-surface">
                    <HardDrive className="w-4 h-4 text-primary" /> Celery Workers & Queue Status
                  </div>
                  <span className={`text-[11px] font-bold px-2 py-0.5 rounded border ${metrics.queue_size > 5 ? 'bg-yellow-500/10 text-yellow-600 border-yellow-500/20' : 'bg-green-500/10 text-green-600 border-green-500/20'}`}>
                    {metrics.queue_size > 5 ? 'HEAVY LOAD' : 'NORMAL'}
                  </span>
                </div>
                <div className="flex justify-between items-center text-[12.5px]">
                  <span className="text-on-surface-variant font-semibold">Queue Size</span>
                  <span className="font-bold text-on-surface">{metrics.queue_size || 0} scans pending</span>
                </div>
              </div>

              <button 
                onClick={openActiveScansModal}
                className="w-full bg-surface-container border border-outline-variant text-primary py-2.5 rounded-xl text-[13px] font-bold hover:bg-primary/10 hover:border-primary/30 cursor-pointer transition-colors flex items-center justify-center gap-2 shadow-2xs"
              >
                <Eye className="w-4 h-4 text-primary" />
                Inspect Active Scans
              </button>
            </div>

            {/* Support Guidance Box */}
            <div className="bg-blue-500/5 border border-blue-500/20 rounded-2xl p-5 flex flex-col justify-between">
              <div>
                <div className="flex items-center gap-2 text-blue-600 mb-2">
                  <Info className="w-5 h-5" />
                  <h3 className="font-bold text-on-surface text-[15px] m-0">Support Engineer Operating Scope</h3>
                </div>
                <p className="text-on-surface-variant text-[13px] leading-relaxed m-0">
                  As a Support Engineer, you have full diagnostic visibility across platform performance metrics, customer environment states, active scans, and transaction logs.
                </p>
                <ul className="text-on-surface-variant text-[12.5px] mt-3 space-y-1.5 pl-4">
                  <li>• Use the <strong><Key className="w-3.5 h-3.5 inline text-primary mr-1" /> Inspect Tenant</strong> tool in Organizations tab to troubleshoot tenant issues in real-time.</li>
                  <li>• Modify client role assignments or org mappings to resolve onboarding configurations.</li>
                  <li>• Member passwords and organization creation/deletion are restricted for administrative security.</li>
                </ul>
              </div>
              
              <div className="mt-4 pt-3 border-t border-blue-500/20 flex items-center justify-between text-xs text-on-surface-variant font-medium">
                <span>System Status: Fully Operational</span>
                <span className="text-emerald-600 font-bold flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span> Online
                </span>
              </div>
            </div>
          </div>

          {/* Global Transaction & Billing History */}
          <div className="flex flex-col gap-md">
            <h2 className="font-headline-sm font-bold text-on-surface flex items-center text-[17px] m-0">
              <Receipt className="w-5 h-5 text-primary mr-2" /> Global Transactions & Invoices
            </h2>
            <div className="bg-surface-container-lowest border border-outline-variant rounded-2xl overflow-hidden shadow-sm">
              {loading ? (
                <div className="p-10 text-center text-on-surface-variant text-[14px]">Fetching transaction logs...</div>
              ) : (
                <div className="overflow-x-auto max-h-[350px] hide-scrollbar">
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
                            </div>
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-outline-variant">
                      {recentPayments.length === 0 ? (
                        <tr><td colSpan="6" className="p-10 text-center text-on-surface-variant">No recent transactions.</td></tr>
                      ) : getSortedBills().map(p => (
                        <tr key={p.id} className="hover:bg-surface-container transition-colors">
                          <td className="px-md py-sm text-[13px] text-on-surface-variant">{new Date(p.created_at).toLocaleDateString()}</td>
                          <td className="px-md py-sm"><div className="font-bold text-on-surface text-[13px]">{p.org_name}</div></td>
                          <td className="px-md py-sm"><span className="text-[12px] font-bold capitalize text-primary bg-primary/10 px-2 py-0.5 rounded border border-primary/20">{p.tier_id}</span></td>
                          <td className="px-md py-sm font-bold text-[13.5px] text-on-surface">{p.currency === 'INR' ? '₹' : '$'}{p.amount.toLocaleString(undefined, { minimumFractionDigits: 2 })}</td>
                          <td className="px-md py-sm"><div className="flex items-center gap-xs text-[12.5px] font-bold"><span className={`w-2 h-2 rounded-full ${p.status === 'successful' ? 'bg-green-500' : 'bg-error'}`}></span><span className={p.status === 'successful' ? 'text-green-600 dark:text-green-500' : 'text-error'}>{p.status === 'successful' ? 'Success' : 'Failed'}</span></div></td>
                          <td className="px-md py-sm text-right">
                            <div className="flex items-center justify-end gap-1">
                              <button onClick={() => setViewInvoice(p)} className="text-on-surface-variant hover:text-primary transition-colors bg-transparent border-0 cursor-pointer p-1" title="View Invoice">
                                <Eye className="w-4 h-4" />
                              </button>
                              <button onClick={() => handleDownloadInvoice(p)} className="text-on-surface-variant hover:text-primary transition-colors bg-transparent border-0 cursor-pointer p-1" title="Download Invoice">
                                <Download className="w-4 h-4" />
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

          {/* System Audit Trail Preview */}
          <div className="flex flex-col gap-md">
            <div className="flex justify-between items-center">
              <h2 className="font-headline-sm font-bold text-on-surface flex items-center text-[17px] m-0">
                <Layers className="w-5 h-5 text-primary mr-2" /> Recent System Audit Events
              </h2>
              <button onClick={() => setActiveTab('audit')} className="text-primary font-bold text-[13px] hover:underline bg-transparent border-0 cursor-pointer">
                View All Logs →
              </button>
            </div>

            <div className="bg-surface-container-lowest border border-outline-variant rounded-2xl overflow-hidden shadow-sm">
              {loading ? (
                <div className="p-10 text-center text-on-surface-variant text-[14px]">Fetching audit logs...</div>
              ) : (
                <div className="overflow-x-auto max-h-[350px] hide-scrollbar">
                  <table className="w-full text-left text-sm border-collapse">
                    <thead className="bg-surface-container text-on-surface-variant border-b border-outline-variant sticky top-0">
                      <tr>
                        <th className="px-md py-sm font-bold text-[12px] uppercase tracking-wider">Date & Time</th>
                        <th className="px-md py-sm font-bold text-[12px] uppercase tracking-wider">User</th>
                        <th className="px-md py-sm font-bold text-[12px] uppercase tracking-wider">Action / Event</th>
                        <th className="px-md py-sm font-bold text-[12px] uppercase tracking-wider">Target</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-outline-variant">
                      {auditLogs.length === 0 ? (
                        <tr><td colSpan="4" className="p-10 text-center text-on-surface-variant">No audit logs found.</td></tr>
                      ) : auditLogs.slice(0, 5).map(log => (
                        <tr key={log.id} className="hover:bg-surface-container transition-colors">
                          <td className="px-md py-sm text-on-surface-variant text-[12.5px]">{new Date(log.timestamp).toLocaleString()}</td>
                          <td className="px-md py-sm font-bold text-on-surface text-[13px]">{log.user_email}</td>
                          <td className="px-md py-sm font-semibold text-on-surface text-[13px]">{log.action}</td>
                          <td className="px-md py-sm font-bold text-[13px] text-on-surface-variant">{log.target_name || log.target_id || '-'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
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
                        <div className="flex flex-wrap gap-1.5 items-center">
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
                      <td className="px-md py-sm text-right whitespace-nowrap">
                        <div className="inline-flex items-center justify-end gap-1 whitespace-nowrap">
                          <button onClick={() => handleImpersonate(org.id, org.name)} className="text-on-surface-variant hover:text-primary transition-colors bg-transparent border-0 cursor-pointer p-1" title="Inspect Customer Environment / Assist Troubleshooting">
                            <span className="material-symbols-outlined text-[18px]">vpn_key</span>
                          </button>
                        </div>
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
                <Users className="w-5 h-5 text-primary mr-2" /> Global Members (Read-Only)
              </h2>
              <p className="text-[13px] text-on-surface-variant mt-0.5">
                Inspect user accounts, assigned roles, and organization mappings across all platform tenants.
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
                    {['Email', 'Role', 'Organization'].map((h) => (
                      <th 
                        key={h} 
                        onClick={() => handleUserSort(h)}
                        className="px-md py-sm font-bold text-[12px] uppercase tracking-wider cursor-pointer hover:bg-surface-container-highest transition-colors group"
                      >
                        <div className="flex items-center gap-xs">
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
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-md mb-xs">
            <h2 className="font-headline-sm font-bold text-on-surface flex items-center text-[18px]">
              <Calendar className="w-5 h-5 text-primary mr-2" /> Demo Bookings & Leads
            </h2>
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
                    <thead className="bg-surface-container-lowest border-b border-outline-variant select-none">
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
                          b.status === 'completed' ? 'Completed' :
                          b.status === 'cancelled' ? 'Cancelled' :
                          b.status === 'rescheduled' ? 'Rescheduled' : 'Pending';

                        const displayEmail = b.email || b.user_email;

                        return (
                          <tr key={b.id} className="hover:bg-surface-container-lowest transition-colors">
                            <td className="px-md py-sm font-bold text-on-surface text-[13px]">{displayEmail}</td>
                            <td className="px-md py-sm text-on-surface-variant text-[13px]">{b.company_size ? b.company_size.replace('Company Size: ', '') : 'N/A'}</td>
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
                                    className="bg-primary text-white border-0 py-1.5 px-3 rounded font-bold cursor-pointer text-[11px] hover:brightness-110 transition-all flex items-center gap-1 shadow-xs"
                                    title="Mark Demo as Completed"
                                  >
                                    Mark Complete
                                  </button>
                                )}
                                {b.status !== 'cancelled' && (
                                  <button
                                    onClick={() => handleCancelBooking(b)}
                                    className="bg-red-500/10 text-red-600 hover:bg-red-600 hover:text-white border border-red-500/30 py-1 px-2.5 rounded font-bold cursor-pointer text-[11px] transition-all flex items-center gap-1"
                                    title="Mark as Cancelled"
                                  >
                                    <X className="w-3.5 h-3.5" />
                                    Cancel
                                  </button>
                                )}
                                <button
                                  onClick={() => handleOpenReschedule(b)}
                                  className="bg-blue-500/10 text-blue-600 hover:bg-blue-600 hover:text-white border border-blue-500/30 py-1 px-2.5 rounded font-bold cursor-pointer text-[11px] transition-all flex items-center gap-1"
                                  title="Reschedule Date & Time"
                                >
                                  <Edit className="w-3.5 h-3.5" />
                                  Reschedule
                                </button>
                                <button
                                  onClick={() => handleDeleteBooking(b)}
                                  className="text-on-surface-variant hover:text-red-600 border-0 bg-transparent p-1 cursor-pointer transition-colors"
                                  title="Delete Lead"
                                >
                                  <Trash2 className="w-4 h-4" />
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

      {/* Active Scans Modal */}
      <CustomModal isOpen={activeScansModalOpen} onClose={() => setActiveScansModalOpen(false)} title="Active Scans Diagnostic">
        {fetchingActiveScans ? <div className="text-center py-xl font-bold text-on-surface-variant">Loading active scans...</div> : activeScans.length === 0 ? <div className="text-center py-xl font-bold text-on-surface-variant">No active scans running right now.</div> : (
          <div className="flex flex-col gap-md">
            {activeScans.map(scan => (
              <div key={scan.id} className="bg-surface border border-outline-variant rounded-xl p-md flex flex-col sm:flex-row justify-between items-center gap-md">
                <div>
                  <div className="font-bold text-on-surface">{scan.target_url}</div>
                  <div className="text-xs text-on-surface-variant mt-0.5">Scan ID: {scan.id} | Org ID: {scan.org_id}</div>
                </div>
                <button onClick={() => handleKillScan(scan.id)} className="bg-error/10 text-error border border-error/20 py-1.5 px-3 rounded font-bold cursor-pointer hover:bg-error/20 transition-all text-xs">
                  Terminate Scan
                </button>
              </div>
            ))}
          </div>
        )}
      </CustomModal>

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

            <div className="border border-outline-variant rounded-lg overflow-hidden">
              <table className="w-full text-left border-collapse text-sm">
                <thead className="bg-surface-container border-b border-outline-variant">
                  <tr>
                    <th className="p-3 font-bold">Subscription Plan</th>
                    <th className="p-3 font-bold text-right">Amount</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td className="p-3 font-semibold capitalize">{viewInvoice.tier_id} Plan Subscription</td>
                    <td className="p-3 font-bold text-right">{viewInvoice.currency === 'INR' ? '₹' : '$'}{viewInvoice.amount.toLocaleString(undefined, { minimumFractionDigits: 2 })}</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div className="flex justify-between items-center bg-primary/10 border border-primary/20 p-4 rounded-lg text-primary font-bold text-lg mt-2">
              <span>Total Amount Paid</span>
              <span>{viewInvoice.currency === 'INR' ? '₹' : '$'}{viewInvoice.amount.toLocaleString(undefined, { minimumFractionDigits: 2 })}</span>
            </div>
          </div>
        )}
      </CustomModal>

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
            <button onClick={confirmModal.onConfirm} className={`px-4 py-2 rounded-lg font-bold border-0 cursor-pointer text-white ${confirmModal.type === 'error' ? 'bg-error' : 'bg-primary'}`}>Confirm</button>
          </>
        }
      />

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

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider block mb-1">Meeting Date</label>
              <input
                type="date"
                value={rescheduleModal.isoDate}
                onChange={(e) => {
                  const val = e.target.value;
                  setRescheduleModal({
                    ...rescheduleModal,
                    isoDate: val,
                    meetingDate: formatToReadableDate(val)
                  });
                }}
                className="w-full border border-outline-variant rounded-lg p-2 text-xs text-on-surface bg-surface-container-lowest focus:border-primary outline-none cursor-pointer font-medium"
              />
              <span className="text-[11px] text-primary font-bold mt-1 block">
                {rescheduleModal.meetingDate || 'No date selected'}
              </span>
            </div>

            <div>
              <label className="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider block mb-1">Meeting Time</label>
              <input
                type="time"
                value={rescheduleModal.isoTime}
                onChange={(e) => {
                  const val = e.target.value;
                  setRescheduleModal({
                    ...rescheduleModal,
                    isoTime: val,
                    meetingTime: formatTo12HrTime(val)
                  });
                }}
                className="w-full border border-outline-variant rounded-lg p-2 text-xs text-on-surface bg-surface-container-lowest focus:border-primary outline-none cursor-pointer font-medium"
              />
              <span className="text-[11px] text-primary font-bold mt-1 block">
                {rescheduleModal.meetingTime || 'No time selected'}
              </span>
            </div>
          </div>

          <div>
            <label className="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider block mb-1">Booking Status</label>
            <select
              value={rescheduleModal.status}
              onChange={(e) => setRescheduleModal({ ...rescheduleModal, status: e.target.value })}
              className="w-full border border-outline-variant rounded-lg p-2.5 text-xs text-on-surface bg-surface-container-lowest focus:border-primary outline-none cursor-pointer"
            >
              <option value="rescheduled">Rescheduled</option>
              <option value="pending">Pending</option>
              <option value="completed">Completed</option>
              <option value="cancelled">Cancelled</option>
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
              Save & Update
            </button>
          </div>
        </form>
      </CustomModal>

    </div>
  );
};

export default SupportEngineerPanel;
