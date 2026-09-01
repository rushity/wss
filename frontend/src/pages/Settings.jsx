import { useState, useEffect } from 'react';
import { useAuth } from '../components/AuthContext';
import toast from 'react-hot-toast';
import Profile from './Profile';

export const AlertSettingsPage = () => {
  const [activeTab, setActiveTab] = useState(() => {
    return localStorage.getItem('settingsActiveTab') || 'profile';
  }); // profile, notifications, apiKeys, team, billing, scheduler

  useEffect(() => {
    localStorage.setItem('settingsActiveTab', activeTab);
  }, [activeTab]);

  // Notification states (connected to backend)
  const [emailNotifications, setEmailNotifications] = useState(true);
  const [webhookUrl, setWebhookUrl] = useState('');
  const [severityThreshold, setSeverityThreshold] = useState('Medium');
  const [reportLogoUrl, setReportLogoUrl] = useState('');


  const [teamUsers, setTeamUsers] = useState([]);
  const [loadingTeam, setLoadingTeam] = useState(false);
  const [newUserFirstName, setNewUserFirstName] = useState('');
  const [newUserLastName, setNewUserLastName] = useState('');
  const [newUserEmail, setNewUserEmail] = useState('');
  const [newUserPassword, setNewUserPassword] = useState('');
  const [newUserRole, setNewUserRole] = useState('soc_analyst');
  const [invitingUser, setInvitingUser] = useState(false);
  const [showAddMember, setShowAddMember] = useState(false);
  const [showNewUserPassword, setShowNewUserPassword] = useState(false);
  const [editingUser, setEditingUser] = useState(null);
  const [updatingUser, setUpdatingUser] = useState(false);
  const [userToDelete, setUserToDelete] = useState(null);
  const [deletingUser, setDeletingUser] = useState(false);

  const [passwordData, setPasswordData] = useState({ currentPassword: '', newPassword: '', confirmPassword: '' });
  const [passwordStatus, setPasswordStatus] = useState({ loading: false, error: null, success: false });
  const [showPassword, setShowPassword] = useState({ current: false, new: false, confirm: false });

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const [billingHistory, setBillingHistory] = useState([]);
  const [loadingBilling, setLoadingBilling] = useState(false);

  const [scanQuotas, setScanQuotas] = useState([]);
  const [loadingQuotas, setLoadingQuotas] = useState(false);

  // Demo Bookings State
  const [demoBookings, setDemoBookings] = useState([]);
  const [loadingDemoBookings, setLoadingDemoBookings] = useState(false);
  const [rescheduleModal, setRescheduleModal] = useState({
    isOpen: false,
    bookingId: null,
    email: '',
    meetingDate: '',
    meetingTime: '',
    status: 'rescheduled'
  });

  const handleUpdateDemoBookingStatus = async (bookingId, status) => {
    try {
      const res = await fetch(`/api/demo/bookings/${bookingId}`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ status })
      });
      if (res.ok) {
        toast.success(`Booking status updated to ${status}`);
        fetchDemoBookings();
      } else {
        toast.error("Failed to update status");
      }
    } catch (err) {
      toast.error("Error updating status");
    }
  };

  const handleOpenReschedule = (booking) => {
    setRescheduleModal({
      isOpen: true,
      bookingId: booking.id,
      email: booking.email,
      meetingDate: booking.meeting_date || '',
      meetingTime: booking.meeting_time || '',
      status: 'rescheduled'
    });
  };

  const handleSaveReschedule = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch(`/api/demo/bookings/${rescheduleModal.bookingId}`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          meeting_date: rescheduleModal.meetingDate,
          meeting_time: rescheduleModal.meetingTime,
          status: rescheduleModal.status
        })
      });
      if (res.ok) {
        toast.success("Demo booking rescheduled successfully!");
        setRescheduleModal({ isOpen: false, bookingId: null, email: '', meetingDate: '', meetingTime: '', status: 'rescheduled' });
        fetchDemoBookings();
      } else {
        toast.error("Failed to reschedule demo booking");
      }
    } catch (err) {
      toast.error("Error rescheduling booking");
    }
  };

  const handleDeleteDemoBooking = async (bookingId) => {
    if (!window.confirm("Are you sure you want to delete this booking lead?")) return;
    try {
      const res = await fetch(`/api/demo/bookings/${bookingId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        toast.success("Booking lead deleted successfully");
        fetchDemoBookings();
      } else {
        toast.error("Failed to delete booking lead");
      }
    } catch (err) {
      toast.error("Error deleting lead");
    }
  };

  // Scheduled Scans
  const [scheduledScans, setScheduledScans] = useState([]);
  const [loadingScans, setLoadingScans] = useState(false);
  const [newSchedule, setNewSchedule] = useState({ target_url: '', scan_type: 'Full', schedule_time: '20:00' });

  // Notification History
  const [notificationHistory, setNotificationHistory] = useState([]);
  const [loadingHistory, setLoadingHistory] = useState(false);

  const [sortTeamCol, setSortTeamCol] = useState('Name');
  const [sortTeamDir, setSortTeamDir] = useState('asc');

  const [sortBillCol, setSortBillCol] = useState('Date');
  const [sortBillDir, setSortBillDir] = useState('desc');

  const handleTeamSort = (column) => {
    if (column === 'Actions') return;
    if (sortTeamCol === column) {
      setSortTeamDir(sortTeamDir === 'asc' ? 'desc' : 'asc');
    } else {
      setSortTeamCol(column);
      setSortTeamDir('asc');
    }
  };

  const getSortedTeam = () => {
    return [...teamUsers].sort((a, b) => {
      let aVal, bVal;
      switch (sortTeamCol) {
        case 'Name': 
          aVal = `${a.first_name || ''} ${a.last_name || ''}`.trim();
          bVal = `${b.first_name || ''} ${b.last_name || ''}`.trim();
          break;
        case 'Email': aVal = a.email || ''; bVal = b.email || ''; break;
        case 'Assigned Role': aVal = a.role || ''; bVal = b.role || ''; break;
        case 'Status': aVal = a.status || ''; bVal = b.status || ''; break;
        default: return 0;
      }
      if (aVal < bVal) return sortTeamDir === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortTeamDir === 'asc' ? 1 : -1;
      return 0;
    });
  };

  const handleBillSort = (column) => {
    if (sortBillCol === column) {
      setSortBillDir(sortBillDir === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBillCol(column);
      setSortBillDir('desc');
    }
  };

  const getSortedBilling = () => {
    return [...billingHistory].sort((a, b) => {
      let aVal, bVal;
      switch (sortBillCol) {
        case 'Date': aVal = new Date(a.created_at).getTime(); bVal = new Date(b.created_at).getTime(); break;
        case 'Plan': aVal = a.tier_id || ''; bVal = b.tier_id || ''; break;
        case 'Amount': aVal = a.amount || 0; bVal = b.amount || 0; break;
        case 'Status': aVal = a.status || ''; bVal = b.status || ''; break;
        default: return 0;
      }
      if (aVal < bVal) return sortBillDir === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortBillDir === 'asc' ? 1 : -1;
      return 0;
    });
  };

  const { token, user, reloadUser } = useAuth();

  useEffect(() => {
    fetchSettings();
  }, [token]);

  const fetchSettings = async () => {
    try {
      const res = await fetch('/api/vulnerabilities/settings', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setEmailNotifications(data.settings.email_notifications);
        setWebhookUrl(data.settings.webhook_url || '');
        setSeverityThreshold(data.settings.severity_threshold);
      }
    } catch (err) {
      console.error("Error loading alert settings", err);
    } finally {
      setLoading(false);
    }
  };

  const fetchNotificationHistory = async () => {
    setLoadingHistory(true);
    try {
      const res = await fetch('/api/auth/notifications', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setNotificationHistory(data.notifications || []);
      }
    } catch (err) {
      console.error("Error loading notification history", err);
    } finally {
      setLoadingHistory(false);
    }
  };

  const fetchTeamUsers = async () => {
    setLoadingTeam(true);
    try {
      const endpoint = user?.org_id ? `/api/auth/organizations/${user.org_id}/users` : '/api/auth/users';
      const res = await fetch(endpoint, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        const filteredUsers = (data.users || []).filter(u => u.role !== 'super_admin');
        setTeamUsers(filteredUsers);
      }
    } catch (err) {
      console.error('Failed to fetch org users', err);
    } finally {
      setLoadingTeam(false);
    }
  };

  useEffect(() => {
    if (activeTab === 'team' && (user?.role === 'org_admin' || user?.role === 'super_admin')) {
      fetchTeamUsers();
    }
  }, [activeTab, user]);

  const handleInviteUser = async (e) => {
    e.preventDefault();
    if (!newUserEmail) return;
    setInvitingUser(true);
    try {
      const res = await fetch('/api/auth/users/invite', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          email: newUserEmail,
          role: newUserRole,
          first_name: newUserFirstName,
          last_name: newUserLastName,
          password: newUserPassword
        })
      });
      const data = await res.json();
      if (res.ok) {
        toast.success(`User added successfully!`);
        setNewUserFirstName('');
        setNewUserLastName('');
        setNewUserEmail('');
        setNewUserPassword('');
        setShowAddMember(false);
        setShowNewUserPassword(false);
        fetchTeamUsers();
      } else {
        toast.error(data.message || 'Failed to invite user');
      }
    } catch (err) {
      toast.error("Error inviting user");
    } finally {
      setInvitingUser(false);
    }
  };

  const handleUpdateUser = async (e) => {
    e.preventDefault();
    if (!editingUser) return;
    setUpdatingUser(true);
    try {
      const res = await fetch(`/api/auth/users/${editingUser.id}`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          first_name: editingUser.first_name,
          last_name: editingUser.last_name,
          email: editingUser.email,
          password: editingUser.new_password,
          role: editingUser.role
        })
      });
      if (res.ok) {
        toast.success(`User updated successfully!`);
        setEditingUser(null);
        fetchTeamUsers();
      } else {
        const data = await res.json();
        toast.error(data.message || 'Failed to update user');
      }
    } catch (err) {
      toast.error("Error updating user");
    } finally {
      setUpdatingUser(false);
    }
  };

  const executeDeleteUser = async () => {
    if (!userToDelete) return;
    setDeletingUser(true);
    try {
      const res = await fetch(`/api/auth/users/${userToDelete.id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        toast.success("User removed successfully!");
        setUserToDelete(null);
        fetchTeamUsers();
      } else {
        const data = await res.json();
        toast.error(data.message || "Failed to remove user");
      }
    } catch (err) {
      toast.error("Error removing user");
    } finally {
      setDeletingUser(false);
    }
  };

  const handlePasswordChange = async (e) => {
    e.preventDefault();
    setPasswordStatus({ loading: true, error: null, success: false });
    if (passwordData.newPassword !== passwordData.confirmPassword) {
      setPasswordStatus({ loading: false, error: "New passwords do not match", success: false });
      return;
    }
    if (passwordData.newPassword.length < 6) {
      setPasswordStatus({ loading: false, error: "New password must be at least 6 characters", success: false });
      return;
    }
    try {
      const res = await fetch('/api/auth/password', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ currentPassword: passwordData.currentPassword, newPassword: passwordData.newPassword })
      });
      let data = {};
      try { data = await res.json(); } catch (e) { }
      if (res.ok) {
        setPasswordStatus({ loading: false, error: null, success: true });
        setPasswordData({ currentPassword: '', newPassword: '', confirmPassword: '' });
        toast.success("Password updated successfully!");
        setTimeout(() => setPasswordStatus(prev => ({ ...prev, success: false })), 3000);
      } else {
        const errorMsg = data.message || "Failed to update password";
        setPasswordStatus({ loading: false, error: errorMsg, success: false });
        toast.error(errorMsg);
      }
    } catch (err) {
      setPasswordStatus({ loading: false, error: "Network error occurred", success: false });
      toast.error("Network error occurred");
    }
  };

  // Auto-refresh user data (e.g., subscription upgrades) when Billing tab is active
  useEffect(() => {
    let intervalId;
    if (activeTab === 'billing' && reloadUser) {
      intervalId = setInterval(() => {
        reloadUser();
        fetchQuotas(true);
        fetchBillingHistory(true);
      }, 15000); // Poll every 15 seconds silently
    }
    return () => {
      if (intervalId) clearInterval(intervalId);
    };
  }, [activeTab, reloadUser]);

  useEffect(() => {
    if (activeTab === 'billing') {
      fetchBillingHistory();
      fetchQuotas();
    }
    if (activeTab === 'notifications') {
      fetchNotificationHistory();
    }
  }, [activeTab, user?.org_id, user?.id]);

  const fetchQuotas = async (isSilent = false) => {
    if (!isSilent && scanQuotas.length === 0) setLoadingQuotas(true);
    try {
      // If user has organization_id, fetch from it. Otherwise we might fetch from a general endpoint if it existed, or we just try to fetch the first organization.
      // Usually users belong to one organization. Let's try to get their organization ID first, or fetch from /api/auth/organizations
      let orgId = user?.org_id;
      if (!orgId) {
        const orgRes = await fetch('/api/auth/organizations', { headers: { 'Authorization': `Bearer ${token}` } });
        if (orgRes.ok) {
          const orgsData = await orgRes.json();
          if (orgsData.organizations && orgsData.organizations.length > 0) {
            orgId = orgsData.organizations[0].id;
          }
        }
      }

      if (orgId) {
        const res = await fetch(`/api/auth/organizations/${orgId}/quotas`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (res.ok) {
          const data = await res.json();
          setScanQuotas(data.quotas || []);
        }
      }
    } catch (err) {
      console.error("Error loading quotas", err);
    } finally {
      setLoadingQuotas(false);
    }
  };

  const fetchBillingHistory = async (isSilent = false) => {
    if (!isSilent && billingHistory.length === 0) setLoadingBilling(true);
    try {
      const res = await fetch('/api/billing/history', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setBillingHistory(data.history || []);
      }
    } catch (err) {
      console.error("Error loading billing history", err);
    } finally {
      setLoadingBilling(false);
    }
  };

  useEffect(() => {
    if (activeTab === 'scheduler') {
      fetchScheduledScans();
    }
  }, [activeTab, token]);

  const fetchScheduledScans = async () => {
    setLoadingScans(true);
    try {
      const res = await fetch('/api/scans/schedule', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setScheduledScans(data.schedules || []);
      }
    } catch (err) {
      console.error("Error loading scheduled scans", err);
    } finally {
      setLoadingScans(false);
    }
  };

  const fetchDemoBookings = async () => {
    setLoadingDemoBookings(true);
    try {
      const res = await fetch('/api/demo/bookings', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setDemoBookings(data || []);
      }
    } catch (err) {
      console.error("Error loading demo bookings", err);
    } finally {
      setLoadingDemoBookings(false);
    }
  };

  useEffect(() => {
    if (activeTab === 'demoBookings') {
      fetchDemoBookings();
    }
  }, [activeTab, token]);

  const handleCreateSchedule = async (e) => {
    e.preventDefault();
    setMessage('');
    setError('');

    if (user?.subscription_tier === 'Free') {
      setError('Scheduled scans require a premium subscription.');
      return;
    }

    try {
      const res = await fetch('/api/scans/schedule', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ ...newSchedule, frequency: 'daily' })
      });

      const data = await res.json();
      if (res.ok) {
        setMessage('Scan scheduled successfully!');
        setNewSchedule({ target_url: '', scan_type: 'Full', schedule_time: '20:00' });
        fetchScheduledScans();
      } else {
        setError(data.message || 'Failed to schedule scan.');
      }
    } catch (err) {
      setError('Connection error.');
    }
  };

  const handleDeleteSchedule = async (id) => {
    try {
      const res = await fetch(`/api/scans/schedule/${id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        setScheduledScans(prev => prev.filter(s => s.id !== id));
      }
    } catch (err) {
      console.error('Failed to delete schedule', err);
    }
  };

  const handleSave = async (e) => {
    e.preventDefault();
    setSaving(true);
    setMessage('');
    setError('');

    try {
      const res = await fetch('/api/vulnerabilities/settings', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          email_notifications: emailNotifications,
          webhook_url: webhookUrl,
          severity_threshold: severityThreshold
        })
      });

      const data = await res.json();
      if (res.ok) {
        setMessage('Alert preferences successfully updated!');
      } else {
        setError(data.message || 'Failed to update alert configurations.');
      }
    } catch (err) {
      setError('Could not establish connection to the security server API.');
      console.error(err);
    } finally {
      setSaving(false);
    }
  };

  const isSchedulerAllowed = ['super_admin', 'support_engineer', 'admin', 'org_admin', 'soc_analyst'].includes(user?.role);
  const isDemoBookingsAllowed = ['super_admin', 'support_engineer', 'admin', 'org_admin', 'soc_analyst'].includes(user?.role);
  const isNotificationsAllowed = ['super_admin', 'support_engineer', 'admin', 'org_admin'].includes(user?.role);
  const isApiKeysAllowed = ['super_admin', 'support_engineer', 'admin', 'org_admin'].includes(user?.role);
  const isTeamAllowed = ['super_admin', 'support_engineer', 'admin', 'org_admin'].includes(user?.role);
  const isBillingAllowed = ['super_admin', 'support_engineer', 'admin', 'org_admin'].includes(user?.role);

  const tabItems = [
    { id: 'profile', label: 'My Profile', icon: 'person' }
  ];

  if (isSchedulerAllowed) tabItems.push({ id: 'scheduler', label: 'Scheduler', icon: 'schedule' });
  if (isDemoBookingsAllowed) tabItems.push({ id: 'demoBookings', label: 'Demo Bookings', icon: 'event_available' });
  if (isNotificationsAllowed) tabItems.push({ id: 'notifications', label: 'Notifications', icon: 'notifications' });
  if (isApiKeysAllowed) tabItems.push({ id: 'apiKeys', label: 'API Keys', icon: 'key' });
  if (isTeamAllowed) tabItems.push({ id: 'team', label: 'Team', icon: 'group' });
  if (isBillingAllowed) tabItems.push({ id: 'billing', label: 'Billing', icon: 'credit_card' });

  useEffect(() => {
    const isAllowed = tabItems.some(t => t.id === activeTab);
    if (!isAllowed) {
      setActiveTab('profile');
    }
  }, [user?.role, activeTab]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-2xl font-label-md text-label-md text-on-surface-variant text-left">
        <span className="material-symbols-outlined animate-spin mr-sm">sync</span>
        Loading Settings...
      </div>
    );
  }

  // Pre-fill user profile info or fallback to Mercer placeholder
  const profileName = user ? user.email.split('@')[0] : 'Alex';
  const profileLastName = user ? 'User' : 'Mercer';
  const profileEmail = user ? user.email : 'alex.mercer@larxiuswss.io';
  const profileRole = user?.role ? `Role: ${user.role}` : 'Lead Security Engineer';

  return (
    <div className="flex flex-col gap-gutter text-left w-full">

      {/* Settings Header & Tabs */}
      <div className="border-b border-outline-variant bg-surface-container-lowest p-lg rounded-xl shadow-sm mb-sm">
        <h1 className="font-display-lg text-display-lg text-on-surface mb-sm font-bold tracking-tight">Settings</h1>
        <p className="font-body-lg text-body-lg text-on-surface-variant mb-xl">
          Manage your account preferences, security protocols, and team access.
        </p>

        {/* Scrollable Tabs row */}
        <div className="flex items-center gap-md md:gap-lg overflow-x-auto scrollbar-none">
          {tabItems.map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => {
                  setActiveTab(tab.id);
                  setMessage('');
                  setError('');
                }}
                className={`font-label-md text-label-md pb-sm px-sm transition-all flex items-center gap-xs cursor-pointer border-0 bg-transparent whitespace-nowrap ${isActive
                  ? 'text-primary border-b-2 border-primary font-bold'
                  : 'text-on-surface-variant hover:text-primary'
                  }`}
              >
                <span className="material-symbols-outlined text-[18px]">{tab.icon}</span>
                {tab.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Tab Switch Contents */}

      {activeTab === 'scheduler' && isSchedulerAllowed && (
        <div className="max-w-3xl mx-auto w-full">
          <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-lg shadow-sm mb-lg">
            <h2 className="font-headline-md text-headline-md font-bold mb-md flex items-center gap-sm border-b pb-sm">
              <span className="material-symbols-outlined text-primary text-[22px]">schedule</span>
              Schedule Automated Scans
            </h2>
            <p className="font-body-sm text-body-sm text-on-surface-variant mb-lg">
              Set up daily automated scans for your targets. The scanner will run automatically at your specified time.
            </p>

            {message && (
              <div className="flex gap-sm bg-green-500/10 border border-green-500/30 rounded-lg p-md text-green-600 font-body-sm text-body-sm items-center mb-md">
                <span className="material-symbols-outlined shrink-0 text-green-500">check_circle</span>
                <div>{message}</div>
              </div>
            )}
            {error && (
              <div className="flex gap-sm bg-error-container/20 border border-error/30 rounded-lg p-md text-error font-body-sm text-body-sm items-center mb-md">
                <span className="material-symbols-outlined shrink-0">error</span>
                <div>{error}</div>
              </div>
            )}

            <form onSubmit={handleCreateSchedule} className="flex flex-col gap-md">
              <div className="flex gap-md w-full max-sm:flex-col">
                <div className="flex-1 flex flex-col gap-xs">
                  <label className="font-label-sm text-label-sm font-bold">Target URL</label>
                  <input
                    type="url" required
                    className="w-full bg-surface-container-low border border-outline-variant rounded-lg px-md py-sm focus:border-primary focus:ring-1 focus:ring-primary/50"
                    placeholder="https://example.com"
                    value={newSchedule.target_url}
                    onChange={e => setNewSchedule({ ...newSchedule, target_url: e.target.value })}
                  />
                </div>
                <div className="w-1/4 max-sm:w-full flex flex-col gap-xs">
                  <label className="font-label-sm text-label-sm font-bold">Time (Daily)</label>
                  <input
                    type="time" required
                    className="w-full bg-surface-container-low border border-outline-variant rounded-lg px-md py-sm focus:border-primary focus:ring-1 focus:ring-primary/50"
                    value={newSchedule.schedule_time}
                    onChange={e => setNewSchedule({ ...newSchedule, schedule_time: e.target.value })}
                  />
                </div>
                <div className="w-1/4 max-sm:w-full flex flex-col gap-xs">
                  <label className="font-label-sm text-label-sm font-bold">Scan Type</label>
                  <select
                    className="w-full bg-surface-container-low border border-outline-variant rounded-lg px-md py-sm focus:border-primary focus:ring-1 focus:ring-primary/50 cursor-pointer"
                    value={newSchedule.scan_type}
                    onChange={e => setNewSchedule({ ...newSchedule, scan_type: e.target.value })}
                  >
                    <option value="Quick">Quick</option>
                    <option value="Full">Full</option>
                    <option value="Deep">Deep</option>
                  </select>
                </div>
              </div>
              <div className="flex justify-end mt-sm">
                <button type="submit" className="bg-primary text-on-primary font-label-md py-sm px-lg rounded-lg hover:opacity-90 transition-opacity font-bold">
                  Add Schedule
                </button>
              </div>
            </form>
          </div>

          <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-lg shadow-sm">
            <h3 className="font-headline-sm font-bold mb-md">Active Schedules</h3>
            {loadingScans ? (
              <p className="text-on-surface-variant font-body-sm py-md">Loading schedules...</p>
            ) : scheduledScans.length === 0 ? (
              <p className="text-on-surface-variant font-body-sm py-md">No automated scans scheduled yet.</p>
            ) : (
              <div className="flex flex-col gap-sm">
                {scheduledScans.map(scan => (
                  <div key={scan.id} className="flex items-center justify-between bg-surface-container-low p-md rounded-lg border border-outline-variant/50">
                    <div>
                      <div className="font-bold font-body-md text-on-surface">{scan.target_url}</div>
                      <div className="text-on-surface-variant font-body-sm flex items-center gap-md mt-xs whitespace-nowrap overflow-x-auto scrollbar-none w-full max-w-[calc(100vw-4rem)]">
                        <span className="flex items-center gap-xs"><span className="material-symbols-outlined text-[14px]">schedule</span> {scan.schedule_time} (Daily)</span>
                        <span className="flex items-center gap-xs"><span className="material-symbols-outlined text-[14px]">troubleshoot</span> {scan.scan_type} Scan</span>
                        {scan.last_run_at && <span className="flex items-center gap-xs text-primary"><span className="material-symbols-outlined text-[14px]">history</span> Last run: {new Date(scan.last_run_at).toLocaleDateString()}</span>}
                      </div>
                    </div>
                    <button onClick={() => handleDeleteSchedule(scan.id)} className="text-error hover:bg-error/10 p-sm rounded-full transition-colors" title="Delete Schedule">
                      <span className="material-symbols-outlined">delete</span>
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'demoBookings' && isDemoBookingsAllowed && (
        <div className="max-w-3xl mx-auto w-full">
          <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-lg shadow-sm mb-lg">
            <h2 className="font-headline-md text-headline-md font-bold mb-md flex items-center gap-sm border-b pb-sm">
              <span className="material-symbols-outlined text-primary text-[22px]">event_available</span>
              Discovery Call Bookings
            </h2>
            <div className="space-y-sm">
              {loadingDemoBookings ? (
                <div className="flex items-center justify-center p-xl">
                  <div className="w-8 h-8 border-4 border-primary/20 border-t-primary rounded-full animate-spin"></div>
                </div>
              ) : demoBookings.length > 0 ? (
                demoBookings.map((b) => {
                  const statusStyle =
                    b.status === 'completed'
                      ? 'bg-emerald-100 text-emerald-700 border-emerald-300'
                      : b.status === 'cancelled'
                      ? 'bg-rose-100 text-rose-700 border-rose-300'
                      : b.status === 'rescheduled'
                      ? 'bg-indigo-100 text-indigo-700 border-indigo-300'
                      : 'bg-amber-100 text-amber-700 border-amber-300';

                  const statusLabel =
                    b.status === 'completed' ? 'Completed' :
                    b.status === 'cancelled' ? 'Cancelled / Not Conducted' :
                    b.status === 'rescheduled' ? 'Rescheduled' : 'Pending';

                  return (
                    <div key={b.id} className={`bg-white border p-md rounded-lg shadow-sm flex flex-col sm:flex-row justify-between items-start sm:items-center gap-md ${b.status === 'completed' ? 'border-emerald-500/50' : 'border-outline-variant/60'}`}>
                      <div>
                        <div className="font-headline-sm font-bold text-on-surface mb-xs flex items-center gap-2 flex-wrap">
                          <span>{b.email}</span>
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${statusStyle}`}>
                            {statusLabel}
                          </span>
                        </div>
                        <div className="font-body-sm text-on-surface-variant flex flex-wrap gap-md mt-xs">
                          <span className="flex items-center gap-xs"><span className="material-symbols-outlined text-[14px]">calendar_today</span> {b.meeting_date}</span>
                          <span className="flex items-center gap-xs"><span className="material-symbols-outlined text-[14px]">schedule</span> {b.meeting_time}</span>
                          <span className="flex items-center gap-xs"><span className="material-symbols-outlined text-[14px]">business</span> {b.company_size}</span>
                        </div>
                      </div>
                      <div className="flex flex-col sm:items-end gap-2 shrink-0 w-full sm:w-auto">
                        <div className="text-xs text-on-surface-variant bg-surface-container-low px-2 py-1 rounded w-max">
                          Booked: {new Date(b.created_at).toLocaleDateString()}
                        </div>
                        <div className="flex items-center gap-1.5 flex-wrap">
                          {b.status !== 'completed' && (
                            <button
                              onClick={() => handleUpdateDemoBookingStatus(b.id, 'completed')}
                              className="bg-emerald-600 text-white border-none py-1 px-2.5 rounded text-[11px] font-bold cursor-pointer hover:bg-emerald-700 transition-all flex items-center gap-1 shadow-xs"
                              title="Mark Completed"
                            >
                              <span className="material-symbols-outlined text-[13px]">task_alt</span> Complete
                            </button>
                          )}
                          {b.status !== 'cancelled' && (
                            <button
                              onClick={() => handleUpdateDemoBookingStatus(b.id, 'cancelled')}
                              className="bg-rose-50 text-rose-600 border border-rose-200 py-1 px-2.5 rounded text-[11px] font-bold cursor-pointer hover:bg-rose-600 hover:text-white transition-all flex items-center gap-1"
                              title="Mark Cancelled / Not Conducted"
                            >
                              <span className="material-symbols-outlined text-[13px]">cancel</span> Cancelled
                            </button>
                          )}
                          <button
                            onClick={() => handleOpenReschedule(b)}
                            className="bg-indigo-50 text-indigo-600 border border-indigo-200 py-1 px-2.5 rounded text-[11px] font-bold cursor-pointer hover:bg-indigo-600 hover:text-white transition-all flex items-center gap-1"
                            title="Reschedule Date & Time"
                          >
                            <span className="material-symbols-outlined text-[13px]">edit_calendar</span> Reschedule
                          </button>
                          <button
                            onClick={() => handleDeleteDemoBooking(b.id)}
                            className="text-on-surface-variant hover:text-rose-600 border-0 bg-transparent p-1 cursor-pointer transition-colors"
                            title="Delete Lead"
                          >
                            <span className="material-symbols-outlined text-[16px]">delete</span>
                          </button>
                        </div>
                      </div>
                    </div>
                  );
                })
              ) : (
                <div className="text-center py-xl bg-white border border-outline-variant/60 rounded-lg shadow-sm">
                  <span className="material-symbols-outlined text-outline text-[48px] mb-sm block">event_busy</span>
                  <p className="font-body-md text-on-surface-variant">No demo bookings found.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 2. Notifications Tab (History) */}
      {activeTab === 'notifications' && isNotificationsAllowed && (
        <div className="max-w-3xl mx-auto w-full">
          {/* Notification History Panel */}
          <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-lg shadow-sm flex flex-col max-h-[700px]">
            <h2 className="font-headline-md text-headline-md font-bold mb-md flex items-center gap-sm border-b pb-sm shrink-0">
              <span className="material-symbols-outlined text-primary text-[22px]">history</span>
              Notification History
            </h2>
            <div className="overflow-y-auto pr-2 space-y-sm flex-1 custom-scrollbar">
              {loadingHistory ? (
                <div className="flex justify-center p-xl">
                  <div className="w-6 h-6 border-2 border-primary/20 border-t-primary rounded-full animate-spin"></div>
                </div>
              ) : notificationHistory.length > 0 ? (
                notificationHistory.map((notif, idx) => (
                  <div key={idx} className="bg-white border border-outline-variant/60 p-md rounded-lg shadow-sm flex gap-md items-start">
                    <div className={`p-sm rounded-full shrink-0 ${notif.bg} ${notif.color}`}>
                      <span className="material-symbols-outlined text-[20px] block">{notif.icon}</span>
                    </div>
                    <div>
                      <div className="font-headline-sm font-bold text-on-surface mb-xs">{notif.title}</div>
                      <div className="font-body-sm text-on-surface-variant mb-xs">{notif.message}</div>
                      <div className="text-[11px] text-on-surface-variant/70">{new Date(notif.timestamp).toLocaleString()}</div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-center py-xl bg-surface-container-low rounded-lg border border-outline-variant/30">
                  <span className="material-symbols-outlined text-outline text-[32px] mb-sm block">notifications_paused</span>
                  <p className="font-body-sm text-on-surface-variant">No recent notifications.</p>
                </div>
              )}
            </div>
          </div>


        </div>
      )}

      {/* 3. Billing Tab */}
      {activeTab === 'billing' && isBillingAllowed && (
        <div className="max-w-3xl mx-auto w-full flex flex-col gap-gutter">

          {/* Subscription & Billing */}
          <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-lg shadow-sm">
            <h2 className="font-headline-md text-headline-md font-bold mb-md flex items-center gap-sm border-b pb-sm">
              <span className="material-symbols-outlined text-primary text-[22px]">credit_card</span>
              Subscription & Billing
            </h2>

            {/* Current Plan - Compact Horizontal Layout */}
            <div className="flex flex-col sm:flex-row items-center justify-between bg-surface-container border border-outline-variant rounded-md p-md mb-lg">
              <div className="flex items-center gap-md">
                <span className="material-symbols-outlined text-primary text-3xl">workspace_premium</span>
                <div>
                  <p className="font-label-sm text-on-surface-variant uppercase tracking-wider mb-0">Current Plan</p>
                  <div className="flex items-center gap-sm">
                    <h3 className="font-headline-sm font-bold text-on-surface capitalize m-0">
                      {user?.role === 'super_admin' ? 'Enterprise' : user?.subscription_tier || 'Free'}
                    </h3>
                    <span className={`px-sm py-xs rounded text-[10px] font-bold uppercase tracking-wider ${user?.role === 'super_admin' || user?.subscription_status === 'active'
                      ? 'bg-emerald-500/10 text-emerald-500'
                      : 'bg-error-container text-error'
                      }`}>
                      {user?.role === 'super_admin' ? 'Active' : user?.subscription_status || 'Inactive'}
                    </span>
                  </div>
                </div>
              </div>

              {user?.role !== 'super_admin' && (
                <a
                  href="/pricing"
                  className="mt-sm sm:mt-0 bg-primary text-on-primary px-lg py-sm rounded-md font-label-md font-bold hover:bg-primary/90 transition-colors flex items-center gap-xs"
                >
                  Upgrade
                  <span className="material-symbols-outlined text-[18px]">arrow_forward</span>
                </a>
              )}
            </div>

            {/* Scan Quotas - Compact Grid */}
            <div>
              <h3 className="font-title-md font-bold text-on-surface mb-sm flex items-center gap-xs">
                <span className="material-symbols-outlined text-on-surface-variant text-[18px]">pie_chart</span>
                Scan Quotas
              </h3>

              {loadingQuotas ? (
                <div className="flex items-center justify-center py-xl text-on-surface-variant">
                  <span className="material-symbols-outlined animate-spin mr-sm">sync</span>
                  Loading...
                </div>
              ) : scanQuotas.length > 0 ? (
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-md">
                  {scanQuotas.filter(q => ['Quick', 'Advanced', 'Deep'].includes(q.scan_type)).map((q, idx) => {
                    const icon = q.scan_type.toLowerCase().includes('quick') ? 'bolt' :
                      q.scan_type.toLowerCase().includes('advanced') ? 'security' :
                        q.scan_type.toLowerCase().includes('deep') ? 'radar' : 'pie_chart';

                    return (
                      <div key={idx} className="bg-surface border border-outline-variant rounded-md p-sm flex items-center gap-sm shadow-sm">
                        <div className="bg-primary/10 text-primary p-xs rounded">
                          <span className="material-symbols-outlined text-xl">{icon}</span>
                        </div>
                        <div className="flex flex-col">
                          <span className="font-label-sm text-on-surface-variant uppercase">{q.scan_type}</span>
                          <span className="font-title-md font-bold text-on-surface leading-tight">
                            {q.allocated_count === -1 ? 'Unlimited' : Math.max(0, q.allocated_count - (q.used_count || 0))}
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="text-center text-on-surface-variant py-md bg-surface-container-low rounded-md border border-outline-variant/50 text-sm">
                  No scan quotas assigned.
                </div>
              )}
            </div>
          </div>

          {/* Billing History */}
          <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-lg shadow-sm">
            <h2 className="font-headline-md text-headline-md font-bold mb-md flex items-center gap-sm border-b pb-sm">
              <span className="material-symbols-outlined text-primary text-[22px]">history</span>
              Payment History
            </h2>

            {loadingBilling ? (
              <div className="flex items-center justify-center py-xl text-on-surface-variant font-body-sm">
                <span className="material-symbols-outlined animate-spin mr-sm">sync</span>
                Loading transactions...
              </div>
            ) : billingHistory.length === 0 ? (
              <div className="text-center py-xl text-on-surface-variant font-body-sm bg-surface-container-low rounded-lg border border-outline-variant/50">
                No past transactions found.
              </div>
            ) : (
              <div className="overflow-x-auto rounded-md border border-outline-variant">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-surface-container border-b border-outline-variant select-none">
                      {['Date', 'Plan', 'Amount', 'Status'].map((h, i) => (
                        <th 
                          key={h}
                          onClick={() => handleBillSort(h)}
                          className="p-sm font-label-sm text-on-surface-variant uppercase cursor-pointer hover:bg-surface-container-highest transition-colors group"
                        >
                          <div className="flex items-center gap-xs">
                            {h}
                            <span className={`material-symbols-outlined text-[14px] opacity-0 group-hover:opacity-50 transition-opacity ${sortBillCol === h ? 'opacity-100 group-hover:opacity-100 text-primary' : ''}`}>
                              {sortBillCol === h && sortBillDir === 'desc' ? 'arrow_downward' : 'arrow_upward'}
                            </span>
                          </div>
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {getSortedBilling().map((tx, idx) => (
                      <tr key={idx} className="border-b border-outline-variant/40 hover:bg-surface-container transition-colors text-sm">
                        <td className="p-sm text-on-surface">{new Date(tx.created_at).toLocaleDateString()}</td>
                        <td className="p-sm text-on-surface capitalize">{tx.tier_id}</td>
                        <td className="p-sm font-bold text-on-surface">${(tx.amount / 100).toFixed(2)}</td>
                        <td className="p-sm">
                          <span className={`px-xs py-[2px] rounded text-[10px] font-bold uppercase tracking-wider ${tx.status === 'success' ? 'bg-emerald-500/20 text-emerald-500' : 'bg-error-container text-error'
                            }`}>
                            {tx.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}


      {/* Profile Tab */}
      {activeTab === 'profile' && (
        <Profile />
      )}

      {/* Team Tab */}
      {activeTab === 'team' && isTeamAllowed && (
        <div className="w-full flex flex-col gap-lg">
          <div className="bg-surface-container-lowest border border-outline-variant rounded-xl overflow-hidden shadow-sm">
            <div className="p-6 border-b border-outline-variant flex justify-between items-center bg-surface-container/50">
              <h2 className="text-xl font-bold flex items-center text-on-surface">
                <span className="material-symbols-outlined text-primary mr-2">group</span>
                Active Team Members
              </h2>
              {(user?.role === 'org_admin' || user?.role === 'super_admin') && (
                <button
                  onClick={() => setShowAddMember(true)}
                  className="bg-primary hover:bg-primary/90 text-on-primary font-bold py-2 px-4 rounded flex items-center gap-2 transition-colors cursor-pointer border-0 shadow-sm text-sm"
                >
                  <span className="material-symbols-outlined text-[18px]">person_add</span>
                  Add New Member
                </button>
              )}
            </div>

            {loadingTeam ? (
              <div className="p-10 text-center text-on-surface-variant">Loading team members...</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="bg-surface-container-low text-on-surface-variant select-none">
                    <tr>
                      {['Name', 'Email', 'Assigned Role', 'Status', 'Actions'].map((h, i) => (
                        <th 
                          key={h}
                          onClick={() => handleTeamSort(h)}
                          className={`px-6 py-4 font-semibold ${i === 4 ? 'text-right' : ''} ${h !== 'Actions' ? 'cursor-pointer hover:bg-surface-container-highest transition-colors group' : ''}`}
                        >
                          <div className={`flex items-center gap-xs ${i === 4 ? 'justify-end' : ''}`}>
                            {h}
                            {h !== 'Actions' && (
                              <span className={`material-symbols-outlined text-[16px] opacity-0 group-hover:opacity-50 transition-opacity ${sortTeamCol === h ? 'opacity-100 group-hover:opacity-100 text-primary' : ''}`}>
                                {sortTeamCol === h && sortTeamDir === 'desc' ? 'arrow_downward' : 'arrow_upward'}
                              </span>
                            )}
                          </div>
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-outline-variant">
                    {getSortedTeam().map((member) => (
                      <tr key={member.id} className="hover:bg-surface-container/30 transition-colors">
                        <td className="px-6 py-4 font-medium text-on-surface">
                          {member.first_name || member.last_name ? `${member.first_name || ''} ${member.last_name || ''}`.trim() : 'N/A'}
                        </td>
                        <td className="px-6 py-4 font-medium text-on-surface">{member.email}</td>
                        <td className="px-6 py-4">
                          <span className="px-3 py-1 bg-surface-container rounded-full text-xs font-medium text-on-surface-variant capitalize">
                            {member.role.replace('_', ' ')}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <span className={`px-2 py-1 text-xs font-semibold rounded-full ${member.status === 'Active' ? 'bg-green-500/10 text-green-600' : 'bg-yellow-500/10 text-yellow-600'}`}>
                            {member.status}
                          </span>
                        </td>
                        <td className="px-6 py-4 flex justify-end gap-2">
                          <button
                            onClick={() => setEditingUser({ ...member, new_password: '' })}
                            className="text-primary hover:bg-primary/10 p-2 rounded transition-colors cursor-pointer border-0 bg-transparent flex items-center justify-center"
                            title="Edit User"
                          >
                            <span className="material-symbols-outlined text-[18px]">edit</span>
                          </button>
                          <button
                            onClick={() => setUserToDelete(member)}
                            className="text-error hover:bg-error/10 p-2 rounded transition-colors cursor-pointer border-0 bg-transparent flex items-center justify-center"
                            title="Remove User"
                          >
                            <span className="material-symbols-outlined text-[18px]">delete</span>
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Add New Member Modal Overlay */}
          {showAddMember && (user?.role === 'org_admin' || user?.role === 'super_admin') && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
              <div className="bg-surface-container-lowest border border-outline-variant rounded-xl overflow-hidden shadow-xl max-w-2xl w-full">
                <div className="p-6 border-b border-outline-variant bg-surface-container/50 flex justify-between items-center">
                  <h2 className="text-xl font-bold flex items-center text-on-surface">
                    <span className="material-symbols-outlined text-primary mr-2">person_add</span>
                    Add New Member
                  </h2>
                  <button
                    onClick={() => setShowAddMember(false)}
                    className="text-on-surface-variant hover:text-on-surface rounded-full p-1 transition-colors cursor-pointer border-0 bg-transparent"
                  >
                    <span className="material-symbols-outlined">close</span>
                  </button>
                </div>
                <div className="p-6">
                  <form onSubmit={handleInviteUser} className="flex flex-col gap-md">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-md">
                      <div>
                        <label className="block text-sm font-semibold text-on-surface mb-2">First Name</label>
                        <input
                          type="text"
                          value={newUserFirstName}
                          onChange={(e) => setNewUserFirstName(e.target.value)}
                          className="w-full bg-surface border border-outline-variant text-on-surface font-body-md px-4 py-3 rounded-lg focus:border-primary focus:ring-2 focus:ring-primary/20 focus:outline-none transition-all"
                          placeholder="John"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-semibold text-on-surface mb-2">Last Name</label>
                        <input
                          type="text"
                          value={newUserLastName}
                          onChange={(e) => setNewUserLastName(e.target.value)}
                          className="w-full bg-surface border border-outline-variant text-on-surface font-body-md px-4 py-3 rounded-lg focus:border-primary focus:ring-2 focus:ring-primary/20 focus:outline-none transition-all"
                          placeholder="Doe"
                        />
                      </div>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-md">
                      <div>
                        <label className="block text-sm font-semibold text-on-surface mb-2">Email Address</label>
                        <input
                          type="email"
                          required
                          value={newUserEmail}
                          onChange={(e) => setNewUserEmail(e.target.value)}
                          className="w-full bg-surface border border-outline-variant text-on-surface font-body-md px-4 py-3 rounded-lg focus:border-primary focus:ring-2 focus:ring-primary/20 focus:outline-none transition-all"
                          placeholder="user@example.com"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-semibold text-on-surface mb-2">Password</label>
                        <div className="relative">
                          <input
                            type={showNewUserPassword ? "text" : "password"}
                            value={newUserPassword}
                            onChange={(e) => setNewUserPassword(e.target.value)}
                            className="w-full bg-surface border border-outline-variant text-on-surface font-body-md px-4 py-3 pr-12 rounded-lg focus:border-primary focus:ring-2 focus:ring-primary/20 focus:outline-none transition-all"
                            placeholder="Leave blank for auto-generated"
                          />
                          <button
                            type="button"
                            onClick={() => setShowNewUserPassword(!showNewUserPassword)}
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-on-surface-variant hover:text-on-surface rounded-full p-1 transition-colors bg-transparent border-0 flex items-center justify-center cursor-pointer"
                          >
                            <span className="material-symbols-outlined text-[20px]">
                              {showNewUserPassword ? 'visibility_off' : 'visibility'}
                            </span>
                          </button>
                        </div>
                      </div>
                    </div>

                    <div className="flex flex-col sm:flex-row justify-between items-end gap-md mt-sm border-t border-outline-variant/50 pt-md">
                      <div className="flex-1 w-full sm:max-w-[200px]">
                        <label className="block text-sm font-semibold text-on-surface mb-2">Assign Role</label>
                        <select
                          value={newUserRole}
                          onChange={(e) => setNewUserRole(e.target.value)}
                          className="w-full bg-surface border border-outline-variant text-on-surface font-body-md px-4 py-3 rounded-lg focus:border-primary focus:ring-2 focus:ring-primary/20 focus:outline-none transition-all cursor-pointer"
                        >
                          <option value="soc_analyst">SOC Analyst</option>
                          <option value="executive_user">Executive User</option>
                        </select>
                      </div>
                      <div className="flex gap-sm w-full sm:w-auto">
                        <button
                          type="button"
                          onClick={() => setShowAddMember(false)}
                          className="w-full sm:w-auto px-6 py-2.5 font-bold rounded-lg border border-outline-variant bg-surface text-on-surface hover:bg-surface-container transition-colors cursor-pointer"
                        >
                          Cancel
                        </button>
                        <button
                          type="submit"
                          disabled={invitingUser}
                          className="w-full sm:w-auto min-w-[150px] bg-primary text-on-primary hover:bg-primary/90 hover:shadow-md font-bold px-6 py-2.5 rounded-lg transition-all cursor-pointer border-0 shadow-sm disabled:opacity-50 flex items-center justify-center"
                        >
                          {invitingUser ? 'Adding...' : 'Confirm & Add'}
                        </button>
                      </div>
                    </div>
                  </form>
                </div>
              </div>
            </div>
          )}

          {/* Edit Member Modal Overlay */}
          {editingUser && (user?.role === 'org_admin' || user?.role === 'super_admin') && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
              <div className="bg-surface-container-lowest border border-outline-variant rounded-xl overflow-hidden shadow-xl max-w-2xl w-full">
                <div className="p-6 border-b border-outline-variant bg-surface-container/50 flex justify-between items-center">
                  <h2 className="text-xl font-bold flex items-center text-on-surface">
                    <span className="material-symbols-outlined text-primary mr-2">manage_accounts</span>
                    Edit Member
                  </h2>
                  <button
                    onClick={() => setEditingUser(null)}
                    className="text-on-surface-variant hover:text-on-surface rounded-full p-1 transition-colors cursor-pointer border-0 bg-transparent"
                  >
                    <span className="material-symbols-outlined">close</span>
                  </button>
                </div>
                <div className="p-6">
                  <form onSubmit={handleUpdateUser} className="flex flex-col gap-md">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-md">
                      <div>
                        <label className="block text-sm font-semibold text-on-surface mb-2">First Name</label>
                        <input
                          type="text"
                          value={editingUser.first_name || ''}
                          onChange={(e) => setEditingUser({ ...editingUser, first_name: e.target.value })}
                          className="w-full bg-surface border border-outline-variant text-on-surface font-body-md px-4 py-3 rounded-lg focus:border-primary focus:ring-2 focus:ring-primary/20 focus:outline-none transition-all"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-semibold text-on-surface mb-2">Last Name</label>
                        <input
                          type="text"
                          value={editingUser.last_name || ''}
                          onChange={(e) => setEditingUser({ ...editingUser, last_name: e.target.value })}
                          className="w-full bg-surface border border-outline-variant text-on-surface font-body-md px-4 py-3 rounded-lg focus:border-primary focus:ring-2 focus:ring-primary/20 focus:outline-none transition-all"
                        />
                      </div>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-md">
                      <div>
                        <label className="block text-sm font-semibold text-on-surface mb-2">Email Address</label>
                        <input
                          type="email"
                          required
                          value={editingUser.email || ''}
                          onChange={(e) => setEditingUser({ ...editingUser, email: e.target.value })}
                          className="w-full bg-surface border border-outline-variant text-on-surface font-body-md px-4 py-3 rounded-lg focus:border-primary focus:ring-2 focus:ring-primary/20 focus:outline-none transition-all"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-semibold text-on-surface mb-2">Password</label>
                        <div className="relative">
                          <input
                            type={showNewUserPassword ? "text" : "password"}
                            value={editingUser.new_password || ''}
                            onChange={(e) => setEditingUser({ ...editingUser, new_password: e.target.value })}
                            className="w-full bg-surface border border-outline-variant text-on-surface font-body-md px-4 py-3 pr-12 rounded-lg focus:border-primary focus:ring-2 focus:ring-primary/20 focus:outline-none transition-all"
                            placeholder="Leave blank to keep unchanged"
                          />
                          <button
                            type="button"
                            onClick={() => setShowNewUserPassword(!showNewUserPassword)}
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-on-surface-variant hover:text-on-surface rounded-full p-1 transition-colors bg-transparent border-0 flex items-center justify-center cursor-pointer"
                          >
                            <span className="material-symbols-outlined text-[20px]">
                              {showNewUserPassword ? 'visibility_off' : 'visibility'}
                            </span>
                          </button>
                        </div>
                      </div>
                    </div>
                    <div className="flex flex-col sm:flex-row justify-between items-end gap-md mt-sm border-t border-outline-variant/50 pt-md">
                      <div className="flex-1 w-full sm:max-w-[200px]">
                        <label className="block text-sm font-semibold text-on-surface mb-2">Assign Role</label>
                        <select
                          value={editingUser.role}
                          onChange={(e) => setEditingUser({ ...editingUser, role: e.target.value })}
                          className="w-full bg-surface border border-outline-variant text-on-surface font-body-md px-4 py-3 rounded-lg focus:border-primary focus:ring-2 focus:ring-primary/20 focus:outline-none transition-all cursor-pointer"
                        >
                          <option value="soc_analyst">SOC Analyst</option>
                          <option value="executive_user">Executive User</option>
                        </select>
                      </div>
                      <div className="flex gap-sm w-full sm:w-auto">
                        <button
                          type="button"
                          onClick={() => setEditingUser(null)}
                          className="w-full sm:w-auto px-6 py-2.5 font-bold rounded-lg border border-outline-variant bg-surface text-on-surface hover:bg-surface-container transition-colors cursor-pointer"
                        >
                          Cancel
                        </button>
                        <button
                          type="submit"
                          disabled={updatingUser}
                          className="w-full sm:w-auto min-w-[150px] bg-primary text-on-primary hover:bg-primary/90 hover:shadow-md font-bold px-6 py-2.5 rounded-lg transition-all cursor-pointer border-0 shadow-sm disabled:opacity-50 flex items-center justify-center"
                        >
                          {updatingUser ? 'Saving...' : 'Save Changes'}
                        </button>
                      </div>
                    </div>
                  </form>
                </div>
              </div>
            </div>
          )}

          {/* Delete Confirmation Modal */}
          {userToDelete && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
              <div className="bg-surface-container-lowest border border-outline-variant rounded-xl overflow-hidden shadow-xl max-w-md w-full">
                <div className="p-6">
                  <div className="flex items-center justify-center w-12 h-12 rounded-full bg-error/10 mb-4 mx-auto">
                    <span className="material-symbols-outlined text-error text-2xl">warning</span>
                  </div>
                  <h3 className="text-xl font-bold text-center text-on-surface mb-2">Remove Team Member?</h3>
                  <p className="text-center text-on-surface-variant mb-6">
                    Are you sure you want to remove <strong>{userToDelete.email}</strong> from the organization? This action cannot be undone and they will lose all access immediately.
                  </p>
                  <div className="flex gap-sm w-full">
                    <button
                      onClick={() => setUserToDelete(null)}
                      className="w-1/2 px-6 py-2.5 font-bold rounded-lg border border-outline-variant bg-surface text-on-surface hover:bg-surface-container transition-colors cursor-pointer"
                    >
                      Cancel
                    </button>
                    <button
                      onClick={executeDeleteUser}
                      disabled={deletingUser}
                      className="w-1/2 bg-error text-white hover:bg-error/90 hover:shadow-md font-bold px-6 py-2.5 rounded-lg transition-all cursor-pointer border-0 shadow-sm disabled:opacity-50 flex items-center justify-center"
                    >
                      {deletingUser ? 'Removing...' : 'Remove User'}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* API Keys Tab (Placeholder) */}
      {activeTab === 'apiKeys' && isApiKeysAllowed && (
        <div className="w-full">
          <div className="bg-surface-container-lowest border border-outline-variant rounded-lg shadow-sm mb-lg overflow-hidden relative min-h-[400px] flex items-center justify-center">

            {/* Background decorative elements */}
            <div className="absolute top-0 left-0 w-full h-full overflow-hidden pointer-events-none">
              <div className="absolute -top-[20%] -right-[10%] w-[50%] h-[60%] bg-primary/5 rounded-full blur-3xl"></div>
              <div className="absolute -bottom-[20%] -left-[10%] w-[40%] h-[50%] bg-primary/5 rounded-full blur-3xl"></div>
              {/* Subtle grid pattern overlay */}
              <div className="absolute inset-0" style={{ backgroundImage: 'radial-gradient(var(--tw-colors-outline-variant) 1px, transparent 1px)', backgroundSize: '32px 32px', opacity: 0.1 }}></div>
            </div>

            <div className="relative z-10 flex flex-col items-center text-center max-w-lg mx-auto p-8">

              <div className="mb-6 relative">
                <div className="absolute inset-0 bg-primary/20 blur-xl rounded-full"></div>
                <div className="h-20 w-20 rounded-2xl bg-gradient-to-br from-primary to-primary/80 flex items-center justify-center text-on-primary shadow-lg shadow-primary/30 relative z-10 border border-white/20">
                  <span className="material-symbols-outlined text-[40px]">vpn_key</span>
                </div>
              </div>

              <span className="bg-surface-variant text-on-surface-variant text-[10px] uppercase tracking-widest font-bold px-3 py-1 rounded-full mb-4 border border-outline-variant">
                Coming Soon
              </span>

              <h2 className="font-headline-md text-on-surface font-bold mb-3 text-3xl">
                Developer API Access
              </h2>

              <p className="font-body-md text-on-surface-variant leading-relaxed mb-8">
                We are actively building a robust, high-performance API for LarShield. Soon, you will be able to programmatically manage scans, retrieve security reports, and integrate seamlessly with your CI/CD pipelines.
              </p>

              <button
                type="button"
                onClick={() => toast.success("You have been added to the early access waitlist!")}
                className="bg-surface-container hover:bg-surface-container-high text-on-surface border border-outline-variant px-6 py-3 rounded-lg font-bold transition-all shadow-sm flex items-center gap-2 cursor-pointer active:scale-95"
              >
                <span className="material-symbols-outlined text-[18px]">notifications_active</span>
                Notify Me When Live
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Reschedule Demo Call Modal */}
      {rescheduleModal.isOpen && (
        <div className="fixed inset-0 z-[9999] flex items-center justify-center p-4">
          <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-sm" onClick={() => setRescheduleModal({ ...rescheduleModal, isOpen: false })}></div>
          <div className="relative bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-2xl max-w-md w-full p-6 z-10 animate-slide-up text-left font-sans">
            <div className="flex justify-between items-center pb-3 border-b border-slate-100 dark:border-slate-800">
              <h3 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <span className="material-symbols-outlined text-primary">edit_calendar</span>
                Reschedule Demo Call
              </h3>
              <button onClick={() => setRescheduleModal({ ...rescheduleModal, isOpen: false })} className="text-slate-400 hover:text-slate-600 border-0 bg-transparent cursor-pointer p-1">
                <span className="material-symbols-outlined text-[20px]">close</span>
              </button>
            </div>
            <form onSubmit={handleSaveReschedule} className="mt-4 flex flex-col gap-4">
              <div>
                <label className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block mb-1">Lead Email</label>
                <input type="text" disabled value={rescheduleModal.email} className="w-full bg-slate-100 border border-slate-200 rounded-lg p-2.5 text-xs text-slate-700 font-bold" />
              </div>
              <div>
                <label className="text-xs font-bold text-slate-700 dark:text-slate-300 block mb-1">New Meeting Date</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. August 28, 2026"
                  value={rescheduleModal.meetingDate}
                  onChange={(e) => setRescheduleModal({ ...rescheduleModal, meetingDate: e.target.value })}
                  className="w-full border border-slate-300 rounded-lg p-2.5 text-xs text-slate-900 dark:text-white dark:bg-slate-800 focus:outline-none focus:border-primary"
                />
              </div>
              <div>
                <label className="text-xs font-bold text-slate-700 dark:text-slate-300 block mb-1">New Meeting Time</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. 04:00 PM"
                  value={rescheduleModal.meetingTime}
                  onChange={(e) => setRescheduleModal({ ...rescheduleModal, meetingTime: e.target.value })}
                  className="w-full border border-slate-300 rounded-lg p-2.5 text-xs text-slate-900 dark:text-white dark:bg-slate-800 focus:outline-none focus:border-primary"
                />
              </div>
              <div>
                <label className="text-xs font-bold text-slate-700 dark:text-slate-300 block mb-1">Update Status</label>
                <select
                  value={rescheduleModal.status}
                  onChange={(e) => setRescheduleModal({ ...rescheduleModal, status: e.target.value })}
                  className="w-full border border-slate-300 rounded-lg p-2.5 text-xs text-slate-900 dark:text-white dark:bg-slate-800 focus:outline-none focus:border-primary cursor-pointer"
                >
                  <option value="rescheduled">Rescheduled</option>
                  <option value="pending">Pending</option>
                  <option value="completed">Completed / Conducted</option>
                  <option value="cancelled">Cancelled / Not Conducted</option>
                </select>
              </div>
              <div className="flex justify-end gap-2 pt-3 border-t border-slate-100 dark:border-slate-800">
                <button
                  type="button"
                  onClick={() => setRescheduleModal({ ...rescheduleModal, isOpen: false })}
                  className="px-4 py-2 rounded-lg text-xs font-bold text-slate-600 border border-slate-300 hover:bg-slate-100 cursor-pointer bg-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg text-xs font-bold text-white bg-primary hover:brightness-110 shadow-sm cursor-pointer border-0"
                >
                  Save & Update
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

    </div>
  );
};
