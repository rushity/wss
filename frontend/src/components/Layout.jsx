import React, { useState, useEffect, useRef } from 'react';
import { Link, NavLink, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from './AuthContext';

export const getInitials = (userData) => {
  if (!userData) return 'DP';
  const firstName = (userData.first_name || '').trim();
  const lastName = (userData.last_name || '').trim();
  if (firstName || lastName) {
    const f = firstName.charAt(0);
    const l = lastName.charAt(0);
    if (f && l) return `${f}${l}`.toUpperCase();
    if (f) return f.toUpperCase();
    if (l) return l.toUpperCase();
  }
  const name = (userData.name || userData.full_name || '').trim();
  if (name) {
    const parts = name.split(/\s+/);
    if (parts.length >= 2) {
      return `${parts[0].charAt(0)}${parts[parts.length - 1].charAt(0)}`.toUpperCase();
    }
    return name.substring(0, 2).toUpperCase();
  }
  const email = (userData.email || '').trim();
  if (email) {
    const username = email.split('@')[0];
    const parts = username.split(/[._-]/);
    if (parts.length >= 2 && parts[0] && parts[1]) {
      return `${parts[0].charAt(0)}${parts[1].charAt(0)}`.toUpperCase();
    }
    if (username.length >= 2) {
      return username.substring(0, 2).toUpperCase();
    }
    return username.charAt(0).toUpperCase();
  }
  return 'DP';
};

export const Layout = ({ children }) => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const searchParams = new URLSearchParams(location.search);
  const urlQuery = searchParams.get('q') || '';
  const [globalSearchQuery, setGlobalSearchQuery] = useState(urlQuery);

  useEffect(() => {
    setGlobalSearchQuery(urlQuery);
  }, [urlQuery]);

  // Always scroll to top of page on route change
  useEffect(() => {
    window.scrollTo(0, 0);
    const mainElement = document.querySelector('main');
    if (mainElement) mainElement.scrollTop = 0;
  }, [location.pathname]);

  const [isDemoMode, setIsDemoMode] = useState(false);
  const [isProfileOpen, setIsProfileOpen] = useState(false);
  const [isNotificationsOpen, setIsNotificationsOpen] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const [loadingNotifications, setLoadingNotifications] = useState(false);
  const [hasUnreadNotifications, setHasUnreadNotifications] = useState(false);

  const notificationsRef = useRef(null);
  const profileRef = useRef(null);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (notificationsRef.current && !notificationsRef.current.contains(event.target)) {
        setIsNotificationsOpen(false);
      }
      if (profileRef.current && !profileRef.current.contains(event.target)) {
        setIsProfileOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, []);
  
  const fetchNotifications = async () => {
    if (!user) return;
    setLoadingNotifications(true);
    try {
      const token = localStorage.getItem('wss_token') || sessionStorage.getItem('wss_token');
      const res = await fetch('/api/auth/notifications', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        const fetched = data.notifications || [];
        
        const lastSeenId = localStorage.getItem('last_seen_notification_id');
        
        if (fetched.length > 0 && String(fetched[0].id) !== lastSeenId) {
          setHasUnreadNotifications(true);
        }
        
        setNotifications(fetched);
      }
    } catch (err) {
      console.error("Failed to fetch notifications:", err);
    } finally {
      setLoadingNotifications(false);
    }
  };

  useEffect(() => {
    if (user) {
      fetchNotifications();
      const interval = setInterval(fetchNotifications, 60000); // refresh every minute
      return () => clearInterval(interval);
    }
  }, [user]);
  useEffect(() => {
    setIsDemoMode(!!window.WSS_DEMO_MODE);
    const checkInterval = setInterval(() => {
      setIsDemoMode(!!window.WSS_DEMO_MODE);
    }, 1000);
    return () => clearInterval(checkInterval);
  }, []);

  // Force removal of dark theme and clear localStorage keys
  useEffect(() => {
    document.documentElement.classList.remove('dark');
    localStorage.removeItem('color-theme');
  }, []);

  const [impersonationToken, setImpersonationToken] = useState(null);
  const [organizations, setOrganizations] = useState([]);

  useEffect(() => {
    setImpersonationToken(localStorage.getItem('original_admin_token'));
  }, [location.pathname]);

  useEffect(() => {
    const fetchOrgs = async () => {
      const adminToken = localStorage.getItem('original_admin_token') || localStorage.getItem('wss_token') || sessionStorage.getItem('wss_token');
      // Only attempt if they might be an admin
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

  const handleLogout = () => {
    const isSuperAdmin = user?.role === 'super_admin' || sessionStorage.getItem('superAdminAuth') === 'true';
    logout();
    sessionStorage.removeItem('superAdminAuth');
    localStorage.removeItem('original_admin_token');
    navigate(isSuperAdmin ? '/' : '/login');
  };

  let navItems = [];
  
  if (user?.role === 'executive_user') {
    navItems = [
      { to: '/scans/history', label: 'Organization Reports', icon: 'analytics' },
      { to: '/settings', label: 'Settings', icon: 'settings' },
    ];
  } else {
    navItems = [
      { to: '/dashboard', label: 'Dashboard', icon: 'dashboard' },
      { to: '/scans/new', label: 'New Scan', icon: 'security' },
      { to: '/scans/history', label: 'Reports', icon: 'analytics' },
      { to: '/scans/results', label: 'Vulnerabilities', icon: 'bug_report' },
      { to: '/settings', label: 'Settings', icon: 'settings' },
    ];
  }

  if (user?.role === 'super_admin') {
    navItems.push({ to: '/super-admin', label: 'Global Management', icon: 'admin_panel_settings' });
  } else if (user?.role === 'admin') {
    navItems.push({ to: '/admin', label: 'Global Management', icon: 'admin_panel_settings' });
  } else if (user?.role === 'support_engineer') {
    navItems.push({ to: '/support', label: 'Global Management', icon: 'support_agent' });
  }

  return (
    <div className="bg-background text-on-background font-body-md text-body-md antialiased min-h-screen flex flex-col md:flex-row w-full transition-colors duration-300">
      
      {/* SideNavBar (Stitch Layout) */}
      <nav className="bg-white dark:bg-inverse-surface h-screen w-64 flex-col fixed left-0 top-0 border-r border-outline-variant dark:border-outline z-40 hidden md:flex py-lg px-md gap-sm text-left">
        
        {/* Header Branding */}
        <div className="mb-xl flex flex-col gap-sm">
          <div className="flex items-center gap-sm">
            <div className="h-12 flex items-center justify-center shrink-0">
              <img src="/logo.png" alt="LarShield Logo" className="h-full object-contain" />
            </div>
            <div className="flex flex-col justify-center">
              <h1 className="font-extrabold tracking-tight m-0 text-[18px] leading-none flex items-center">
                <span className="text-[#0b132a] dark:text-white">Lar</span>
                <span className="text-[#5856d6]">Shield</span>
              </h1>
              <p className="text-[12px] text-[#64748b] dark:text-slate-400 uppercase tracking-[0.14em] m-0 font-medium leading-tight mt-1">
                {user?.role === 'super_admin' ? 'SUPER ADMIN' : 
                 user?.role === 'admin' ? 'ADMIN' : 
                 user?.role === 'support_engineer' ? 'SUPPORT ENGINEER' : 
                 user?.role === 'executive_user' ? 'EXECUTIVE USER' :
                 user?.role === 'soc_analyst' ? 'SOC ANALYST' :
                 'ORG ADMIN'}
              </p>
            </div>
          </div>
          
          {user?.role !== 'executive_user' && (
            <NavLink 
              to="/scans/new" 
              className="mt-md w-full bg-primary text-on-primary rounded-lg py-sm px-md font-label-md text-label-md flex items-center justify-center gap-xs hover:opacity-90 transition-opacity border-0 cursor-pointer"
              style={{ textDecoration: 'none' }}
            >
              <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>add</span>
              Quick Scan
            </NavLink>
          )}
        </div>

        {/* Navigation Links */}
        <div className="flex flex-col gap-base flex-1">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) => 
                `flex items-center gap-sm px-sm py-sm rounded-lg transition-colors cursor-pointer transition-all duration-200 border-0 ${
                  isActive 
                    ? 'text-primary dark:text-primary-fixed-dim font-bold bg-surface-container-high dark:bg-on-secondary-fixed-variant' 
                    : 'text-on-surface-variant dark:text-surface-variant hover:bg-surface-container-high dark:hover:bg-on-secondary-fixed-variant'
                }`
              }
              style={{ textDecoration: 'none' }}
            >
              <span className="material-symbols-outlined">{item.icon}</span>
              <span className="font-label-md text-label-md">{item.label}</span>
            </NavLink>
          ))}

          {/* Help Page Link */}
          <NavLink 
            to="/help"
            className={({ isActive }) => 
              `flex items-center gap-sm px-sm py-sm rounded-lg transition-colors cursor-pointer transition-all duration-200 mt-auto border-0 ${
                isActive 
                  ? 'text-primary dark:text-primary-fixed-dim font-bold bg-surface-container-high dark:bg-on-secondary-fixed-variant' 
                  : 'text-on-surface-variant dark:text-surface-variant hover:bg-surface-container-high dark:hover:bg-on-secondary-fixed-variant'
              }`
            }
            style={{ textDecoration: 'none' }}
          >
            <span className="material-symbols-outlined">help</span>
            <span className="font-label-md text-label-md">Help</span>
          </NavLink>
        </div>


        {/* Sidebar Status / Log Out */}
        <div className="mt-md pt-md border-t border-outline-variant">
          <button 
            onClick={handleLogout}
            className="w-full flex items-center gap-sm px-sm py-sm rounded-lg text-on-surface-variant dark:text-surface-variant hover:bg-surface-container-high dark:hover:bg-on-secondary-fixed-variant transition-colors cursor-pointer transition-all duration-200 border-0 bg-transparent text-left"
          >
            <span className="material-symbols-outlined">logout</span>
            <span className="font-label-md text-label-md">Log Out</span>
          </button>
        </div>
      </nav>

      {/* TopNavBar (Stitch Layout) */}
      <header className="bg-surface/80 dark:bg-inverse-surface/80 backdrop-blur-md fixed top-0 w-full z-50 border-b border-outline-variant dark:border-outline shadow-sm flex justify-between items-center h-16 px-gutter max-w-container-max mx-auto md:w-[calc(100%-16rem)] md:left-64 md:px-lg">
        
        {/* Mobile Hamburger menu */}
        <div className="md:hidden flex items-center gap-sm">
          <span className="material-symbols-outlined text-primary cursor-pointer">menu</span>
          <div className="flex items-center gap-xs">
            <img src="/logo.png" alt="LarShield Logo" className="h-7 w-7 object-contain" />
            <div className="flex flex-col justify-center">
              <span className="font-extrabold tracking-tight text-[15px] leading-none flex items-center">
                <span className="text-[#0b132a] dark:text-white">Lar</span>
                <span className="text-[#5856d6]">Shield</span>
              </span>
              <span className="text-[10px] text-[#64748b] dark:text-slate-400 uppercase tracking-[0.12em] font-medium leading-none mt-0.5">
                {user?.role === 'super_admin' ? 'SUPER ADMIN' : 
                 user?.role === 'admin' ? 'ADMIN' : 
                 user?.role === 'support_engineer' ? 'SUPPORT ENGINEER' : 
                 user?.role === 'executive_user' ? 'EXECUTIVE USER' :
                 user?.role === 'soc_analyst' ? 'SOC ANALYST' :
                 'ORG ADMIN'}
              </span>
            </div>
          </div>
        </div>

        {/* Search Bar Utility */}
        <div className="hidden md:flex flex-1 max-w-md ml-xl relative">
          <span className="material-symbols-outlined absolute left-sm top-1/2 -translate-y-1/2 text-outline" style={{ fontSize: '20px' }}>search</span>
          <input 
            className="w-full bg-surface-container-lowest border border-outline-variant rounded-lg pl-xl pr-sm py-xs font-body-sm text-body-sm text-on-surface focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all placeholder:text-outline" 
            placeholder="Search vulnerabilities, reports, assets..." 
            type="text"
            value={globalSearchQuery}
            onChange={(e) => setGlobalSearchQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                if (globalSearchQuery.trim()) {
                  navigate(`/scans/history?q=${encodeURIComponent(globalSearchQuery.trim())}`);
                } else {
                  navigate(`/scans/history`);
                }
              }
            }}
          />
        </div>

        {/* Right Nav Icons / Mode Selector */}
        <div className="flex items-center gap-gutter ml-auto">

          {/* Organization Display / Admin Dropdown */}
          {(user?.role === 'admin' || user?.role === 'super_admin' || impersonationToken) && organizations.length > 0 ? (
            <div className="flex items-center">
              <select
                className="bg-surface-container border border-outline-variant rounded-md px-sm py-xs font-label-sm text-on-surface focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary max-w-[200px] truncate"
                value={impersonationToken ? (user?.org_id || '') : ''}
                onChange={async (e) => {
                  const targetOrgId = e.target.value;
                  if (!targetOrgId) {
                    // Return to Admin
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
                      window.location.href = location.pathname; // Reload current page with new token
                    }
                  } catch (err) {
                    console.error("Failed to impersonate from dropdown:", err);
                  }
                }}
              >
                <option value="">-- Return to Admin --</option>
                {organizations.map(org => (
                  <option key={org.id} value={org.id}>{org.name}</option>
                ))}
              </select>
            </div>
          ) : user?.org_name ? (
            <div className="hidden md:flex items-center gap-xs font-label-md text-label-md text-on-surface bg-surface-container-low px-sm py-xs rounded-md border border-outline-variant">
              <span className="material-symbols-outlined text-[18px] text-primary">domain</span>
              <span className="font-bold">{user.org_name}</span>
            </div>
          ) : null}
          
          {/* Active Status Badge */}
          {isDemoMode ? (
            <div className="hidden md:inline-flex items-center gap-xs bg-yellow-500/10 border border-yellow-500/30 rounded-full px-sm py-[2px] font-label-sm text-label-sm text-yellow-600 dark:text-yellow-500 font-bold uppercase tracking-wider">
              <span className="w-2 h-2 rounded-full bg-yellow-500 animate-pulse"></span> Sandbox Mode
            </div>
          ) : (
            <div className="hidden md:inline-flex items-center gap-xs bg-green-500/10 border border-green-500/30 rounded-full px-sm py-[2px] font-label-sm text-label-sm text-green-600 dark:text-green-500 font-bold uppercase tracking-wider">
              <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span> Connected
            </div>
          )}



          {/* Profile & Controls */}
          <div className="flex items-center gap-sm">
            <div className="relative" ref={notificationsRef}>
              <button 
                onClick={() => {
                  const willOpen = !isNotificationsOpen;
                  setIsNotificationsOpen(willOpen);
                  setIsProfileOpen(false);
                  if (willOpen) {
                    setHasUnreadNotifications(false);
                    if (notifications.length > 0) {
                      localStorage.setItem('last_seen_notification_id', String(notifications[0].id));
                    }
                  }
                }}
                className="text-on-surface-variant dark:text-surface-variant hover:text-primary transition-colors duration-200 active:opacity-80 transition-all flex items-center justify-center relative border-0 bg-transparent cursor-pointer"
              >
                <span className="material-symbols-outlined text-[26px]">notifications</span>
                {hasUnreadNotifications && (
                  <span className="absolute top-0 right-0 flex h-2.5 w-2.5">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-error opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-error border-[1.5px] border-white dark:border-inverse-surface"></span>
                  </span>
                )}
              </button>
              
              {isNotificationsOpen && (
                <div className="absolute right-0 mt-sm w-80 bg-surface border border-outline-variant rounded-xl shadow-xl z-50 flex flex-col overflow-hidden">
                  <div className="px-md py-md border-b border-outline-variant bg-surface/95 backdrop-blur-sm flex justify-between items-center z-10 shrink-0">
                    <h3 className="font-label-lg text-label-lg font-bold text-on-surface m-0 flex items-center gap-xs">
                      <span className="material-symbols-outlined text-primary text-xl">notifications</span>
                      Notifications
                    </h3>
                    <button 
                      onClick={fetchNotifications} 
                      className="border border-outline-variant/50 bg-surface-container-lowest hover:bg-surface-container rounded-full w-8 h-8 flex items-center justify-center cursor-pointer transition-all text-on-surface-variant hover:text-primary shadow-sm"
                      title="Refresh Notifications"
                    >
                      <span className={"material-symbols-outlined text-base" + (loadingNotifications ? " animate-spin" : "")}>sync</span>
                    </button>
                  </div>
                  
                  <div className="flex flex-col bg-surface-container-lowest overflow-hidden">
                    {loadingNotifications && notifications.length === 0 ? (
                      <div className="p-xl flex-1 flex flex-col justify-center items-center text-on-surface-variant font-body-sm gap-sm">
                        <span className="material-symbols-outlined animate-spin text-3xl text-primary/60">sync</span>
                        <span>Loading notifications...</span>
                      </div>
                    ) : notifications.length === 0 ? (
                      <div className="p-xl flex-1 flex flex-col justify-center items-center text-on-surface-variant font-body-sm gap-xs text-center">
                        <div className="w-12 h-12 rounded-full bg-surface-container flex items-center justify-center mb-sm shadow-inner border border-outline-variant/30">
                          <span className="material-symbols-outlined text-3xl text-on-surface-variant/60">notifications_off</span>
                        </div>
                        <span className="font-bold text-on-surface font-label-md">All Caught Up!</span>
                        <span className="text-xs opacity-80 mt-1">You have no new notifications right now.</span>
                      </div>
                    ) : (
                      notifications.slice(0, 3).map(n => (
                        <div key={n.id} className="flex gap-md p-md border-b border-outline-variant/40 hover:bg-surface-container-low transition-colors cursor-default text-left group">
                          <div className={`w-10 h-10 rounded-full flex items-center justify-center shrink-0 shadow-sm ${n.bg || 'bg-primary/10'}`}>
                            <span className={`material-symbols-outlined text-[20px] ${n.color || 'text-primary'}`}>{n.icon}</span>
                          </div>
                          <div className="flex flex-col flex-1 justify-center">
                            <span className="font-label-md text-label-md font-bold text-on-surface group-hover:text-primary transition-colors">{n.title}</span>
                            <span className="font-body-sm text-[13px] text-on-surface-variant leading-snug mt-[2px]">{n.message}</span>
                            <span className="font-label-sm text-[11px] text-on-surface-variant/60 mt-xs uppercase tracking-wider">{new Date(n.timestamp).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</span>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>
            
            {!user && (
              <button className="flex items-center gap-xs text-primary font-label-md text-label-md hover:bg-primary/5 px-sm py-xs rounded-lg transition-colors border-0 bg-transparent cursor-pointer">
                <span className="font-bold">Book Demo</span>
                <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>calendar_today</span>
              </button>
            )}

            {user && (
              <div className="relative ml-sm" ref={profileRef}>
                <button 
                  onClick={() => {
                    setIsProfileOpen(!isProfileOpen);
                    setIsNotificationsOpen(false);
                  }}
                  className="flex items-center gap-xs border-0 bg-transparent cursor-pointer hover:opacity-80 transition-opacity"
                >
                  <div className="w-8 h-8 rounded-full bg-primary/10 text-primary border border-primary/20 flex items-center justify-center font-bold text-xs uppercase shadow-sm">
                    {getInitials(user)}
                  </div>
                  <span className="hidden lg:inline text-xs font-semibold text-on-surface-variant dark:text-surface-variant">
                    {user.first_name || user.last_name ? `${user.first_name || ''} ${user.last_name || ''}`.trim() : user.email.split('@')[0]}
                  </span>
                </button>
                
                {isProfileOpen && (
                  <div className="absolute right-0 mt-xs w-52 bg-surface border border-outline-variant rounded-lg shadow-lg overflow-hidden z-50">
                    <div className="px-md py-sm border-b border-outline-variant bg-surface-container-low flex items-center gap-sm">
                      <div className="w-9 h-9 rounded-full bg-primary/10 text-primary border border-primary/20 flex items-center justify-center font-bold text-sm uppercase shrink-0">
                        {getInitials(user)}
                      </div>
                      <div className="flex flex-col min-w-0">
                        <p className="font-label-md text-label-md font-bold text-on-surface truncate m-0">
                          {user.first_name || user.last_name ? `${user.first_name || ''} ${user.last_name || ''}`.trim() : user.email}
                        </p>
                        <p className="font-body-sm text-[11px] text-on-surface-variant capitalize m-0 truncate">{(user.role || 'User').replace(/_/g, ' ')}</p>
                      </div>
                    </div>
                    <div className="p-xs">
                      <button 
                        onClick={() => {
                          setIsProfileOpen(false);
                          navigate('/settings');
                        }}
                        className="w-full text-left px-sm py-xs font-label-md text-label-md text-on-surface hover:bg-surface-container rounded transition-colors flex items-center gap-xs border-0 bg-transparent cursor-pointer"
                      >
                        <span className="material-symbols-outlined text-[18px]">person</span>
                        My Profile
                      </button>

                      <button 
                        onClick={handleLogout}
                        className="w-full text-left px-sm py-xs font-label-md text-label-md text-error hover:bg-error/10 rounded transition-colors flex items-center gap-xs border-0 bg-transparent cursor-pointer mt-xs"
                      >
                        <span className="material-symbols-outlined text-[18px]">logout</span>
                        Logout
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Main Content Render Area */}
      <main className="flex-grow pt-[64px] md:pl-64 min-h-screen bg-background pb-xl w-full text-left">
        {impersonationToken && (
          <div className="bg-primary text-white px-md py-sm flex justify-between items-center shadow-md mx-md md:mx-xl mt-md md:mt-0 mb-sm rounded-lg animate-fade-in">
            <div className="flex items-center gap-sm">
              <span className="material-symbols-outlined text-[20px]">vpn_key</span>
              <span className="font-bold text-[14px]">Impersonation Mode Active</span>
              <span className="text-[13px] opacity-90 border-l border-white/30 pl-sm ml-sm">
                You are currently viewing data for <strong>{user?.org_name || organizations.find(o => String(o.id) === String(user?.org_id))?.name || 'this organization'}</strong>.
              </span>
            </div>
            <button 
              onClick={handleReturnToAdmin} 
              className="bg-white text-primary hover:bg-surface-container transition-colors px-3 py-1.5 rounded-md font-bold text-[12px] border-0 cursor-pointer shadow-sm flex items-center gap-xs shrink-0"
            >
              <span className="material-symbols-outlined text-[16px]">exit_to_app</span>
              Return
            </button>
          </div>
        )}
        <div className="px-md py-sm md:px-xl md:py-md max-w-container-max mx-auto flex flex-col gap-gutter">
          {children}
        </div>
      </main>

    </div>
  );
};
