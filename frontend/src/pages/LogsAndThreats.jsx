import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../components/AuthContext';
import { ShieldAlert, Search, Download, RefreshCw, List, ArrowLeft } from 'lucide-react';

const LogsAndThreats = () => {
  const { user, loading: authLoading } = useAuth();
  const [trends, setTrends] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  // Dedicated Full Page Audit Logs State
  const [isFullLogsView, setIsFullLogsView] = useState(false);
  const [allLogs, setAllLogs] = useState([]);
  const [loadingAllLogs, setLoadingAllLogs] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  
  const [sortLogCol, setSortLogCol] = useState('Timestamp');
  const [sortLogDir, setSortLogDir] = useState('desc');

  const fetchStats = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('wss_token');
      const res = await fetch('/api/auth/global-stats', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (res.ok) {
        const data = await res.json();
        setTrends(data.trends || []);
        setAuditLogs(data.audit_logs || []);
      }
    } catch (err) {
      console.error('Failed to fetch stats', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchAllAuditLogs = async () => {
    setLoadingAllLogs(true);
    try {
      const token = localStorage.getItem('wss_token');
      const res = await fetch('/api/auth/audit-logs?limit=500', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (res.ok) {
        const data = await res.json();
        setAllLogs(data.audit_logs || []);
      }
    } catch (err) {
      console.error('Failed to fetch all audit logs', err);
    } finally {
      setLoadingAllLogs(false);
    }
  };

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 5000);
    return () => clearInterval(interval);
  }, []);

  const openFullLogsView = () => {
    setIsFullLogsView(true);
    fetchAllAuditLogs();
  };

  const closeFullLogsView = () => {
    setIsFullLogsView(false);
  };

  const filteredAllLogs = allLogs.filter(log => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      (log.action && log.action.toLowerCase().includes(q)) ||
      (log.user_email && log.user_email.toLowerCase().includes(q)) ||
      (log.target_name && log.target_name.toLowerCase().includes(q)) ||
      (log.target_id && log.target_id.toLowerCase().includes(q))
    );
  });

  const handleLogSort = (column) => {
    if (sortLogCol === column) {
      setSortLogDir(sortLogDir === 'asc' ? 'desc' : 'asc');
    } else {
      setSortLogCol(column);
      setSortLogDir('desc'); 
    }
  };

  const getSortedLogs = () => {
    return [...filteredAllLogs].sort((a, b) => {
      let aVal, bVal;
      switch (sortLogCol) {
        case 'Timestamp': aVal = new Date(a.timestamp).getTime(); bVal = new Date(b.timestamp).getTime(); break;
        case 'User': aVal = a.user_email || a.admin_id || ''; bVal = b.user_email || b.admin_id || ''; break;
        case 'Action': aVal = a.action || ''; bVal = b.action || ''; break;
        case 'Target': aVal = a.target_name || a.target_id || ''; bVal = b.target_name || b.target_id || ''; break;
        default: return 0;
      }
      if (aVal < bVal) return sortLogDir === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortLogDir === 'asc' ? 1 : -1;
      return 0;
    });
  };

  const exportLogsToCSV = () => {
    if (!filteredAllLogs.length) return;
    const headers = ["Timestamp", "User Email", "Action", "Target"];
    const rows = filteredAllLogs.map(l => [
      `"${new Date(l.timestamp).toLocaleString()}"`,
      `"${l.user_email || 'System'}"`,
      `"${(l.action || '').replace(/"/g, '""')}"`,
      `"${(l.target_name || l.target_id || '').replace(/"/g, '""')}"`
    ]);
    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(e => e.join(","))].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `audit_logs_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const isMasterAuthorized = sessionStorage.getItem('superAdminAuth') === 'true';

  if (authLoading) {
    return (
      <div className="flex h-[70vh] items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <span className="material-symbols-outlined animate-spin text-3xl text-primary">sync</span>
          <span className="font-bold text-on-surface-variant text-sm">Loading Logs & Threats...</span>
        </div>
      </div>
    );
  }

  if (!isMasterAuthorized && user?.role !== 'super_admin' && user?.role !== 'admin' && user?.role !== 'support_engineer') {
    return (
      <div className="min-h-[60vh] flex flex-col items-center justify-center text-center p-6">
        <div className="w-16 h-16 rounded-full bg-red-500/10 text-error flex items-center justify-center mb-4">
          <span className="material-symbols-outlined text-3xl">lock</span>
        </div>
        <h2 className="text-xl font-bold text-on-surface mb-2">Access Restricted</h2>
        <p className="text-on-surface-variant text-sm max-w-md mb-6 leading-relaxed">
          You do not have permissions to view global logs and threat intelligence.
        </p>
        <Link to="/dashboard" className="px-4 py-2 bg-primary text-white rounded-lg font-bold text-sm no-underline shadow-md">
          Go to Dashboard
        </Link>
      </div>
    );
  }

  // Full Page View Mode
  if (isFullLogsView) {
    return (
      <div className="w-full text-on-surface animate-fade-in">
        {/* Full Page Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between mb-lg gap-sm border-b border-outline-variant/60 pb-md">
          <div>
            <button 
              onClick={closeFullLogsView}
              className="flex items-center text-primary hover:underline font-bold text-[13px] mb-2 cursor-pointer bg-transparent border-0 p-0"
            >
              <ArrowLeft className="w-4 h-4 mr-1" />
              Back to Summary Dashboard
            </button>
            <h1 className="text-[26px] font-extrabold font-display tracking-tight text-on-surface flex items-center gap-2">
              <span className="material-symbols-outlined text-primary text-[28px]">policy</span>
              Complete Admin Audit Logs
              <span className="bg-primary/10 text-primary text-[12px] font-bold px-2.5 py-0.5 rounded-full ml-2">
                {filteredAllLogs.length} Records
              </span>
            </h1>
            <p className="text-on-surface-variant text-[13.5px] mt-1">Full system audit trail of administrative events and actions.</p>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={fetchAllAuditLogs}
              disabled={loadingAllLogs}
              className="flex items-center gap-1.5 px-3.5 py-2 bg-surface-container border border-outline-variant text-on-surface hover:bg-surface-container-high rounded-lg text-[13px] font-bold transition-colors cursor-pointer"
            >
              <RefreshCw className={`w-4 h-4 ${loadingAllLogs ? 'animate-spin' : ''}`} />
              Refresh
            </button>
            <button
              onClick={exportLogsToCSV}
              disabled={!filteredAllLogs.length}
              className="flex items-center gap-1.5 px-4 py-2 bg-primary text-on-primary hover:bg-primary/90 rounded-lg text-[13px] font-bold transition-colors cursor-pointer shadow-2xs"
            >
              <Download className="w-4 h-4" />
              Export CSV
            </button>
          </div>
        </div>

        {/* Filter and Search Bar */}
        <div className="mb-md bg-surface-container-lowest border border-outline-variant/70 rounded-xl p-4 flex flex-col sm:flex-row items-center justify-between gap-3 shadow-2xs">
          <div className="relative w-full sm:w-80">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant" />
            <input
              type="text"
              placeholder="Search user, action, or target..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-2 bg-surface border border-outline-variant/60 rounded-lg text-[13.5px] text-on-surface focus:outline-none focus:border-primary"
            />
          </div>
          <div className="text-[12.5px] text-on-surface-variant font-medium">
            Showing <strong className="text-on-surface font-bold">{getSortedLogs().length}</strong> audit event entries
          </div>
        </div>

        {/* Audit Logs Data Table */}
        <div className="bg-surface-container-lowest border border-outline-variant/70 rounded-xl overflow-hidden shadow-2xs">
          {loadingAllLogs ? (
            <div className="text-center py-16 text-on-surface-variant text-[14px]">Loading full audit history...</div>
          ) : filteredAllLogs.length === 0 ? (
            <div className="text-center py-16 text-on-surface-variant text-[14px]">No audit logs match your search filter.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-[13.5px]">
                <thead className="bg-surface-container-high/60 text-on-surface-variant text-[11px] uppercase tracking-wider select-none border-b border-outline-variant/70">
                  <tr>
                    {['Timestamp', 'User', 'Action', 'Target'].map((h, i) => (
                      <th 
                        key={h}
                        onClick={() => handleLogSort(h)}
                        className="p-3.5 cursor-pointer hover:bg-surface-container-highest transition-colors group"
                      >
                        <div className="flex items-center gap-xs font-bold">
                          {h}
                          <span className={`material-symbols-outlined text-[14px] opacity-0 group-hover:opacity-50 transition-opacity ${sortLogCol === h ? 'opacity-100 group-hover:opacity-100 text-primary' : ''}`}>
                            {sortLogCol === h && sortLogDir === 'desc' ? 'arrow_downward' : 'arrow_upward'}
                          </span>
                        </div>
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-outline-variant/60">
                  {getSortedLogs().map((log, i) => (
                    <tr key={log.id || i} className="hover:bg-surface-container-lowest/80 transition-colors">
                      <td className="p-3.5 text-[12px] font-mono text-on-surface-variant whitespace-nowrap">
                        {new Date(log.timestamp).toLocaleString()}
                      </td>
                      <td className="p-3.5 font-bold text-on-surface">
                        {log.user_email || log.admin_id || 'System'}
                      </td>
                      <td className="p-3.5 text-on-surface">
                        {log.action}
                      </td>
                      <td className="p-3.5 text-[12.5px] text-on-surface-variant">
                        {log.target_name || log.target_id || '-'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    );
  }

  // Dashboard Overview Mode
  return (
    <div className="w-full text-on-surface animate-fade-in">
      <div className="flex flex-col md:flex-row md:items-center justify-between mb-xl gap-sm">
        <div>
          <h1 className="text-[28px] font-extrabold font-display tracking-tight text-primary flex items-center gap-2">
            <ShieldAlert className="w-8 h-8" />
            Logs & Global Threats
          </h1>
          <p className="text-on-surface-variant text-[14px] mt-1">Review system audit trails and global vulnerability trends.</p>
        </div>
        <button onClick={() => window.history.back()} className="flex items-center px-md py-sm bg-surface-container border border-outline-variant text-on-surface rounded-lg hover:bg-surface-container-high transition-colors font-bold text-[13.5px] cursor-pointer">
          <span className="material-symbols-outlined text-[18px] mr-2">arrow_back</span>
          Back to Panel
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-lg mt-xl">
        {/* Threat Intelligence */}
        <div>
          <h2 className="font-headline-sm font-bold text-on-surface flex items-center text-[18px] mb-md">
            <span className="material-symbols-outlined text-error mr-2 text-[20px]">warning</span>
            Global Threat Intelligence
          </h2>
          <div className="bg-surface-container-lowest border border-outline-variant rounded-2xl overflow-hidden shadow-2xs p-4">
            {loading ? (
              <div className="text-center text-on-surface-variant text-[13px] py-4">Loading threats...</div>
            ) : trends.length === 0 ? (
              <div className="text-center text-on-surface-variant text-[13px] py-4">No global vulnerabilities recorded yet.</div>
            ) : (
              <ul className="divide-y divide-outline-variant">
                {trends.map((t, i) => (
                  <li key={i} className="py-3 flex justify-between items-center">
                    <span className="font-semibold text-on-surface text-[14px] flex items-center gap-2">
                      <span className="w-6 h-6 rounded-full bg-error/10 text-error flex items-center justify-center text-[11px] font-bold">{i + 1}</span>
                      {t.title}
                    </span>
                    <span className="bg-surface-container-high px-2.5 py-1 rounded-md text-[12px] font-bold">{t.count} Found</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>

        {/* Admin Audit Logs */}
        <div>
          <div className="flex items-center justify-between mb-md">
            <h2 className="font-headline-sm font-bold text-on-surface flex items-center text-[18px]">
              <span className="material-symbols-outlined text-primary mr-2 text-[20px]">policy</span>
              Admin Audit Logs
            </h2>
            <button
              onClick={openFullLogsView}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-primary/10 hover:bg-primary/20 text-primary rounded-lg transition-colors font-bold text-[12px] cursor-pointer"
            >
              <List className="w-4 h-4" />
              View All Audit Logs
            </button>
          </div>
          <div className="bg-surface-container-lowest border border-outline-variant rounded-2xl overflow-hidden shadow-2xs p-4">
            {loading ? (
              <div className="text-center text-on-surface-variant text-[13px] py-4">Loading logs...</div>
            ) : auditLogs.length === 0 ? (
              <div className="text-center text-on-surface-variant text-[13px] py-4">No admin actions recorded yet.</div>
            ) : (
              <div>
                <ul className="divide-y divide-outline-variant">
                  {auditLogs.slice(0, 10).map((log, i) => (
                    <li key={i} className="py-3">
                      <div className="flex justify-between items-start mb-1">
                        <span className="font-semibold text-on-surface text-[13.5px]">{log.action}</span>
                        <span className="text-[11px] text-on-surface-variant shrink-0 ml-2">{new Date(log.timestamp).toLocaleString()}</span>
                      </div>
                      <div className="text-[12px] text-on-surface-variant flex items-center gap-1.5 flex-wrap">
                        <span>User: <strong className="text-on-surface font-bold">{log.user_email || log.admin_id || 'System'}</strong></span>
                        {log.target_name && log.target_name !== log.user_email && log.target_name !== log.admin_id && (
                          <span className="text-outline">| Target: <strong className="text-on-surface font-bold">{log.target_name}</strong></span>
                        )}
                      </div>
                    </li>
                  ))}
                </ul>
                <div className="mt-4 pt-3 border-t border-outline-variant text-center">
                  <button
                    onClick={openFullLogsView}
                    className="text-primary hover:underline text-[13px] font-bold inline-flex items-center gap-1 cursor-pointer bg-transparent border-0"
                  >
                    View All Complete Audit Logs &rarr;
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default LogsAndThreats;
