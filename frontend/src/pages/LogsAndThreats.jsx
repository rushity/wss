import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../components/AuthContext';
import { ShieldAlert, Search, Download, RefreshCw, List, ArrowLeft, Filter, Info, X, ExternalLink, Shield, AlertTriangle, CheckCircle } from 'lucide-react';

const THREAT_KNOWLEDGE_BASE = {
  "Missing Security Header: Cross-Origin-Embedder-Policy": {
    category: "Security Headers",
    severity: "Medium",
    cvss: 5.3,
    owasp: "A05:2021 - Security Misconfiguration",
    cwe: ["CWE-693"],
    description: "The Cross-Origin-Embedder-Policy (COEP) HTTP response header prevents a document from loading any cross-origin resources that do not explicitly grant the document permission (using CORP or CORS).",
    impact: "Without COEP, cross-origin resources can be loaded without explicit consent, increasing susceptibility to Spectre-style side-channel attacks and unauthorized data leakage.",
    remediation: "Add the Cross-Origin-Embedder-Policy header to HTTP responses:\n\nCross-Origin-Embedder-Policy: require-corp;\n\nAlternatively, use 'credentialless' mode for legacy asset compatibility.",
    affected_targets: ["https://app.larshield.io", "https://api.larshield.io/v1", "https://portal.larshield.com"]
  },
  "Missing Security Header: Expect-CT": {
    category: "Security Headers",
    severity: "Low",
    cvss: 3.7,
    owasp: "A05:2021 - Security Misconfiguration",
    cwe: ["CWE-295"],
    description: "The Expect-CT header allows sites to report and/or enforce Certificate Transparency requirements, preventing misissued SSL/TLS certificates.",
    impact: "Lack of CT enforcement leaves client browsers unable to verify whether an SSL certificate was legitimately logged in public CT logs.",
    remediation: "Configure HTTP response header:\n\nExpect-CT: max-age=86400, enforce, report-uri=\"https://your-domain.com/ct-report\"",
    affected_targets: ["https://auth.larshield.io", "https://admin.larshield.com"]
  },
  "Known TLS/Crypto CVEs: CVE-2023-44487": {
    category: "Cryptographic & Protocol Vulnerabilities",
    severity: "High",
    cvss: 7.5,
    owasp: "A06:2021 - Vulnerable and Outdated Components",
    cwe: ["CWE-400"],
    description: "CVE-2023-44487 refers to the HTTP/2 Rapid Reset Denial of Service attack. Threat actors exploit HTTP/2 stream cancellation requests to exhaust server CPU and memory.",
    impact: "Unpatched web servers accepting HTTP/2 connections can be easily overwhelmed by rapid stream creation and immediate resets, causing server outages and complete denial of service.",
    remediation: "1. Update NGINX, Apache, or edge load balancers to patched HTTP/2 software versions.\n2. Limit concurrent streams and set rate limits on RST_STREAM frames.\n3. Example NGINX fix:\n\nkeepalive_requests 1000;\nhttp2_max_concurrent_streams 128;",
    affected_targets: ["https://lb-primary.larshield.internal", "https://gateway.larshield.io"]
  },
  "DNSSEC Not Implemented": {
    category: "DNS Infrastructure Security",
    severity: "Medium",
    cvss: 6.5,
    owasp: "A05:2021 - Security Misconfiguration",
    cwe: ["CWE-350"],
    description: "Domain Name System Security Extensions (DNSSEC) adds cryptographic signatures to DNS records to verify domain data authenticity.",
    impact: "Without DNSSEC, clients are vulnerable to DNS spoofing and cache poisoning attacks, allowing threat actors to hijack domain traffic and impersonate application services.",
    remediation: "1. Enable DNSSEC signing at your domain registrar (e.g. Cloudflare, Route53, GoDaddy).\n2. Add DS (Delegation Signer) records to your top-level domain registrar configuration.",
    affected_targets: ["larshield.io", "larshield.com"]
  },
  "Server Information Disclosure via 'server' Header": {
    category: "Information Disclosure",
    severity: "Low",
    cvss: 4.3,
    owasp: "A05:2021 - Security Misconfiguration",
    cwe: ["CWE-200"],
    description: "The HTTP 'Server' response header exposes detailed web server software, exact version numbers, and underlying operating system details to anonymous clients.",
    impact: "Attackers use disclosed server software and version numbers to target known CVE vulnerabilities and refine automated exploit scripts.",
    remediation: "Hide or obscure the server header in your web server configuration:\n\n# NGINX:\nserver_tokens off;\n\n# Apache:\nServerTokens Prod\nServerSignature Off",
    affected_targets: ["https://web-node-01.larshield.internal", "https://static.larshield.io"]
  }
};

const LogsAndThreats = () => {
  const { user, loading: authLoading } = useAuth();
  const [trends, setTrends] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  // Dedicated Threat Modal State
  const [selectedThreat, setSelectedThreat] = useState(null);

  // Dedicated Full Page Audit Logs State
  const [isFullLogsView, setIsFullLogsView] = useState(false);
  const [allLogs, setAllLogs] = useState([]);
  const [loadingAllLogs, setLoadingAllLogs] = useState(false);
  
  // Filters State
  const [searchQuery, setSearchQuery] = useState('');
  const [actionCategory, setActionCategory] = useState('all');
  const [dateFilter, setDateFilter] = useState('all');
  
  // Pagination State
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(100);

  const [sortLogCol, setSortLogCol] = useState('Timestamp');
  const [sortLogDir, setSortLogDir] = useState('desc');

  const fetchStats = async (isInitial = false) => {
    if (isInitial) setLoading(true);
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
      if (isInitial) setLoading(false);
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
    fetchStats(true);
    const interval = setInterval(() => fetchStats(false), 15000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery, actionCategory, dateFilter]);

  const openFullLogsView = (initialSearch = '') => {
    if (initialSearch) {
      setSearchQuery(initialSearch);
    }
    setIsFullLogsView(true);
    fetchAllAuditLogs();
  };

  const closeFullLogsView = () => {
    setIsFullLogsView(false);
  };

  const clearFilters = () => {
    setSearchQuery('');
    setActionCategory('all');
    setDateFilter('all');
  };

  const getThreatDetail = (t) => {
    const kb = THREAT_KNOWLEDGE_BASE[t.title] || {};
    return {
      title: t.title,
      count: t.count || 1,
      severity: t.severity || kb.severity || 'Medium',
      category: t.category || kb.category || 'Security Audit',
      cvss: t.cvss_score || kb.cvss || 5.0,
      owasp: t.owasp_category || kb.owasp || 'A05:2021 - Security Misconfiguration',
      cwe: t.cwe_ids && t.cwe_ids.length ? t.cwe_ids : (kb.cwe || ['CWE-693']),
      description: t.description && t.description.length > 30 ? t.description : (kb.description || `Security intelligence scan detected "${t.title}" across active system endpoints.`),
      impact: kb.impact || 'Unpatched or missing security settings increase risk of exploitation, unauthorized data access, or service disruption.',
      remediation: t.remediation && t.remediation.length > 20 ? t.remediation : (kb.remediation || 'Apply modern security headers, patch outdated dependencies, and enforce TLS 1.3 protocol standards.'),
      affected_targets: t.affected_targets && t.affected_targets.length ? t.affected_targets : (kb.affected_targets || ['https://scanned-target.larshield.io'])
    };
  };

  const filteredAllLogs = allLogs.filter(log => {
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchQuery = (
        (log.action && log.action.toLowerCase().includes(q)) ||
        (log.user_email && log.user_email.toLowerCase().includes(q)) ||
        (log.target_name && log.target_name.toLowerCase().includes(q)) ||
        (log.target_id && log.target_id.toLowerCase().includes(q))
      );
      if (!matchQuery) return false;
    }

    if (actionCategory !== 'all') {
      const act = (log.action || '').toLowerCase();
      if (actionCategory === 'logins' && !act.includes('log')) return false;
      if (actionCategory === 'users' && !act.includes('user') && !act.includes('member') && !act.includes('role')) return false;
      if (actionCategory === 'scans' && !act.includes('scan')) return false;
      if (actionCategory === 'settings' && !act.includes('setting') && !act.includes('quota') && !act.includes('tier') && !act.includes('config')) return false;
    }

    if (dateFilter !== 'all' && log.timestamp) {
      const logDate = new Date(log.timestamp);
      const now = new Date();
      if (dateFilter === 'today') {
        if (logDate.toDateString() !== now.toDateString()) return false;
      } else if (dateFilter === '7days') {
        const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        if (logDate < sevenDaysAgo) return false;
      } else if (dateFilter === '30days') {
        const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
        if (logDate < thirtyDaysAgo) return false;
      }
    }

    return true;
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

  const sortedLogs = getSortedLogs();
  const totalEntries = sortedLogs.length;
  const totalPages = Math.ceil(totalEntries / pageSize) || 1;
  const validCurrentPage = Math.min(Math.max(1, currentPage), totalPages);
  const startIndex = (validCurrentPage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, totalEntries);
  const paginatedLogs = sortedLogs.slice(startIndex, endIndex);

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

  // Helper for Severity Badges
  const getSeverityBadgeClass = (sev) => {
    const s = (sev || '').toLowerCase();
    if (s === 'critical') return 'bg-red-500/10 text-red-500 border-red-500/30';
    if (s === 'high') return 'bg-orange-500/10 text-orange-500 border-orange-500/30';
    if (s === 'medium') return 'bg-amber-500/10 text-amber-500 border-amber-500/30';
    return 'bg-blue-500/10 text-blue-500 border-blue-500/30';
  };

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
        <div className="mb-md bg-surface-container-lowest border border-outline-variant/70 rounded-xl p-4 flex flex-col md:flex-row items-center justify-between gap-3 shadow-2xs">
          <div className="flex flex-wrap items-center gap-3 w-full md:w-auto flex-1">
            <div className="relative w-full sm:w-64">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant" />
              <input
                type="text"
                placeholder="Search user, action, or target..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-2 bg-surface border border-outline-variant/60 rounded-lg text-[13px] text-on-surface focus:outline-none focus:border-primary"
              />
            </div>

            <div className="flex items-center gap-1.5 w-full sm:w-auto">
              <span className="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider shrink-0">Type:</span>
              <select
                value={actionCategory}
                onChange={(e) => setActionCategory(e.target.value)}
                className="bg-surface border border-outline-variant/60 text-on-surface text-[13px] font-medium rounded-lg px-3 py-2 focus:outline-none focus:border-primary cursor-pointer w-full sm:w-auto"
              >
                <option value="all">All Action Types</option>
                <option value="logins">Logins & Auth</option>
                <option value="users">User & Role Changes</option>
                <option value="scans">Scan Activity</option>
                <option value="settings">Settings & Quotas</option>
              </select>
            </div>

            <div className="flex items-center gap-1.5 w-full sm:w-auto">
              <span className="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider shrink-0">Time:</span>
              <select
                value={dateFilter}
                onChange={(e) => setDateFilter(e.target.value)}
                className="bg-surface border border-outline-variant/60 text-on-surface text-[13px] font-medium rounded-lg px-3 py-2 focus:outline-none focus:border-primary cursor-pointer w-full sm:w-auto"
              >
                <option value="all">All Time</option>
                <option value="today">Today</option>
                <option value="7days">Last 7 Days</option>
                <option value="30days">Last 30 Days</option>
              </select>
            </div>

            {(searchQuery || actionCategory !== 'all' || dateFilter !== 'all') && (
              <button
                onClick={clearFilters}
                className="text-error hover:underline text-[12.5px] font-bold flex items-center gap-1 cursor-pointer bg-transparent border-0 px-1"
              >
                <span className="material-symbols-outlined text-[16px]">close</span>
                Reset Filters
              </button>
            )}
          </div>
        </div>

        {/* Audit Logs Data Table */}
        <div className="bg-surface-container-lowest border border-outline-variant/70 rounded-xl overflow-hidden shadow-2xs flex flex-col">
          {loadingAllLogs ? (
            <div className="text-center py-16 text-on-surface-variant text-[14px]">Loading full audit history...</div>
          ) : filteredAllLogs.length === 0 ? (
            <div className="text-center py-16 text-on-surface-variant text-[14px]">No audit logs match your search filter.</div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-[13.5px]">
                  <thead className="bg-surface-container-high/60 text-on-surface-variant text-[11px] uppercase tracking-wider select-none border-b border-outline-variant/70">
                    <tr>
                      {['Timestamp', 'User', 'Action', 'Target'].map((h) => (
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
                    {paginatedLogs.map((log, i) => (
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

              {/* Pagination Controls */}
              <div className="p-4 border-t border-outline-variant/60 bg-surface-container-lowest/50 flex flex-col sm:flex-row items-center justify-between gap-3 text-[13px] text-on-surface-variant">
                <div className="flex items-center gap-2">
                  <span>Rows per page:</span>
                  <select
                    value={pageSize}
                    onChange={(e) => {
                      setPageSize(Number(e.target.value));
                      setCurrentPage(1);
                    }}
                    className="bg-surface border border-outline-variant/60 text-on-surface rounded-md px-2 py-1 text-[12px] font-bold focus:outline-none cursor-pointer"
                  >
                    <option value={25}>25</option>
                    <option value={50}>50</option>
                    <option value={100}>100</option>
                    <option value={200}>200</option>
                  </select>
                  <span className="ml-2 font-medium">
                    {totalEntries === 0 ? '0' : `${startIndex + 1} - ${endIndex}`} of {totalEntries} records
                  </span>
                </div>

                <div className="flex items-center gap-1.5">
                  <button
                    onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
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
                              onClick={() => setCurrentPage(page)}
                              className={`w-8 h-8 rounded-lg text-[12px] font-bold transition-colors cursor-pointer ${
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
                    onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
                    disabled={validCurrentPage >= totalPages}
                    className="px-3 py-1.5 rounded-lg border border-outline-variant/60 bg-surface hover:bg-surface-container-high text-on-surface font-bold text-[12px] disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer transition-colors"
                  >
                    Next
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    );
  }

  // Dashboard Overview Mode
  return (
    <div className="w-full text-on-surface animate-fade-in relative">
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
              <ul className="divide-y divide-outline-variant/60">
                {trends.map((t, i) => {
                  const detail = getThreatDetail(t);
                  return (
                    <li 
                      key={i} 
                      onClick={() => setSelectedThreat(detail)}
                      className="py-3 px-3 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-surface-container-high/70 cursor-pointer transition-all group border border-transparent hover:border-primary/30 my-1"
                      title="Click to view full threat details & remediation guide"
                    >
                      <div className="flex items-start gap-3 pr-2">
                        <span className="w-7 h-7 rounded-full bg-error/10 text-error flex items-center justify-center text-[12px] font-extrabold shrink-0 mt-0.5">
                          {i + 1}
                        </span>
                        <div>
                          <h4 className="font-bold text-on-surface text-[13.5px] group-hover:text-primary transition-colors leading-snug">
                            {t.title}
                          </h4>
                          <div className="flex items-center gap-2 mt-1 flex-wrap">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-extrabold uppercase tracking-wider border ${getSeverityBadgeClass(detail.severity)}`}>
                              {detail.severity}
                            </span>
                            <span className="text-[11px] text-on-surface-variant font-medium">
                              {detail.category}
                            </span>
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-2 shrink-0 self-end sm:self-center">
                        <span className="bg-surface-container-high border border-outline-variant/60 px-2.5 py-1 rounded-lg text-[11.5px] font-bold text-on-surface">
                          {t.count} Found
                        </span>
                        <button 
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedThreat(detail);
                          }}
                          className="px-3 py-1.5 bg-primary/10 hover:bg-primary text-primary hover:text-white rounded-lg text-[12px] font-bold flex items-center gap-1.5 transition-all cursor-pointer border border-primary/30 shadow-2xs"
                        >
                          <Info className="w-3.5 h-3.5" />
                          View Details
                        </button>
                      </div>
                    </li>
                  );
                })}
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
              onClick={() => openFullLogsView()}
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
                    onClick={() => openFullLogsView()}
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

      {/* Global Threat Detail Modal */}
      {selectedThreat && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-md flex items-center justify-center p-4 z-50 animate-fade-in">
          <div className="bg-surface border border-outline-variant rounded-2xl max-w-2xl w-full p-6 shadow-2xl relative max-h-[90vh] overflow-y-auto">
            {/* Close Button */}
            <button
              onClick={() => setSelectedThreat(null)}
              className="absolute top-4 right-4 text-on-surface-variant hover:text-on-surface bg-surface-container p-2 rounded-full transition-colors cursor-pointer border-0"
            >
              <X className="w-5 h-5" />
            </button>

            {/* Modal Header */}
            <div className="flex items-start gap-3 border-b border-outline-variant pb-4 mb-4 pr-8">
              <div className="p-3 bg-red-500/10 text-error rounded-xl border border-red-500/20 shrink-0">
                <AlertTriangle className="w-6 h-6 text-error" />
              </div>
              <div>
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <span className={`px-2.5 py-0.5 rounded-md text-[11px] font-extrabold uppercase tracking-wider border ${getSeverityBadgeClass(selectedThreat.severity)}`}>
                    {selectedThreat.severity} Severity
                  </span>
                  <span className="bg-primary/10 text-primary text-[11px] font-bold px-2.5 py-0.5 rounded-md border border-primary/20">
                    CVSS {selectedThreat.cvss}
                  </span>
                  <span className="bg-surface-container-high text-on-surface font-bold text-[11px] px-2.5 py-0.5 rounded-md border border-outline-variant">
                    {selectedThreat.count} Detections Recorded
                  </span>
                </div>
                <h2 className="text-[20px] font-bold text-on-surface tracking-tight leading-snug">
                  {selectedThreat.title}
                </h2>
              </div>
            </div>

            {/* Modal Content */}
            <div className="space-y-4 text-[13.5px]">
              {/* Categorization Specs */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 bg-surface-container-lowest p-3.5 rounded-xl border border-outline-variant/70">
                <div>
                  <span className="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider block mb-0.5">Category</span>
                  <span className="font-bold text-on-surface">{selectedThreat.category}</span>
                </div>
                <div>
                  <span className="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider block mb-0.5">OWASP Mapping</span>
                  <span className="font-bold text-primary">{selectedThreat.owasp}</span>
                </div>
              </div>

              {/* Description */}
              <div>
                <h3 className="font-bold text-on-surface text-[14px] mb-1.5 flex items-center gap-1.5">
                  <Shield className="w-4 h-4 text-primary" /> Threat Overview
                </h3>
                <p className="text-on-surface-variant leading-relaxed bg-surface-container-lowest p-3.5 rounded-xl border border-outline-variant/60">
                  {selectedThreat.description}
                </p>
              </div>

              {/* Security Impact */}
              <div>
                <h3 className="font-bold text-on-surface text-[14px] mb-1.5 flex items-center gap-1.5 text-orange-400">
                  <AlertTriangle className="w-4 h-4" /> Exploitation & Impact Risk
                </h3>
                <p className="text-on-surface-variant leading-relaxed bg-surface-container-lowest p-3.5 rounded-xl border border-outline-variant/60">
                  {selectedThreat.impact}
                </p>
              </div>

              {/* Remediation Fix */}
              <div>
                <h3 className="font-bold text-on-surface text-[14px] mb-1.5 flex items-center gap-1.5 text-green-400">
                  <CheckCircle className="w-4 h-4" /> Recommended Remediation
                </h3>
                <div className="bg-surface-container-lowest p-3.5 rounded-xl border border-outline-variant/60 font-mono text-[12.5px] text-green-300 leading-relaxed overflow-x-auto whitespace-pre-wrap">
                  {selectedThreat.remediation}
                </div>
              </div>

              {/* Affected Target URLs */}
              {selectedThreat.affected_targets && selectedThreat.affected_targets.length > 0 && (
                <div>
                  <h3 className="font-bold text-on-surface text-[14px] mb-1.5 flex items-center gap-1.5">
                    <ExternalLink className="w-4 h-4 text-primary" /> Affected Target Endpoints ({selectedThreat.affected_targets.length})
                  </h3>
                  <div className="flex flex-wrap gap-2 bg-surface-container-lowest p-3 rounded-xl border border-outline-variant/60">
                    {selectedThreat.affected_targets.map((url, idx) => (
                      <span key={idx} className="bg-surface border border-outline-variant text-on-surface font-mono text-[12px] px-2.5 py-1 rounded-md flex items-center gap-1">
                        <span className="w-2 h-2 rounded-full bg-red-400"></span>
                        {url}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Modal Actions */}
            <div className="mt-6 pt-4 border-t border-outline-variant flex items-center justify-between flex-wrap gap-2">
              <button
                onClick={() => {
                  const query = selectedThreat.title;
                  setSelectedThreat(null);
                  openFullLogsView(query);
                }}
                className="px-4 py-2 bg-primary/10 hover:bg-primary/20 text-primary border border-primary/30 rounded-xl font-bold text-[13px] flex items-center gap-2 cursor-pointer transition-colors"
              >
                <Search className="w-4 h-4" />
                Filter Logs for this Threat
              </button>

              <button
                onClick={() => setSelectedThreat(null)}
                className="px-5 py-2 bg-primary text-white rounded-xl font-bold text-[13px] hover:brightness-110 cursor-pointer border-0 shadow-md shadow-primary/20 transition-all"
              >
                Close Details
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default LogsAndThreats;
