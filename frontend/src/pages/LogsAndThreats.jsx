import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../components/AuthContext';
import { 
  ShieldAlert, Search, Download, RefreshCw, List, ArrowLeft, Filter, 
  Info, X, ExternalLink, Shield, AlertTriangle, CheckCircle, Copy, Check, Terminal, Layers, Eye,
  Clock, Radio, FileText
} from 'lucide-react';

const THREAT_KNOWLEDGE_BASE = {
  "Missing Security Header: Cross-Origin-Embedder-Policy": {
    category: "Security Headers",
    severity: "Medium",
    cvss: 5.3,
    owasp: "A05:2021 - Security Misconfiguration",
    cwe: ["CWE-693"],
    description: "The Cross-Origin-Embedder-Policy (COEP) HTTP response header prevents a document from loading any cross-origin resources that do not explicitly grant the document permission (using CORP or CORS).",
    impact: "Without COEP, cross-origin resources can be loaded without explicit consent, increasing susceptibility to Spectre-style side-channel attacks and unauthorized data leakage.",
    remediation: "add_header Cross-Origin-Embedder-Policy \"require-corp\" always;\n# Options: require-corp, credentialless, unsafe-none",
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
    remediation: "add_header Expect-CT \"max-age=86400, enforce, report-uri=\\\"https://larshield.io/ct-report\\\"\" always;",
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
    remediation: "# NGINX HTTP/2 Rapid Reset Mitigation\nkeepalive_requests 1000;\nhttp2_max_concurrent_streams 128;\nlimit_req_zone $binary_remote_addr zone=http2_limit:10m rate=100r/s;",
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
    remediation: "# Enable DNSSEC at domain registrar\n1. Sign zone using ECDSA Curve P-256 with SHA-256\n2. Publish DS records to TLD parent zone",
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
    remediation: "# Hide NGINX server tokens\nserver_tokens off;\n\n# Hide Apache server header\nServerTokens Prod\nServerSignature Off",
    affected_targets: ["https://web-node-01.larshield.internal", "https://static.larshield.io"]
  }
};

const LogsAndThreats = () => {
  const { user, loading: authLoading } = useAuth();
  const [trends, setTrends] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  // Selected Threat Detail Modal State
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [copiedCode, setCopiedCode] = useState(false);
  const [copiedBrief, setCopiedBrief] = useState(false);
  
  // Full Page Threat Intelligence View State
  const [isFullThreatsView, setIsFullThreatsView] = useState(false);
  const [threatSearch, setThreatSearch] = useState('');
  const [threatSeverityFilter, setThreatSeverityFilter] = useState('all');
  const [threatCategoryFilter, setThreatCategoryFilter] = useState('all');
  const [threatOwaspFilter, setThreatOwaspFilter] = useState('all');
  const [threatSortCol, setThreatSortCol] = useState('severity');
  const [threatSortDir, setThreatSortDir] = useState('desc');
  const [fullThreatsPage, setFullThreatsPage] = useState(1);
  const [fullThreatsPageSize, setFullThreatsPageSize] = useState(5);

  // Full Page Audit Logs View State
  const [isFullLogsView, setIsFullLogsView] = useState(false);
  const [allLogs, setAllLogs] = useState([]);
  const [loadingAllLogs, setLoadingAllLogs] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [actionCategory, setActionCategory] = useState('all');
  const [dateFilter, setDateFilter] = useState('all');
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(8);
  const [sortLogCol, setSortLogCol] = useState('Timestamp');
  const [sortLogDir, setSortLogDir] = useState('desc');

  // Threat In-Card Pagination State (Dashboard Overview)
  const [threatCardPage, setThreatCardPage] = useState(1);
  const [threatCardPageSize, setThreatCardPageSize] = useState(5);

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
    fetchAllAuditLogs();
  }, []);

  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery, actionCategory, dateFilter]);

  useEffect(() => {
    setFullThreatsPage(1);
  }, [threatSearch, threatSeverityFilter, threatCategoryFilter, threatOwaspFilter, threatSortCol, threatSortDir]);

  const openFullLogsView = (initialSearch = '') => {
    let cleanQuery = '';
    if (initialSearch) {
      if (initialSearch.includes('CVE-')) {
        const match = initialSearch.match(/CVE-\d{4}-\d+/i);
        cleanQuery = match ? match[0] : initialSearch;
      } else if (initialSearch.includes(':')) {
        cleanQuery = initialSearch.split(':')[0].trim();
      } else {
        cleanQuery = initialSearch.trim();
      }
    }
    setSearchQuery(cleanQuery);
    setActionCategory('all');
    setDateFilter('all');
    setCurrentPage(1);
    setIsFullThreatsView(false);
    setIsFullLogsView(true);
    fetchAllAuditLogs();
  };

  const openFullThreatsView = () => {
    setIsFullLogsView(false);
    setIsFullThreatsView(true);
  };

  const closeFullViews = () => {
    setIsFullLogsView(false);
    setIsFullThreatsView(false);
  };

  const clearLogFilters = () => {
    setSearchQuery('');
    setActionCategory('all');
    setDateFilter('all');
  };

  const clearThreatFilters = () => {
    setThreatSearch('');
    setThreatSeverityFilter('all');
    setThreatCategoryFilter('all');
    setThreatOwaspFilter('all');
    setThreatSortCol('severity');
    setThreatSortDir('desc');
  };

  const copyBriefToClipboard = (threat) => {
    if (!threat) return;
    const text = `[LARSHIELD EXECUTIVE THREAT BRIEF]
Threat Title: ${threat.title}
Severity: ${threat.severity} | CVSS Score: ${threat.cvss} | Detections: ${threat.count}
CWE Standard: ${threat.cwe} | Remediation SLA: ${threat.sla}
Category: ${threat.category}
OWASP Standard: ${threat.owasp}
Attack Vector: ${threat.attackVector}

THREAT OVERVIEW:
${threat.description}

EXPLOITATION & IMPACT RISK:
${threat.impact}

RECOMMENDED SECURITY FIX:
${threat.remediation}

AFFECTED TARGET ENDPOINTS (${threat.affected_targets.length}):
${threat.affected_targets.join('\n')}`;

    navigator.clipboard.writeText(text);
    setCopiedBrief(true);
    setTimeout(() => setCopiedBrief(false), 2000);
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const getThreatDetail = (t) => {
    if (!t) return null;
    const titleKey = typeof t === 'string' ? t : (t.title || '');
    
    // Intelligent fuzzy matching for Knowledge Base lookup
    const kbKey = Object.keys(THREAT_KNOWLEDGE_BASE).find(k => 
      k.toLowerCase() === titleKey.toLowerCase() || 
      titleKey.toLowerCase().includes(k.toLowerCase()) || 
      k.toLowerCase().includes(titleKey.toLowerCase()) ||
      (titleKey.toLowerCase().includes('cve') && k.toLowerCase().includes('cve'))
    );
    const kb = (kbKey ? THREAT_KNOWLEDGE_BASE[kbKey] : null) || {};

    const sev = t.severity || kb.severity || 'Medium';
    const isUrgent = sev.toLowerCase() === 'critical' || sev.toLowerCase() === 'high';
    const rawCwe = t.cwe_ids && t.cwe_ids.length ? (Array.isArray(t.cwe_ids) ? t.cwe_ids[0] : t.cwe_ids) : (kb.cwe ? (Array.isArray(kb.cwe) ? kb.cwe[0] : kb.cwe) : 'CWE-693');

    return {
      title: titleKey || kbKey || 'Security Vulnerability',
      count: t.count || 1,
      severity: sev,
      category: t.category || kb.category || 'Security Headers',
      cvss: t.cvss_score || t.cvss || kb.cvss || 5.3,
      owasp: t.owasp_category || t.owasp || kb.owasp || 'A05:2021 - Security Misconfiguration',
      cwe: rawCwe,
      sla: isUrgent ? 'Fix Required: Within 24 Hours' : 'Fix Required: Within 7 Days',
      attackVector: kb.attack_vector || (titleKey.toLowerCase().includes('cve') || titleKey.toLowerCase().includes('tls') ? 'Network / Remote Exploitable' : 'HTTP Header Misconfiguration'),
      description: t.description && t.description.length > 20 ? t.description : (kb.description || `Security intelligence scan detected "${titleKey}" across active system endpoints.`),
      impact: t.impact || kb.impact || 'Unpatched or missing security settings increase risk of exploitation, unauthorized data access, or service disruption.',
      remediation: t.remediation && t.remediation.length > 20 ? t.remediation : (kb.remediation || 'add_header Cross-Origin-Embedder-Policy "require-corp" always;'),
      affected_targets: t.affected_targets && t.affected_targets.length ? t.affected_targets : (kb.affected_targets || ['https://app.larshield.io'])
    };
  };

  // Helper for Severity Badges
  const getSeverityBadgeClass = (sev) => {
    const s = (sev || '').toLowerCase();
    if (s === 'critical') return 'bg-red-500/15 text-red-600 dark:text-red-400 border-red-500/30';
    if (s === 'high') return 'bg-orange-500/15 text-orange-600 dark:text-orange-400 border-orange-500/30';
    if (s === 'medium') return 'bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/30';
    return 'bg-blue-500/15 text-blue-600 dark:text-blue-400 border-blue-500/30';
  };

  // Threat Details Calculations (Merge KB + Live API Trends)
  const mergedThreatsMap = new Map();
  Object.keys(THREAT_KNOWLEDGE_BASE).forEach(key => {
    mergedThreatsMap.set(key, getThreatDetail({ title: key, count: 1 }));
  });

  if (Array.isArray(trends) && trends.length > 0) {
    trends.forEach(t => {
      const detail = getThreatDetail(t);
      if (detail && detail.title) {
        const existingKey = Array.from(mergedThreatsMap.keys()).find(k => 
          k.toLowerCase() === detail.title.toLowerCase() || 
          k.toLowerCase().includes(detail.title.toLowerCase()) || 
          detail.title.toLowerCase().includes(k.toLowerCase())
        );
        if (existingKey) {
          mergedThreatsMap.set(existingKey, {
            ...mergedThreatsMap.get(existingKey),
            ...detail,
            count: detail.count || mergedThreatsMap.get(existingKey).count || 1
          });
        } else {
          mergedThreatsMap.set(detail.title, detail);
        }
      }
    });
  }

  const allThreatDetails = Array.from(mergedThreatsMap.values());

  // Stats Counters
  const criticalCount = allThreatDetails.filter(t => t.severity.toLowerCase() === 'critical').length;
  const highCount = allThreatDetails.filter(t => t.severity.toLowerCase() === 'high').length;
  const mediumCount = allThreatDetails.filter(t => t.severity.toLowerCase() === 'medium').length;
  const lowCount = allThreatDetails.filter(t => t.severity.toLowerCase() === 'low').length;

  // In-Card Threats Pagination Calculations (Dashboard Overview)
  const totalThreatCount = allThreatDetails.length;
  const totalThreatCardPages = Math.ceil(totalThreatCount / threatCardPageSize) || 1;
  const validThreatCardPage = Math.min(Math.max(1, threatCardPage), totalThreatCardPages);
  const startThreatCardIdx = (validThreatCardPage - 1) * threatCardPageSize;
  const endThreatCardIdx = Math.min(startThreatCardIdx + threatCardPageSize, totalThreatCount);
  const paginatedCardThreats = allThreatDetails.slice(startThreatCardIdx, endThreatCardIdx);

  // Dynamic unique categories and OWASPs
  const uniqueThreatCategories = Array.from(new Set(allThreatDetails.map(t => t.category).filter(Boolean)));
  const uniqueThreatOwasps = Array.from(new Set(allThreatDetails.map(t => t.owasp).filter(Boolean)));

  const handleThreatSort = (column) => {
    if (threatSortCol === column) {
      setThreatSortDir(threatSortDir === 'asc' ? 'desc' : 'asc');
    } else {
      setThreatSortCol(column);
      setThreatSortDir(column === 'title' || column === 'category' ? 'asc' : 'desc');
    }
  };

  // Full Page Threat View Filtering & Sorting
  const filteredFullThreats = allThreatDetails.filter(t => {
    if (threatSearch) {
      const q = threatSearch.toLowerCase();
      const match = t.title.toLowerCase().includes(q) || t.category.toLowerCase().includes(q) || t.owasp.toLowerCase().includes(q) || t.description.toLowerCase().includes(q);
      if (!match) return false;
    }
    if (threatSeverityFilter !== 'all') {
      if (t.severity.toLowerCase() !== threatSeverityFilter.toLowerCase()) return false;
    }
    if (threatCategoryFilter !== 'all') {
      if (t.category !== threatCategoryFilter) return false;
    }
    if (threatOwaspFilter !== 'all') {
      if (t.owasp !== threatOwaspFilter) return false;
    }
    return true;
  }).sort((a, b) => {
    let aVal, bVal;
    const sevWeight = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1 };
    switch (threatSortCol) {
      case 'title':
        aVal = a.title.toLowerCase(); bVal = b.title.toLowerCase();
        break;
      case 'severity':
        aVal = sevWeight[a.severity.toLowerCase()] || 0;
        bVal = sevWeight[b.severity.toLowerCase()] || 0;
        break;
      case 'cvss':
        aVal = Number(a.cvss) || 0; bVal = Number(b.cvss) || 0;
        break;
      case 'category':
        aVal = a.category.toLowerCase(); bVal = b.category.toLowerCase();
        break;
      case 'detections':
        aVal = Number(a.count) || 0; bVal = Number(b.count) || 0;
        break;
      default:
        aVal = 0; bVal = 0;
    }
    if (aVal < bVal) return threatSortDir === 'asc' ? -1 : 1;
    if (aVal > bVal) return threatSortDir === 'asc' ? 1 : -1;
    return 0;
  });

  const totalFullThreatEntries = filteredFullThreats.length;
  const totalFullThreatPages = Math.ceil(totalFullThreatEntries / fullThreatsPageSize) || 1;
  const validFullThreatPage = Math.min(Math.max(1, fullThreatsPage), totalFullThreatPages);
  const startFullThreatIdx = (validFullThreatPage - 1) * fullThreatsPageSize;
  const endFullThreatIdx = Math.min(startFullThreatIdx + fullThreatsPageSize, totalFullThreatEntries);
  const paginatedFullThreats = filteredFullThreats.slice(startFullThreatIdx, endFullThreatIdx);

  // Filtered Audit Logs Calculation
  const logsToFilter = (allLogs && allLogs.length > 0) ? allLogs : auditLogs;

  const filteredAllLogs = logsToFilter.filter(log => {
    if (searchQuery) {
      const q = searchQuery.toLowerCase().trim();
      const searchableText = [
        log.action,
        log.user_email,
        log.admin_id,
        log.target_name,
        log.target_id,
        log.details,
        log.threat_name,
        log.severity,
        log.category,
        log.owasp
      ].filter(Boolean).join(' ').toLowerCase();

      const words = q.split(/\s+/).filter(w => w.length >= 2);
      const matchQuery = searchableText.includes(q) || (words.length > 0 && words.some(w => searchableText.includes(w)));
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

  const renderThreatModal = () => {
    if (!selectedThreat) return null;

    const severityColorMap = {
      critical: { border: 'border-t-red-500', badge: 'bg-red-500/10 text-red-500 border-red-500/30' },
      high: { border: 'border-t-orange-500', badge: 'bg-orange-500/10 text-orange-500 border-orange-500/30' },
      medium: { border: 'border-t-amber-500', badge: 'bg-amber-500/10 text-amber-500 border-amber-500/30' },
      low: { border: 'border-t-blue-500', badge: 'bg-blue-500/10 text-blue-500 border-blue-500/30' },
    };

    const sevKey = (selectedThreat.severity || 'medium').toLowerCase();
    const activeSev = severityColorMap[sevKey] || severityColorMap.medium;

    return (
      <div className="fixed inset-0 bg-slate-950/85 backdrop-blur-md flex items-center justify-center p-4 sm:p-6 z-[9999] animate-fade-in overflow-hidden">
        <div className={`bg-[#0b0f1a] text-slate-100 border border-slate-800 rounded-2xl max-w-3xl lg:max-w-4xl w-full shadow-2xl relative overflow-hidden flex flex-col transition-all duration-200 transform animate-in fade-in zoom-in-95 border-t-4 ${activeSev.border}`}>
          
          {/* Header Banner */}
          <div className="bg-[#111827]/90 p-4 sm:p-5 px-5 sm:px-6 border-b border-slate-800/80 relative">
            <button
              onClick={() => setSelectedThreat(null)}
              className="absolute top-4 right-4 text-slate-400 hover:text-white bg-[#1e293b] p-1.5 rounded-full transition-all cursor-pointer border border-slate-700 hover:scale-105"
              title="Close"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-2 flex-wrap mb-2 pr-10">
              <span className={`px-2.5 py-0.5 rounded-md text-[11px] font-black uppercase tracking-wider border flex items-center gap-1 ${getSeverityBadgeClass(selectedThreat.severity)}`}>
                <ShieldAlert className="w-3.5 h-3.5" />
                {selectedThreat.severity} SEVERITY
              </span>
              <span className="bg-cyan-500/10 text-cyan-400 text-[11px] font-black px-2.5 py-0.5 rounded-md border border-cyan-500/30 font-mono">
                CVSS {selectedThreat.cvss}
              </span>
              <span className="bg-purple-500/10 text-purple-400 text-[11px] font-black px-2.5 py-0.5 rounded-md border border-purple-500/30 font-mono">
                {selectedThreat.cwe}
              </span>
              <span className="bg-emerald-500/10 text-emerald-400 text-[11px] font-black px-2.5 py-0.5 rounded-md border border-emerald-500/30 flex items-center gap-1">
                <Clock className="w-3 h-3" />
                {selectedThreat.sla}
              </span>
              <span className="bg-red-500/10 text-red-400 text-[11px] font-black px-2.5 py-0.5 rounded-md border border-red-500/30 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse"></span>
                {selectedThreat.count} Detections
              </span>
            </div>

            <h2 className="text-xl sm:text-2xl font-extrabold text-white tracking-tight leading-snug font-display">
              {selectedThreat.title}
            </h2>
          </div>

          {/* Modal Body: Spacious Executive View (Zero Scrollbar) */}
          <div className="p-4 sm:p-5 px-5 sm:px-6 space-y-3.5 text-sm bg-[#0b0f1a] overflow-hidden">
            
            {/* Top Row: Category, OWASP Standard & Attack Vector Badges */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="bg-[#131c2e] p-2.5 px-3 rounded-xl border border-slate-800 flex items-center gap-2.5">
                <div className="w-7 h-7 rounded-lg bg-primary/20 text-primary flex items-center justify-center shrink-0">
                  <Layers className="w-3.5 h-3.5" />
                </div>
                <div className="truncate">
                  <span className="text-[9.5px] font-bold text-slate-400 uppercase tracking-wider block leading-none mb-0.5">Category</span>
                  <span className="font-bold text-slate-100 text-[12px] truncate block">{selectedThreat.category}</span>
                </div>
              </div>

              <div className="bg-[#131c2e] p-2.5 px-3 rounded-xl border border-slate-800 flex items-center gap-2.5">
                <div className="w-7 h-7 rounded-lg bg-indigo-500/20 text-indigo-400 flex items-center justify-center shrink-0">
                  <Shield className="w-3.5 h-3.5" />
                </div>
                <div className="truncate">
                  <span className="text-[9.5px] font-bold text-slate-400 uppercase tracking-wider block leading-none mb-0.5">OWASP Standard</span>
                  <span className="font-bold text-indigo-400 text-[12px] truncate block">{selectedThreat.owasp}</span>
                </div>
              </div>

              <div className="bg-[#131c2e] p-2.5 px-3 rounded-xl border border-slate-800 flex items-center gap-2.5">
                <div className="w-7 h-7 rounded-lg bg-rose-500/20 text-rose-400 flex items-center justify-center shrink-0">
                  <Radio className="w-3.5 h-3.5" />
                </div>
                <div className="truncate">
                  <span className="text-[9.5px] font-bold text-slate-400 uppercase tracking-wider block leading-none mb-0.5">Attack Vector</span>
                  <span className="font-bold text-rose-400 text-[12px] truncate block">{selectedThreat.attackVector}</span>
                </div>
              </div>
            </div>

            {/* Middle Grid: Threat Overview & Exploitation Risk */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
              <div className="bg-[#131c2e] p-3 px-3.5 rounded-xl border-l-4 border-l-primary border border-slate-800">
                <h3 className="font-bold text-slate-100 text-xs mb-1 flex items-center gap-1.5">
                  <Shield className="w-3.5 h-3.5 text-primary" /> Threat Overview
                </h3>
                <p className="text-slate-300 leading-relaxed text-[12px] line-clamp-3">
                  {selectedThreat.description}
                </p>
              </div>

              <div className="bg-[#131c2e] p-3 px-3.5 rounded-xl border-l-4 border-l-amber-500 border border-slate-800">
                <h3 className="font-bold text-amber-400 text-xs mb-1 flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5" /> Exploitation & Impact Risk
                </h3>
                <p className="text-slate-300 leading-relaxed text-[12px] line-clamp-3">
                  {selectedThreat.impact}
                </p>
              </div>
            </div>

            {/* Code Remediation Terminal Box */}
            <div className="bg-[#131c2e] rounded-xl border border-slate-800 overflow-hidden">
              <div className="bg-[#1e293b]/70 px-3.5 py-1.5 border-b border-slate-800 flex items-center justify-between">
                <h3 className="font-bold text-slate-200 text-xs flex items-center gap-2 font-mono">
                  <Terminal className="w-3.5 h-3.5 text-green-400" /> Recommended Security Fix
                </h3>

                <button
                  onClick={() => copyToClipboard(selectedThreat.remediation)}
                  className="flex items-center gap-1.5 px-2.5 py-1 bg-[#0f172a] hover:bg-slate-800 text-slate-200 rounded-md text-xs font-bold border border-slate-700 cursor-pointer transition-all active:scale-95 shadow-2xs"
                >
                  {copiedCode ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5 text-primary" />}
                  {copiedCode ? 'Copied' : 'Copy Code Snippet'}
                </button>
              </div>

              <div className="bg-[#030712] text-[#38bdf8] font-mono text-[11.5px] p-2.5 leading-relaxed whitespace-pre-wrap max-h-16 overflow-hidden">
                {selectedThreat.remediation}
              </div>
            </div>

            {/* Affected Target Endpoints */}
            {selectedThreat.affected_targets && selectedThreat.affected_targets.length > 0 && (
              <div className="bg-[#131c2e] p-2.5 px-3.5 rounded-xl border border-slate-800">
                <h3 className="font-bold text-slate-200 text-xs mb-1 flex items-center gap-1.5">
                  <ExternalLink className="w-3.5 h-3.5 text-primary" /> Affected Target Endpoints ({selectedThreat.affected_targets.length})
                </h3>
                <div className="flex flex-wrap gap-1.5">
                  {selectedThreat.affected_targets.slice(0, 4).map((url, idx) => (
                    <a
                      key={idx}
                      href={url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="bg-[#1e293b] border border-slate-700 hover:border-primary text-slate-200 font-mono text-[11px] px-2 py-0.5 rounded-md flex items-center gap-1 transition-all"
                    >
                      <span className="w-1.5 h-1.5 rounded-full bg-red-500"></span>
                      {url}
                    </a>
                  ))}
                  {selectedThreat.affected_targets.length > 4 && (
                    <span className="bg-[#1e293b] text-slate-400 font-mono text-[11px] px-2 py-0.5 rounded-md font-bold border border-slate-700">
                      +{selectedThreat.affected_targets.length - 4} more
                    </span>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Actions Footer */}
          <div className="p-3 px-5 sm:px-6 bg-[#111827] border-t border-slate-800/80 flex items-center justify-between flex-wrap gap-2.5">
            <button
              onClick={() => {
                const query = selectedThreat.title;
                setSelectedThreat(null);
                openFullLogsView(query);
              }}
              className="px-3.5 py-1.5 bg-primary/20 hover:bg-primary/30 text-sky-400 border border-primary/40 rounded-xl font-bold text-xs sm:text-sm flex items-center gap-2 cursor-pointer transition-all active:scale-95"
            >
              <Search className="w-4 h-4" />
              Filter Audit Logs for this Threat
            </button>

            <div className="flex items-center gap-2">
              <button
                onClick={() => copyBriefToClipboard(selectedThreat)}
                className="px-3.5 py-1.5 bg-[#1e293b] hover:bg-slate-700 text-slate-200 rounded-xl font-bold text-xs sm:text-sm cursor-pointer border border-slate-700 flex items-center gap-1.5 transition-all active:scale-95"
                title="Copy Executive Threat Brief to Clipboard"
              >
                {copiedBrief ? <Check className="w-4 h-4 text-green-400" /> : <FileText className="w-4 h-4 text-sky-400" />}
                {copiedBrief ? 'Brief Copied!' : 'Copy Threat Brief'}
              </button>

              <button
                onClick={() => setSelectedThreat(null)}
                className="px-5 py-1.5 bg-primary text-white hover:brightness-110 rounded-xl font-bold text-xs sm:text-sm cursor-pointer border-0 shadow-md shadow-primary/30 transition-all active:scale-95"
              >
                Close Window
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  };

  // Full Page Threat Intelligence View Mode
  if (isFullThreatsView) {
    return (
      <div className="w-full text-on-surface animate-fade-in pb-12">
        {/* Full Page Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between mb-lg gap-sm border-b border-outline-variant/60 pb-md">
          <div>
            <button 
              onClick={closeFullViews}
              className="flex items-center text-primary hover:underline font-bold text-[13px] mb-2 cursor-pointer bg-transparent border-0 p-0"
            >
              <ArrowLeft className="w-4 h-4 mr-1" />
              Back to Summary Dashboard
            </button>
            <h1 className="text-[26px] font-extrabold font-display tracking-tight text-on-surface flex items-center gap-2">
              <span className="material-symbols-outlined text-error text-[28px]">warning</span>
              Global Threat Intelligence Center
              <span className="bg-error/10 text-error text-[12px] font-extrabold px-2.5 py-0.5 rounded-full ml-2 border border-error/20">
                {totalFullThreatEntries} Active Threats
              </span>
            </h1>
            <p className="text-on-surface-variant text-[13.5px] mt-1">Vulnerability advisories, OWASP classifications, and technical remediation steps.</p>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => fetchStats(true)}
              disabled={loading}
              className="flex items-center gap-1.5 px-4 py-2 bg-surface-container border border-outline-variant text-on-surface hover:bg-surface-container-high rounded-xl text-[13px] font-bold transition-colors cursor-pointer shadow-2xs"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              Refresh Threats
            </button>
          </div>
        </div>

        {/* Threat Severity Quick Counters */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-md">
          <div 
            onClick={() => setThreatSeverityFilter('all')}
            className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
              threatSeverityFilter === 'all' 
                ? 'bg-primary/10 border-primary text-primary shadow-sm' 
                : 'bg-surface-container-lowest border-outline-variant/70 text-on-surface-variant hover:bg-surface-container-high'
            }`}
          >
            <div className="text-[11px] font-extrabold uppercase tracking-wider">Total Threats</div>
            <div className="text-2xl font-black mt-1">{totalThreatCount}</div>
          </div>
          <div 
            onClick={() => setThreatSeverityFilter('critical')}
            className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
              threatSeverityFilter === 'critical' 
                ? 'bg-red-500/10 border-red-500 text-red-500 shadow-sm' 
                : 'bg-surface-container-lowest border-outline-variant/70 text-on-surface-variant hover:bg-surface-container-high'
            }`}
          >
            <div className="text-[11px] font-extrabold uppercase tracking-wider text-red-500">Critical</div>
            <div className="text-2xl font-black text-red-500 mt-1">{criticalCount}</div>
          </div>
          <div 
            onClick={() => setThreatSeverityFilter('high')}
            className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
              threatSeverityFilter === 'high' 
                ? 'bg-orange-500/10 border-orange-500 text-orange-500 shadow-sm' 
                : 'bg-surface-container-lowest border-outline-variant/70 text-on-surface-variant hover:bg-surface-container-high'
            }`}
          >
            <div className="text-[11px] font-extrabold uppercase tracking-wider text-orange-500">High</div>
            <div className="text-2xl font-black text-orange-500 mt-1">{highCount}</div>
          </div>
          <div 
            onClick={() => setThreatSeverityFilter('medium')}
            className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
              threatSeverityFilter === 'medium' 
                ? 'bg-amber-500/10 border-amber-500 text-amber-500 shadow-sm' 
                : 'bg-surface-container-lowest border-outline-variant/70 text-on-surface-variant hover:bg-surface-container-high'
            }`}
          >
            <div className="text-[11px] font-extrabold uppercase tracking-wider text-amber-500">Medium</div>
            <div className="text-2xl font-black text-amber-500 mt-1">{mediumCount}</div>
          </div>
          <div 
            onClick={() => setThreatSeverityFilter('low')}
            className={`p-3.5 rounded-xl border cursor-pointer transition-all col-span-2 sm:col-span-1 ${
              threatSeverityFilter === 'low' 
                ? 'bg-blue-500/10 border-blue-500 text-blue-500 shadow-sm' 
                : 'bg-surface-container-lowest border-outline-variant/70 text-on-surface-variant hover:bg-surface-container-high'
            }`}
          >
            <div className="text-[11px] font-extrabold uppercase tracking-wider text-blue-500">Low</div>
            <div className="text-2xl font-black text-blue-500 mt-1">{lowCount}</div>
          </div>
        </div>

        {/* Filter and Search Bar */}
        <div className="mb-md bg-surface-container-lowest border border-outline-variant/70 rounded-xl p-4 flex flex-col md:flex-row items-center justify-between gap-3 shadow-2xs">
          <div className="flex flex-wrap items-center gap-3 w-full flex-1">
            
            {/* Search Input */}
            <div className="relative w-full sm:w-72">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant" />
              <input
                type="text"
                placeholder="Search threat title, OWASP, CWE..."
                value={threatSearch}
                onChange={(e) => setThreatSearch(e.target.value)}
                className="w-full pl-9 pr-3 py-2 bg-surface border border-outline-variant/60 rounded-lg text-[13px] text-on-surface focus:outline-none focus:border-primary"
              />
            </div>

            {/* Category Filter */}
            <div className="flex items-center gap-1.5 w-full sm:w-auto">
              <span className="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider shrink-0">Category:</span>
              <select
                value={threatCategoryFilter}
                onChange={(e) => setThreatCategoryFilter(e.target.value)}
                className="bg-surface border border-outline-variant/60 text-on-surface text-[13px] font-medium rounded-lg px-3 py-2 focus:outline-none focus:border-primary cursor-pointer w-full sm:w-auto max-w-[200px] truncate"
              >
                <option value="all">All Categories</option>
                {uniqueThreatCategories.map(cat => (
                  <option key={cat} value={cat}>{cat}</option>
                ))}
              </select>
            </div>

            {/* OWASP Filter */}
            <div className="flex items-center gap-1.5 w-full sm:w-auto">
              <span className="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider shrink-0">OWASP:</span>
              <select
                value={threatOwaspFilter}
                onChange={(e) => setThreatOwaspFilter(e.target.value)}
                className="bg-surface border border-outline-variant/60 text-on-surface text-[13px] font-medium rounded-lg px-3 py-2 focus:outline-none focus:border-primary cursor-pointer w-full sm:w-auto max-w-[220px] truncate"
              >
                <option value="all">All OWASP Standards</option>
                {uniqueThreatOwasps.map(owasp => (
                  <option key={owasp} value={owasp}>{owasp}</option>
                ))}
              </select>
            </div>

            {/* Sort By Dropdown */}
            <div className="flex items-center gap-1.5 w-full sm:w-auto">
              <span className="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider shrink-0">Sort By:</span>
              <select
                value={`${threatSortCol}_${threatSortDir}`}
                onChange={(e) => {
                  const parts = e.target.value.split('_');
                  setThreatSortCol(parts[0]);
                  setThreatSortDir(parts[1]);
                }}
                className="bg-surface border border-outline-variant/60 text-on-surface text-[13px] font-medium rounded-lg px-3 py-2 focus:outline-none focus:border-primary cursor-pointer w-full sm:w-auto"
              >
                <option value="severity_desc">Highest Severity</option>
                <option value="severity_asc">Lowest Severity</option>
                <option value="cvss_desc">Highest CVSS</option>
                <option value="cvss_asc">Lowest CVSS</option>
                <option value="detections_desc">Most Detections</option>
                <option value="detections_asc">Least Detections</option>
                <option value="title_asc">Title (A-Z)</option>
                <option value="title_desc">Title (Z-A)</option>
              </select>
            </div>

            {/* Reset Button */}
            {(threatSearch || threatSeverityFilter !== 'all' || threatCategoryFilter !== 'all' || threatOwaspFilter !== 'all' || threatSortCol !== 'severity') && (
              <button
                onClick={clearThreatFilters}
                className="text-error hover:underline text-[12.5px] font-bold flex items-center gap-1 cursor-pointer bg-transparent border-0 px-1 ml-auto"
              >
                <span className="material-symbols-outlined text-[16px]">close</span>
                Reset All Filters
              </button>
            )}
          </div>
        </div>

        {/* Full Page Threats Data List / Table */}
        <div className="bg-surface-container-lowest border border-outline-variant/70 rounded-xl overflow-hidden shadow-2xs flex flex-col">
          {loading ? (
            <div className="text-center py-16 text-on-surface-variant text-[14px]">Loading threat intelligence...</div>
          ) : totalFullThreatEntries === 0 ? (
            <div className="text-center py-16 text-on-surface-variant text-[14px]">No vulnerabilities match your search filter.</div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-[13.5px]">
                  <thead className="bg-surface-container-high/60 text-on-surface-variant text-[11px] uppercase tracking-wider select-none border-b border-outline-variant/70">
                    <tr>
                      <th className="p-3.5 font-bold w-12 text-center">#</th>
                      <th onClick={() => handleThreatSort('title')} className="p-3.5 font-bold cursor-pointer hover:text-primary transition-colors">
                        <div className="flex items-center gap-1">
                          Threat Title & Description
                          {threatSortCol === 'title' && <span className="text-[12px] text-primary">{threatSortDir === 'asc' ? '▲' : '▼'}</span>}
                        </div>
                      </th>
                      <th onClick={() => handleThreatSort('severity')} className="p-3.5 font-bold cursor-pointer hover:text-primary transition-colors">
                        <div className="flex items-center gap-1">
                          Severity
                          {threatSortCol === 'severity' && <span className="text-[12px] text-primary">{threatSortDir === 'asc' ? '▲' : '▼'}</span>}
                        </div>
                      </th>
                      <th onClick={() => handleThreatSort('cvss')} className="p-3.5 font-bold cursor-pointer hover:text-primary transition-colors">
                        <div className="flex items-center gap-1">
                          CVSS
                          {threatSortCol === 'cvss' && <span className="text-[12px] text-primary">{threatSortDir === 'asc' ? '▲' : '▼'}</span>}
                        </div>
                      </th>
                      <th onClick={() => handleThreatSort('category')} className="p-3.5 font-bold cursor-pointer hover:text-primary transition-colors">
                        <div className="flex items-center gap-1">
                          Category & OWASP
                          {threatSortCol === 'category' && <span className="text-[12px] text-primary">{threatSortDir === 'asc' ? '▲' : '▼'}</span>}
                        </div>
                      </th>
                      <th onClick={() => handleThreatSort('detections')} className="p-3.5 font-bold text-center cursor-pointer hover:text-primary transition-colors">
                        <div className="flex items-center justify-center gap-1">
                          Detections
                          {threatSortCol === 'detections' && <span className="text-[12px] text-primary">{threatSortDir === 'asc' ? '▲' : '▼'}</span>}
                        </div>
                      </th>
                      <th className="p-3.5 font-bold text-right pr-6">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-outline-variant/60">
                    {paginatedFullThreats.map((detail, i) => {
                      const rowIdx = startFullThreatIdx + i + 1;
                      return (
                        <tr 
                          key={i}
                          className="hover:bg-surface-container-high/60 transition-colors group"
                        >
                          <td className="p-3.5 text-center font-extrabold text-[12px] text-error">
                            {rowIdx}
                          </td>
                          <td className="p-3.5 max-w-md">
                            <h4 
                              onClick={() => setSelectedThreat(detail)}
                              className="font-bold text-on-surface text-[14px] hover:text-primary transition-colors leading-snug cursor-pointer flex items-center gap-1.5 group/title"
                              title="Click to inspect vulnerability diagnostic report"
                            >
                              {detail.title}
                              <Eye className="w-3.5 h-3.5 opacity-0 group-hover/title:opacity-100 transition-all text-primary shrink-0 transform group-hover/title:scale-110" />
                            </h4>
                            <p className="text-[12px] text-on-surface-variant line-clamp-1 mt-0.5">
                              {detail.description}
                            </p>
                          </td>
                          <td className="p-3.5 whitespace-nowrap">
                            <span className={`px-2.5 py-0.5 rounded-md text-[10.5px] font-extrabold uppercase tracking-wider border ${getSeverityBadgeClass(detail.severity)}`}>
                              {detail.severity}
                            </span>
                          </td>
                          <td className="p-3.5 font-mono font-bold text-[13px] text-on-surface whitespace-nowrap">
                            {detail.cvss}
                          </td>
                          <td className="p-3.5 text-[12.5px]">
                            <div className="font-medium text-on-surface">{detail.category}</div>
                            <div className="text-[11px] text-on-surface-variant font-mono">{detail.owasp}</div>
                          </td>
                          <td className="p-3.5 text-center whitespace-nowrap">
                            <span className="bg-surface-container-high border border-outline-variant/60 px-2.5 py-1 rounded-lg text-[12px] font-bold text-on-surface">
                              {detail.count} Found
                            </span>
                          </td>
                          <td className="p-3.5 text-right pr-6 whitespace-nowrap">
                            <button
                              type="button"
                              onClick={(e) => {
                                e.preventDefault();
                                e.stopPropagation();
                                setSelectedThreat(detail);
                              }}
                              className="px-3.5 py-1.5 bg-primary/10 hover:bg-primary text-primary hover:text-white rounded-xl text-[12px] font-bold inline-flex items-center gap-1.5 transition-all cursor-pointer border border-primary/30 shadow-2xs hover:scale-105 active:scale-95 hover:shadow-md hover:shadow-primary/20"
                            >
                              <Eye className="w-3.5 h-3.5" />
                              View Details
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {/* Pagination Controls */}
              <div className="p-4 border-t border-outline-variant/60 bg-surface-container-lowest/50 flex flex-col sm:flex-row items-center justify-between gap-3 text-[13px] text-on-surface-variant">
                <div className="flex items-center gap-2">
                  <span>Rows per page:</span>
                  <select
                    value={fullThreatsPageSize}
                    onChange={(e) => {
                      setFullThreatsPageSize(Number(e.target.value));
                      setFullThreatsPage(1);
                    }}
                    className="bg-surface border border-outline-variant/60 text-on-surface rounded-md px-2 py-1 text-[12px] font-bold focus:outline-none cursor-pointer"
                  >
                    <option value={10}>10</option>
                    <option value={25}>25</option>
                    <option value={50}>50</option>
                    <option value={100}>100</option>
                  </select>
                  <span className="ml-2 font-medium">
                    {totalFullThreatEntries === 0 ? '0' : `${startFullThreatIdx + 1} - ${endFullThreatIdx}`} of {totalFullThreatEntries} records
                  </span>
                </div>

                <div className="flex items-center gap-1.5">
                  <button
                    onClick={() => setFullThreatsPage(prev => Math.max(1, prev - 1))}
                    disabled={validFullThreatPage === 1}
                    className="px-3 py-1.5 rounded-lg border border-outline-variant/60 bg-surface hover:bg-surface-container-high text-on-surface font-bold text-[12px] disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer transition-colors"
                  >
                    Previous
                  </button>

                  <div className="flex items-center gap-1 px-1">
                    {Array.from({ length: totalFullThreatPages }, (_, i) => i + 1)
                      .filter(p => p === 1 || p === totalFullThreatPages || Math.abs(p - validFullThreatPage) <= 1)
                      .map((page, idx, arr) => {
                        const prev = arr[idx - 1];
                        return (
                          <React.Fragment key={page}>
                            {prev && page - prev > 1 && <span className="px-1 text-on-surface-variant text-[12px]">...</span>}
                            <button
                              onClick={() => setFullThreatsPage(page)}
                              className={`w-8 h-8 rounded-lg text-[12px] font-bold transition-colors cursor-pointer ${
                                validFullThreatPage === page
                                  ? 'bg-error text-white shadow-2xs'
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
                    onClick={() => setFullThreatsPage(prev => Math.min(totalFullThreatPages, prev + 1))}
                    disabled={validFullThreatPage >= totalFullThreatPages}
                    className="px-3 py-1.5 rounded-lg border border-outline-variant/60 bg-surface hover:bg-surface-container-high text-on-surface font-bold text-[12px] disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer transition-colors"
                  >
                    Next
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
        {selectedThreat && renderThreatModal()}
      </div>
    );
  }
  // Full Page Audit Logs Mode
  if (isFullLogsView) {
    return (
      <div className="w-full text-on-surface animate-fade-in pb-12">
        {/* Full Page Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between mb-lg gap-sm border-b border-outline-variant/60 pb-md">
          <div>
            <button 
              onClick={closeFullViews}
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
                onClick={clearLogFilters}
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
        {selectedThreat && renderThreatModal()}
      </div>
    );
  }

  // Dashboard Overview Mode
  return (
    <div className="w-full text-on-surface animate-fade-in relative pb-12">
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
        {/* Threat Intelligence Card */}
        <div>
          <div className="flex items-center justify-between mb-md">
            <h2 className="font-headline-sm font-bold text-on-surface flex items-center text-[18px]">
              <span className="material-symbols-outlined text-error mr-2 text-[20px]">warning</span>
              Global Threat Intelligence
            </h2>
            <button
              onClick={openFullThreatsView}
              className="flex items-center gap-1.5 px-3.5 py-1.5 bg-error/10 hover:bg-error/20 text-error rounded-xl transition-colors font-bold text-[12px] cursor-pointer border border-error/20"
            >
              <List className="w-4 h-4" />
              View All Threats
            </button>
          </div>
          <div className="bg-surface-container-lowest border border-outline-variant rounded-2xl overflow-hidden shadow-2xs p-4 flex flex-col justify-between min-h-[420px]">
            {loading ? (
              <div className="text-center text-on-surface-variant text-[13px] py-8">Loading threats...</div>
            ) : trends.length === 0 ? (
              <div className="text-center text-on-surface-variant text-[13px] py-8">No global vulnerabilities recorded yet.</div>
            ) : (
              <div>
                <ul className="divide-y divide-outline-variant/60">
                  {paginatedCardThreats.map((detail, i) => {
                    const globalIdx = startThreatCardIdx + i + 1;
                    return (
                      <li 
                        key={i} 
                        className="py-3 px-3 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-surface-container-high/40 transition-all group my-1"
                      >
                        <div className="flex items-start gap-3 pr-2">
                          <span className="w-7 h-7 rounded-full bg-error/10 text-error flex items-center justify-center text-[12px] font-extrabold shrink-0 mt-0.5 border border-error/20">
                            {globalIdx}
                          </span>
                          <div>
                            <h4 className="font-bold text-on-surface text-[13.5px] group-hover:text-primary transition-colors leading-snug">
                              {detail.title}
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
                            {detail.count} Found
                          </span>
                        </div>
                      </li>
                    );
                  })}
                </ul>
              </div>
            )}

            {/* Standardized In-Card Pagination for Threat Intelligence */}
            {totalThreatCount > 0 && (
              <div className="mt-4 pt-3 border-t border-outline-variant/60 flex flex-col sm:flex-row items-center justify-between gap-2 text-[12.5px] text-on-surface-variant">
                <div className="flex items-center gap-1.5">
                  <span>Rows:</span>
                  <select
                    value={threatCardPageSize}
                    onChange={(e) => {
                      setThreatCardPageSize(Number(e.target.value));
                      setThreatCardPage(1);
                    }}
                    className="bg-surface border border-outline-variant/60 text-on-surface rounded-md px-2 py-1 text-[11.5px] font-bold focus:outline-none cursor-pointer"
                  >
                    <option value={5}>5</option>
                    <option value={10}>10</option>
                    <option value={15}>15</option>
                  </select>
                  <span className="ml-1 font-medium">
                    {startThreatCardIdx + 1} - {endThreatCardIdx} of {totalThreatCount} records
                  </span>
                </div>

                <div className="flex items-center gap-1">
                  <button
                    onClick={() => setThreatCardPage(prev => Math.max(1, prev - 1))}
                    disabled={validThreatCardPage === 1}
                    className="px-2.5 py-1 rounded-md border border-outline-variant/60 bg-surface hover:bg-surface-container-high text-on-surface font-bold text-[11.5px] disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
                  >
                    Previous
                  </button>

                  <div className="flex items-center gap-1 px-1">
                    {Array.from({ length: totalThreatCardPages }, (_, i) => i + 1).map(page => (
                      <button
                        key={page}
                        onClick={() => setThreatCardPage(page)}
                        className={`w-7 h-7 rounded-md text-[11.5px] font-bold cursor-pointer ${
                          validThreatCardPage === page
                            ? 'bg-error text-white shadow-2xs'
                            : 'bg-surface hover:bg-surface-container-high border border-outline-variant/60 text-on-surface'
                        }`}
                      >
                        {page}
                      </button>
                    ))}
                  </div>

                  <button
                    onClick={() => setThreatCardPage(prev => Math.min(totalThreatCardPages, prev + 1))}
                    disabled={validThreatCardPage >= totalThreatCardPages}
                    className="px-2.5 py-1 rounded-md border border-outline-variant/60 bg-surface hover:bg-surface-container-high text-on-surface font-bold text-[11.5px] disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Admin Audit Logs Card */}
        <div>
          <div className="flex items-center justify-between mb-md">
            <h2 className="font-headline-sm font-bold text-on-surface flex items-center text-[18px]">
              <span className="material-symbols-outlined text-primary mr-2 text-[20px]">policy</span>
              Admin Audit Logs
            </h2>
            <button
              onClick={() => openFullLogsView()}
              className="flex items-center gap-1.5 px-3.5 py-1.5 bg-primary/10 hover:bg-primary/20 text-primary rounded-xl transition-colors font-bold text-[12px] cursor-pointer border border-primary/20"
            >
              <List className="w-4 h-4" />
              View All Audit Logs
            </button>
          </div>
          <div className="bg-surface-container-lowest border border-outline-variant rounded-2xl overflow-hidden shadow-2xs p-4 flex flex-col justify-between min-h-[420px]">
            {loading ? (
              <div className="text-center text-on-surface-variant text-[13px] py-8">Loading logs...</div>
            ) : auditLogs.length === 0 ? (
              <div className="text-center text-on-surface-variant text-[13px] py-8">No admin actions recorded yet.</div>
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
              </div>
            )}
            <div className="mt-4 pt-3 border-t border-outline-variant text-center">
              <button
                onClick={() => openFullLogsView()}
                className="text-primary hover:underline text-[13px] font-bold inline-flex items-center gap-1 cursor-pointer bg-transparent border-0"
              >
                View All Complete Audit Logs &rarr;
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Global Threat Detail Modal */}
      {selectedThreat && renderThreatModal()}
    </div>
  );
};

export default LogsAndThreats;
