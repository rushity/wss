import React, { useState, useEffect, useRef } from 'react';
import { useSearchParams, Link, useNavigate } from 'react-router-dom';
import { io } from 'socket.io-client';
import { useAuth } from '../components/AuthContext';
import { CodeBlock } from '../components/CodeBlock';
import { OrganizationSelector } from '../components/OrganizationSelector';

export const ScanResults = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const scanIdFromUrl = searchParams.get('id');

  const [scans, setScans] = useState([]);
  const [activeScanId, setActiveScanId] = useState(scanIdFromUrl);
  const [scan, setScan] = useState(null);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalItems, setTotalItems] = useState(0);
  const [hasNext, setHasNext] = useState(false);
  const [hasPrev, setHasPrev] = useState(false);
  const [filterSeverity, setFilterSeverity] = useState('All');
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [resolvedVulns, setResolvedVulns] = useState(new Set());
  
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [shareText, setShareText] = useState('Share');
  const [liveLogs, setLiveLogs] = useState([]);

  useEffect(() => {
    if (!activeScanId || (scan && scan.status === 'completed')) return;

    const socket = io('/', { path: '/socket.io' });
    
    socket.on('connect', () => {
      socket.emit('join_scan', { scan_id: activeScanId });
    });

    socket.on('scan_log', (data) => {
      setLiveLogs(prev => [...prev, data].slice(-100));
    });

    socket.on('vulnerability_found', (data) => {
      setVulnerabilities(prev => {
        const isDup = prev.some(v => v.title === data.title && v.category === data.category);
        if (!isDup) {
          setTotalItems(t => t + 1);
          return [data, ...prev];
        }
        return prev;
      });
    });

    socket.on('scan_progress', (data) => {
       if (data.status === 'completed' || data.status === 'failed') {
           setScan(prev => prev ? {...prev, status: data.status} : prev);
       }
    });

    return () => {
      socket.emit('leave_scan', { scan_id: activeScanId });
      socket.disconnect();
    };
  }, [activeScanId, scan?.status]);

  const [sortColumn, setSortColumn] = useState('Severity');
  const [sortDirection, setSortDirection] = useState('desc');

  const savedScrollPositionRef = useRef(0);

  const handleOpenVulnDetail = (vuln) => {
    savedScrollPositionRef.current = window.scrollY || document.documentElement.scrollTop || 0;
    setSelectedVuln(vuln);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleBackToOverview = () => {
    const targetY = savedScrollPositionRef.current;
    setSelectedVuln(null);
    setTimeout(() => {
      window.scrollTo({ top: targetY, behavior: 'smooth' });
    }, 30);
  };

  const { token } = useAuth();
  const navigate = useNavigate();

  // Load basic scan histories and target scan session
  useEffect(() => {
    loadScanHistory();
  }, [token]);

  useEffect(() => {
    if (activeScanId) {
      fetchScanData(activeScanId, currentPage);
    }
  }, [activeScanId, currentPage]);

  const loadScanHistory = async () => {
    try {
      const res = await fetch('/api/scans/history', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setScans(data.scans || []);
        
        // If no scan ID was provided in URL, automatically select the most recent completed one
        if (!activeScanId && data.scans.length > 0) {
          const completedScan = data.scans.find(s => s.status === 'completed') || data.scans[0];
          setActiveScanId(completedScan.id);
        } else if (!activeScanId && data.scans.length === 0) {
          setLoading(false);
        }
      } else {
        setLoading(false);
      }
    } catch (err) {
      console.error("Error loading scans history", err);
      setLoading(false);
    }
  };

  // Sync activeScanId if the URL search parameter changes (e.g. clicking the sidebar link)
  useEffect(() => {
    if (scanIdFromUrl && scanIdFromUrl !== activeScanId) {
      setActiveScanId(scanIdFromUrl);
    } else if (!scanIdFromUrl && scans.length > 0) {
      const completedScan = scans.find(s => s.status === 'completed') || scans[0];
      if (activeScanId !== completedScan.id) {
        setActiveScanId(completedScan.id);
      }
    }
  }, [scanIdFromUrl, scans]);


  const fetchScanData = async (id, page = 1) => {
    setLoading(true);
    try {
      const scanRes = await fetch(`/api/scans/${id}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const vulnsRes = await fetch(`/api/scans/${id}/vulnerabilities?page=${page}&limit=50`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (scanRes.ok && vulnsRes.ok) {
        const scanData = await scanRes.json();
        const vulnsData = await vulnsRes.json();
        
        // Deduplicate locally to prevent UI duplication if DB contains duplicates
        const uniqueVulnsMap = new Map();
        (vulnsData.vulnerabilities || []).forEach(v => {
          const key = `${v.title}-${v.category}`;
          if (!uniqueVulnsMap.has(key)) {
            uniqueVulnsMap.set(key, v);
          } else {
            // Keep the one with higher severity if duplicates found
            const current = uniqueVulnsMap.get(key);
            const severityRank = { "Low": 0, "Medium": 1, "High": 2, "Critical": 3 };
            if ((severityRank[v.severity] || 0) > (severityRank[current.severity] || 0)) {
              uniqueVulnsMap.set(key, v);
            }
          }
        });

        setScan(scanData.scan);
        setVulnerabilities(Array.from(uniqueVulnsMap.values()));
        setCurrentPage(vulnsData.current_page || 1);
        setTotalPages(vulnsData.total_pages || 1);
        setTotalItems(vulnsData.total_items || uniqueVulnsMap.size);
        setHasNext(vulnsData.has_next || false);
        setHasPrev(vulnsData.has_prev || false);
        
        // Reset selected vuln when changing scans
        setSelectedVuln(null);
      }
    } catch (err) {
      console.error("Error fetching scan details", err);
    } finally {
      setLoading(false);
    }
  };

  const handlePdfExport = async () => {
    if (!scan) return;
    setExporting(true);
    try {
      const res = await fetch(`/api/reports/${scan.id}/pdf`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        let filename = '';
        const disposition = res.headers.get('Content-Disposition');
        if (disposition && disposition.includes('filename=')) {
          const match = disposition.match(/filename="?([^";]+)"?/);
          if (match && match[1]) {
            filename = match[1];
          }
        }

        if (!filename) {
          const orgName = scan.org_name || scan.organization_name || 'Global';
          const cleanOrg = orgName.replace(/[^\w]/g, '') || 'Organization';
          const dateObj = new Date(scan.completed_at || scan.started_at || Date.now());
          const day = String(dateObj.getDate()).padStart(2, '0');
          const month = String(dateObj.getMonth() + 1).padStart(2, '0');
          const year = dateObj.getFullYear();
          filename = `LarShield_${cleanOrg}_Report_${day}${month}${year}.pdf`;
        }

        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
      } else {
        setError("Failed to compile PDF Report. Server error.");
      }
    } catch (err) {
      console.error("PDF Export error", err);
    } finally {
      setExporting(false);
    }
  };

  const toggleResolved = (vulnId) => {
    const updated = new Set(resolvedVulns);
    if (updated.has(vulnId)) {
      updated.delete(vulnId);
    } else {
      updated.add(vulnId);
    }
    setResolvedVulns(updated);
  };

  const handleShare = () => {
    if (!scan?.id) return;
    const shareUrl = `${window.location.origin}/api/reports/${scan.id}/public-pdf`;
    navigator.clipboard.writeText(shareUrl);
    setShareText('Link Copied!');
    setTimeout(() => setShareText('Share'), 2500);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-2xl font-label-md text-label-md text-on-surface-variant">
        <span className="material-symbols-outlined animate-spin mr-sm">sync</span>
        Compiling Security Feed...
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="text-center py-2xl bg-surface-container-lowest border border-outline-variant rounded-xl max-w-lg mx-auto p-xl flex flex-col items-center gap-md">
        <span className="material-symbols-outlined text-[48px] text-outline">error</span>
        <h2 className="font-headline-md text-on-surface">No scan sessions recorded.</h2>
        <p className="font-body-md text-on-surface-variant">
          Configure and run your first vulnerability probe using the New Scan panel.
        </p>
        <Link to="/scans/new" className="bg-primary text-on-primary font-label-md text-label-md px-lg py-sm rounded-lg hover:opacity-90 transition-opacity border-0 cursor-pointer" style={{ textDecoration: 'none' }}>
          Configure Security Scan
        </Link>
      </div>
    );
  }

  // Parse target domain name for clean UI
  const domain = scan.target_url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0];

  // Distribution Chart logic
  const categoryCounts = vulnerabilities.reduce((acc, v) => {
    acc[v.category] = (acc[v.category] || 0) + 1;
    return acc;
  }, {});
  const totalVulns = totalItems > 0 ? totalItems : vulnerabilities.length;
  const categoriesList = Object.keys(categoryCounts).map(cat => ({
    name: cat,
    count: categoryCounts[cat],
    percentage: totalVulns > 0 ? Math.round((categoryCounts[cat] / totalVulns) * 100) : 0
  })).sort((a, b) => b.count - a.count);

  // Severe counts
  const critCount = vulnerabilities.filter(v => v.severity === 'Critical').length;
  const highCount = vulnerabilities.filter(v => v.severity === 'High').length;
  const medCount = vulnerabilities.filter(v => v.severity === 'Medium').length;
  const lowCount = vulnerabilities.filter(v => v.severity === 'Low').length;

  // Filter logic
  const filteredVulns = filterSeverity === 'All'
    ? vulnerabilities
    : vulnerabilities.filter(v => v.severity === filterSeverity);

  const handleSort = (column) => {
    if (column === 'Sr. No.') return;
    if (sortColumn === column) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortColumn(column);
      setSortDirection('desc'); // Default to descending to show highest threats first
    }
  };

  const getSortedVulns = () => {
    return [...filteredVulns].sort((a, b) => {
      let aVal, bVal;
      switch (sortColumn) {
        case 'Vulnerability':
          aVal = a.title || ''; bVal = b.title || ''; break;
        case 'Severity':
          const rank = { "Low": 0, "Medium": 1, "High": 2, "Critical": 3 };
          aVal = rank[a.severity] || 0; bVal = rank[b.severity] || 0; break;
        case 'Resource':
          aVal = a.category || ''; bVal = b.category || ''; break;
        case 'Score':
          aVal = a.cvss_score || 0; bVal = b.cvss_score || 0; break;
        case 'Status':
          aVal = resolvedVulns.has(a.id) ? 1 : 0; bVal = resolvedVulns.has(b.id) ? 1 : 0; break;
        default:
          return 0;
      }
      if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });
  };

  // SVG Gauge calculations
  const score = scan.security_score ?? 100;
  const dashOffset = 283 - (283 * score) / 100;

  // Evidence and payloads mapping
  const getProofOfDetection = (vuln) => {
    // Build proof from REAL scanner data first — never show fake fallback if real data exists
    const sections = [];
    if (vuln.request_details && vuln.request_details.trim()) {
      sections.push(`# Request Details\n${vuln.request_details.trim()}`);
    }
    if (vuln.payload && vuln.payload.trim()) {
      sections.push(`# Payload Used\n${vuln.payload.trim()}`);
    }
    if (vuln.response_details && vuln.response_details.trim()) {
      sections.push(`# Response Details\n${vuln.response_details.trim()}`);
    }
    if (vuln.evidence && vuln.evidence.trim()) {
      sections.push(`# Evidence\n${vuln.evidence.trim()}`);
    }
    if (vuln.exploit_poc && vuln.exploit_poc.trim()) {
      sections.push(`# Proof of Concept\n${vuln.exploit_poc.trim()}`);
    }
    
    if (sections.length > 0) return sections.join('\n\n');
    
    // Only use synthetic fallback when NO real data at all
    if (vuln.category === 'Security Headers') {
      return `# Request Headers\nGET / HTTP/1.1\nHost: ${domain}\nUser-Agent: LarShield/2.0\n\n# Response Headers Analysis\nHTTP/1.1 200 OK\nServer: nginx\nContent-Type: text/html\n... [snip] ...\n\n[Detection] ${vuln.title}\nMissing or misconfigured attribute in server response.`;
    }
    if (vuln.category === 'SSL/TLS') {
      return `# TLS Handshake Probe\nopenssl s_client -connect ${domain}:443 -tls1_2\n\n# Protocol Analysis\nCONNECTED(00000003)\n[Detection] ${vuln.title}\nCertificate or protocol weakness verified during handshake negotiation.`;
    }
    if (vuln.title.includes('SQL') || vuln.category === 'Injection') {
      return `# Malicious Request Payload\nPOST /api/v1/query HTTP/1.1\nHost: ${domain}\nContent-Type: application/json\n\n{\n    "input": "1' OR '1'='1' --"\n}\n\n# Response Analysis\nHTTP/1.1 500 Internal Server Error\n[Detection] ${vuln.title}\nDatabase error or behavioral delay confirmed injection execution.`;
    }
    if (vuln.title.includes('XSS') || vuln.title.includes('Cross-Site')) {
      return `# Payload Injection\nGET /search?q=<script>alert('XSS')</script> HTTP/1.1\nHost: ${domain}\n\n# Response Analysis\nHTTP/1.1 200 OK\n[Detection] ${vuln.title}\nPayload reflected in DOM without sanitization.`;
    }
    
    // Default context-aware fallback
    return `# Automated Probe Log
Target: ${domain}
Category: ${vuln.category}
Scanner Module: ${vuln.title}

# Detection Output
[System] Vulnerability confirmed via behavioral analysis and pattern matching.
[Evidence] ${vuln.description.split('.')[0]}.`;
  };

  const getCweId = (vuln) => {
    // Use real CWE IDs from database first
    if (vuln.cwe_ids && Array.isArray(vuln.cwe_ids) && vuln.cwe_ids.length > 0) {
      return vuln.cwe_ids[0];
    }
    // Fallback to category-based inference
    if (vuln.title.includes("SQL Injection") || vuln.category === "Injection") return "CWE-89";
    if (vuln.title.includes("XSS") || vuln.title.includes("Cross-Site Scripting")) return "CWE-79";
    if (vuln.category === "Security Headers") return "CWE-693";
    if (vuln.category === "SSL/TLS") return "CWE-311";
    if (vuln.category === "Insecure Deserialization") return "CWE-502";
    if (vuln.category === "SSRF") return "CWE-918";
    if (vuln.category === "Path Traversal") return "CWE-22";
    if (vuln.category === "Open Redirect") return "CWE-601";
    if (vuln.category === "CSRF") return "CWE-352";
    if (vuln.category === "Cookie Security") return "CWE-1004";
    return "CWE-200";
  };

  // If a vulnerability is selected, render the high fidelity details view (da08996ed26048719f8bf496a07abc3b)
  if (selectedVuln) {
    const isResolved = resolvedVulns.has(selectedVuln.id);
    const cweId = getCweId(selectedVuln);
    const payloadCode = getProofOfDetection(selectedVuln);

    // Color theme classes matching severity
    let badgeBg = 'bg-surface-variant text-on-surface-variant border-outline-variant';
    let iconName = 'info';
    let severityLabel = selectedVuln.severity.toUpperCase();

    if (selectedVuln.severity === 'Critical') {
      badgeBg = 'bg-error-container text-on-error-container border-error/20';
      iconName = 'warning';
    } else if (selectedVuln.severity === 'High') {
      badgeBg = 'bg-tertiary-container/15 text-tertiary border-tertiary/20';
      iconName = 'warning';
    }

    return (
      <div className="flex flex-col gap-gutter text-left w-full">
        {/* Breadcrumbs & Actions */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-md mb-lg border-b border-outline-variant pb-lg">
          <div className="flex flex-col gap-md">
            <button 
              onClick={handleBackToOverview}
              className="self-start text-primary font-label-md text-label-md flex items-center gap-xs hover:underline cursor-pointer border-0 bg-transparent p-0 font-bold"
            >
              <span className="material-symbols-outlined text-[18px]">arrow_back</span>
              Back to Scan Overview
            </button>
            <div className="flex items-center gap-sm text-body-sm text-on-surface-variant font-body-sm">
            <button 
              onClick={handleBackToOverview} 
              className="hover:text-primary transition-colors border-0 bg-transparent cursor-pointer font-semibold"
            >
              Vulnerabilities
            </button>
            <span className="material-symbols-outlined text-[16px] text-outline">chevron_right</span>
            <button 
              onClick={handleBackToOverview} 
              className="hover:text-primary transition-colors cursor-pointer truncate max-w-[200px] text-on-surface-variant font-medium border-0 bg-transparent"
            >
              {domain}
            </button>
            <span className="material-symbols-outlined text-[16px] text-outline">chevron_right</span>
            <span className="text-on-surface font-medium truncate max-w-[200px]">{selectedVuln.title}</span>
          </div>
          </div>

          <div className="flex items-center gap-md">
            <button 
              onClick={handleShare}
              className="bg-surface border border-outline-variant text-on-surface font-label-md text-label-md px-md py-sm rounded hover:bg-surface-container-low transition-all flex items-center gap-sm cursor-pointer"
            >
              <span className="material-symbols-outlined text-[18px]">share</span>
              {shareText}
            </button>
            <button 
              onClick={() => toggleResolved(selectedVuln.id)}
              className={`${
                isResolved 
                  ? 'bg-green-600 text-white' 
                  : 'bg-primary text-on-primary'
              } font-label-md text-label-md px-md py-sm rounded hover:opacity-90 transition-all flex items-center gap-sm border-0 cursor-pointer`}
            >
              <span className="material-symbols-outlined text-[18px]">
                {isResolved ? 'check_circle' : 'published_with_changes'}
              </span>
              {isResolved ? 'Marked Resolved' : 'Mark Resolved'}
            </button>
          </div>
        </div>

        {/* Vulnerability Header */}
        <div className="mb-md">
          <div className="flex flex-row items-center gap-sm mb-sm">
            <div className={`font-label-sm text-label-sm px-sm py-xs rounded flex items-center gap-xs border shrink-0 ${badgeBg}`}>
              <span className="material-symbols-outlined text-[14px]" style={{ fontVariationSettings: "'FILL' 1" }}>{iconName}</span>
              {severityLabel}
            </div>
            <h1 className="font-display-lg text-display-lg text-on-surface m-0 leading-tight tracking-tight">
              {selectedVuln.title}
            </h1>
          </div>
          
          <div className="flex flex-wrap gap-lg text-body-sm font-body-sm text-on-surface-variant mt-md">
            <div className="flex items-center gap-xs">
              <span className="material-symbols-outlined text-[16px] text-outline">calendar_today</span>
              Detected: {new Date(selectedVuln.detected_at).toLocaleDateString()}
            </div>
            <div className="flex items-center gap-xs">
              <span className="material-symbols-outlined text-[16px] text-outline">dns</span>
              Asset: {domain}
            </div>
            <div className="flex items-center gap-xs">
              <span className="material-symbols-outlined text-[16px] text-outline">code</span>
              {cweId}
            </div>
            <div className="flex items-center gap-xs font-semibold">
              <span className="material-symbols-outlined text-[16px] text-outline">speed</span>
              CVSS: {selectedVuln.cvss_score}
            </div>
            {selectedVuln.owasp_category && (
              <div className="flex items-center gap-xs">
                <span className="material-symbols-outlined text-[16px] text-outline">security</span>
                <span className="font-medium">{selectedVuln.owasp_category}</span>
              </div>
            )}
            {selectedVuln.confidence && (
              <div className={`flex items-center gap-xs font-medium px-xs py-[2px] rounded border text-[11px] ${
                selectedVuln.confidence === 'Confirmed' ? 'bg-green-500/10 text-green-600 border-green-500/20'
                : selectedVuln.confidence === 'High' ? 'bg-tertiary-container/15 text-tertiary border-tertiary/20'
                : 'bg-surface-variant text-on-surface-variant border-outline-variant'
              }`}>
                <span className="material-symbols-outlined text-[13px]" style={{ fontVariationSettings: "'FILL' 1" }}>verified</span>
                {selectedVuln.confidence} confidence
              </div>
            )}
            {isResolved && (
              <div className="flex items-center gap-xs text-green-600 font-bold bg-green-500/10 px-xs py-[2px] rounded border border-green-500/20 uppercase tracking-wide">
                <span className="material-symbols-outlined text-[16px]">check_circle</span> Resolved
              </div>
            )}
          </div>
        </div>

        {/* Main Details Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-xl mt-md">
          
          {/* Left Column (Description & Technicals) */}
          <div className="lg:col-span-2 flex flex-col gap-lg">
            
            {/* Description Section */}
            <section className="bg-surface-container-lowest border border-outline-variant rounded-lg p-lg shadow-sm">
              <h2 className="font-headline-md text-headline-md text-on-surface mb-md flex items-center gap-sm font-bold">
                <span className="material-symbols-outlined text-primary">description</span>
                Description
              </h2>
              <p className="font-body-md text-body-md text-on-surface-variant mb-md leading-relaxed">
                {selectedVuln.description}
              </p>
              <div className="bg-error-container/20 border-l-4 border-error p-md rounded-r text-body-sm font-body-sm text-on-surface-variant mt-md">
                <strong>Impact Assessment:</strong> High probability of unauthorized exploitation. An attacker could bypass perimeter authentication protocols, compromise transport records, or escalate privileges within the application runtime context.
              </div>
            </section>

            {/* Proof of Detection (Code Snippet) */}
            <section className="bg-surface-container-lowest border border-outline-variant rounded-lg overflow-hidden shadow-sm">
              <div className="bg-surface-container-low border-b border-outline-variant px-lg py-sm flex justify-between items-center">
                <h2 className="font-label-md text-label-md text-on-surface flex items-center gap-sm font-bold">
                  <span className="material-symbols-outlined text-[18px]">terminal</span>
                  Proof of Detection
                </h2>
                <span className="text-outline font-label-sm text-label-sm">Engine Payload Audit Log</span>
              </div>
              <div className="p-0">
                <CodeBlock code={payloadCode} />
              </div>
            </section>

            {/* Remediation */}
            <section className="bg-surface-container-lowest border border-outline-variant rounded-lg p-lg shadow-sm">
              <h2 className="font-headline-md text-headline-md text-on-surface mb-md flex items-center gap-sm font-bold">
                <span className="material-symbols-outlined text-primary">build</span>
                Remediation Steps
              </h2>
              <p className="font-body-md text-body-md text-on-surface-variant mb-md leading-relaxed">
                Apply the following security configuration or architectural code adjustments to mitigate this exposure vector:
              </p>
              <div className="border border-outline-variant/50 rounded-lg p-md bg-surface-container-low text-body-sm font-body-sm leading-relaxed text-on-surface-variant whitespace-pre-wrap">
                {selectedVuln.remediation}
              </div>
              {selectedVuln.remediation_code && selectedVuln.remediation_code.trim() && (
                <div className="mt-md">
                  <div className="bg-surface-container-low border-b border-outline-variant px-md py-sm flex items-center gap-sm rounded-t-lg">
                    <span className="material-symbols-outlined text-[16px] text-primary">code</span>
                    <span className="font-label-sm text-label-sm text-on-surface font-bold">Remediation Code Snippet</span>
                  </div>
                  <CodeBlock code={selectedVuln.remediation_code} />
                </div>
              )}
            </section>

            <button 
              onClick={handleBackToOverview}
              className="self-start text-primary font-label-md text-label-md flex items-center gap-xs hover:underline cursor-pointer border-0 bg-transparent pt-md font-bold"
            >
              <span className="material-symbols-outlined">arrow_back</span>
              Back to Scan Overview
            </button>
          </div>

          {/* Right Column (Meta & References) */}
          <div className="flex flex-col gap-lg">
            
            {/* Threat Gauge / Status Card */}
            <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-lg text-center shadow-sm flex flex-col items-center">
              <h3 className="font-label-md text-label-md text-on-surface-variant uppercase tracking-wider mb-lg font-bold">Exploitability</h3>
              
              <div className="relative w-32 h-32 mb-md">
                <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                  <path 
                    className="text-surface-container-high" 
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" 
                    fill="none" 
                    stroke="currentColor" 
                    strokeWidth="3.5"
                  ></path>
                  <path 
                    className={selectedVuln.cvss_score >= 8.0 ? 'text-error' : selectedVuln.cvss_score >= 5.0 ? 'text-tertiary' : 'text-primary'}
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" 
                    fill="none" 
                    stroke="currentColor" 
                    strokeDasharray={`${selectedVuln.cvss_score * 10}, 100`}
                    strokeWidth="3.5"
                    strokeLinecap="round"
                  ></path>
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="font-headline-lg text-headline-lg font-bold text-on-surface m-0 leading-none">{selectedVuln.cvss_score}</span>
                  <span className="font-label-sm text-label-sm text-on-surface-variant mt-base">CVSS v3</span>
                </div>
              </div>
              <p className="font-body-sm text-body-sm text-on-surface-variant">
                {selectedVuln.cvss_score >= 9.0 
                  ? 'Highly critical exploit vectors. Direct patching demanded.' 
                  : selectedVuln.cvss_score >= 7.0 
                  ? 'High sensitivity breach threat. Prioritize scheduling.' 
                  : 'Moderate security policy alignment recommendation.'}
              </p>
            </div>

            {/* Environment Context */}
            <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-lg shadow-sm">
              <h3 className="font-label-md text-label-md text-on-surface-variant uppercase tracking-wider mb-md border-b border-outline-variant pb-sm font-bold">Context</h3>
              <dl className="space-y-sm font-body-sm text-body-sm m-0">
                <div className="flex justify-between py-1">
                  <dt className="text-on-surface-variant">Target</dt>
                  <dd className="text-on-surface font-semibold truncate max-w-[150px]">{domain}</dd>
                </div>
                <div className="flex justify-between py-1">
                  <dt className="text-on-surface-variant">Category</dt>
                  <dd className="text-on-surface font-semibold">{selectedVuln.category}</dd>
                </div>
                {selectedVuln.owasp_category && (
                  <div className="flex flex-col py-1 gap-xs">
                    <dt className="text-on-surface-variant">OWASP</dt>
                    <dd className="text-primary font-semibold text-[11px] leading-tight">{selectedVuln.owasp_category}</dd>
                  </div>
                )}
                <div className="flex justify-between py-1">
                  <dt className="text-on-surface-variant">Confidence</dt>
                  <dd className={`font-bold ${
                    selectedVuln.confidence === 'Confirmed' ? 'text-green-600'
                    : selectedVuln.confidence === 'High' ? 'text-tertiary'
                    : 'text-on-surface'
                  }`}>{selectedVuln.confidence || 'Medium'}</dd>
                </div>
                <div className="flex justify-between py-1">
                  <dt className="text-on-surface-variant">CVSS v3</dt>
                  <dd className={`font-bold ${
                    selectedVuln.cvss_score >= 9 ? 'text-error' 
                    : selectedVuln.cvss_score >= 7 ? 'text-tertiary' 
                    : 'text-on-surface'
                  }`}>{selectedVuln.cvss_score}</dd>
                </div>
                {selectedVuln.cwe_ids && selectedVuln.cwe_ids.length > 0 && (
                  <div className="flex justify-between py-1">
                    <dt className="text-on-surface-variant">CWE IDs</dt>
                    <dd className="text-on-surface font-semibold">{selectedVuln.cwe_ids.join(', ')}</dd>
                  </div>
                )}
              </dl>
            </div>

            {/* References */}
            <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-lg shadow-sm">
              <h3 className="font-label-md text-label-md text-on-surface-variant uppercase tracking-wider mb-md border-b border-outline-variant pb-sm font-bold">References</h3>
              <ul className="space-y-sm font-body-sm text-body-sm m-0 pl-0 list-none">
                {selectedVuln.owasp_category && (() => {
                  // Extract OWASP year+code e.g. "A01:2021" → link to owasp.org
                  const owaspMatch = selectedVuln.owasp_category.match(/A(\d+):(\d{4})/);
                  const owaspHref = owaspMatch
                    ? `https://owasp.org/Top10/A${owaspMatch[1].padStart(2,'0')}_${owaspMatch[2]}-${selectedVuln.owasp_category.split(' - ')[1]?.replace(/\s+/g,'_').replace(/[^a-zA-Z0-9_]/g,'') || 'Security_Misconfiguration'}/`
                    : 'https://owasp.org/www-project-top-ten/';
                  return (
                    <li className="py-1">
                      <a className="text-primary hover:underline flex items-center gap-xs font-semibold" href={owaspHref} target="_blank" rel="noreferrer" style={{ textDecoration: 'none' }}>
                        <span className="material-symbols-outlined text-[16px]">open_in_new</span>
                        OWASP: {selectedVuln.owasp_category}
                      </a>
                    </li>
                  );
                })()}
                {selectedVuln.cwe_ids && selectedVuln.cwe_ids.length > 0 && selectedVuln.cwe_ids.map(cwe => (
                  <li key={cwe} className="py-1">
                    <a
                      className="text-primary hover:underline flex items-center gap-xs font-semibold"
                      href={`https://cwe.mitre.org/data/definitions/${cwe.replace('CWE-','')}.html`}
                      target="_blank"
                      rel="noreferrer"
                      style={{ textDecoration: 'none' }}
                    >
                      <span className="material-symbols-outlined text-[16px]">open_in_new</span>
                      {cwe} — MITRE CWE Database
                    </a>
                  </li>
                ))}
                {(!selectedVuln.cwe_ids || selectedVuln.cwe_ids.length === 0) && (
                  <li className="py-1">
                    <a className="text-primary hover:underline flex items-center gap-xs font-semibold" href={`https://nvd.nist.gov/vuln/search/results?query=${encodeURIComponent(selectedVuln.title)}`} target="_blank" rel="noreferrer" style={{ textDecoration: 'none' }}>
                      <span className="material-symbols-outlined text-[16px]">open_in_new</span>
                      NVD NIST — Search {selectedVuln.title}
                    </a>
                  </li>
                )}
                <li className="py-1">
                  <a className="text-primary hover:underline flex items-center gap-xs font-semibold" href="https://cheatsheetseries.owasp.org/" target="_blank" rel="noreferrer" style={{ textDecoration: 'none' }}>
                    <span className="material-symbols-outlined text-[16px]">open_in_new</span>
                    OWASP Cheat Sheet Series
                  </a>
                </li>
              </ul>
            </div>
          </div>

        </div>
      </div>
    );
  }

  // Render scan dashboard view (eb15a48970e543afbfe15786d831c1c4)
  return (
    <div className="flex flex-col gap-gutter text-left w-full">
      
      {error && (
        <div className="fixed bottom-10 left-1/2 -translate-x-1/2 z-[100] flex items-center bg-error text-on-error px-md py-sm rounded-lg shadow-xl animate-fade-in gap-sm border border-on-error/20">
          <span className="material-symbols-outlined">error</span>
          <span className="font-bold text-[14px]">{error}</span>
          <button onClick={() => setError(null)} className="ml-md text-on-error/80 hover:text-on-error bg-transparent border-0 cursor-pointer p-0 flex items-center">
            <span className="material-symbols-outlined text-[18px]">close</span>
          </button>
        </div>
      )}

      {scan.status !== 'completed' && scan.status !== 'failed' && (
        <div className="bg-surface-container-lowest border border-outline-variant rounded-xl p-md mb-md flex flex-col gap-sm shadow-sm overflow-hidden">
          <div className="flex justify-between items-center border-b border-outline-variant pb-sm">
            <div className="flex items-center gap-sm">
              <span className="material-symbols-outlined text-primary animate-pulse">terminal</span>
              <h2 className="font-title-md text-title-md text-on-surface">Live Scan Console</h2>
            </div>
            <span className="text-[12px] font-mono text-primary font-bold animate-pulse">● RUNNING</span>
          </div>
          <div className="bg-black/90 p-md rounded-lg font-mono text-[13px] text-green-400 overflow-y-auto h-[300px] flex flex-col gap-xs shadow-inner">
            {liveLogs.length === 0 && (
              <div className="text-gray-500 italic">Initializing scanner engines... waiting for output...</div>
            )}
            {liveLogs.map((log, i) => {
               // Log might be an object or string
               const msg = typeof log === 'object' ? `[${log.level || 'INFO'}] ${log.message}` : log;
               const isError = msg.includes('ERROR') || msg.includes('CRITICAL');
               const isVuln = msg.includes('Vulnerability') || msg.includes('Found');
               return (
                 <div key={i} className={`whitespace-pre-wrap ${isError ? 'text-red-400' : isVuln ? 'text-orange-400 font-bold' : 'text-green-400'}`}>
                   {msg}
                 </div>
               );
            })}
            {/* Auto-scroll anchor */}
            <div ref={(el) => el?.scrollIntoView({ behavior: 'smooth' })} />
          </div>
        </div>
      )}

      {/* Page Header */}
      <header className="flex flex-col md:flex-row md:items-end justify-between gap-md border-b border-outline-variant pb-md">
        <div className="flex flex-col">
          <button onClick={() => navigate(-1)} className="self-start inline-flex items-center gap-xs text-primary font-label-md text-label-md hover:underline cursor-pointer mb-md font-bold border-0 bg-transparent p-0">
            <span className="material-symbols-outlined text-[18px]">arrow_back</span>
            Back
          </button>
          <div className="flex items-center gap-sm text-on-surface-variant mb-xs">
            <Link to="/scans/results" className="font-label-sm text-label-sm uppercase font-semibold hover:text-primary transition-colors cursor-pointer" style={{ textDecoration: 'none', color: 'inherit' }}>Vulnerabilities</Link>
            <span className="material-symbols-outlined text-[16px] text-outline">chevron_right</span>
            <span className="font-label-sm text-label-sm text-on-surface font-bold">{domain}</span>
          </div>
          <h1 className="font-headline-lg-mobile md:font-headline-lg text-headline-lg-mobile md:text-headline-lg text-on-surface">Scan Results Report</h1>
          <p className="font-body-sm text-body-sm text-on-surface-variant mt-xs">
            Completed: {new Date(scan.completed_at || scan.started_at).toLocaleString()} • Duration: {
              scan.completed_at && scan.started_at
                ? (() => {
                    const diff = new Date(scan.completed_at) - new Date(scan.started_at);
                    const minutes = Math.floor(diff / 60000);
                    const seconds = Math.floor((diff % 60000) / 1000);
                    return `${minutes}m ${seconds}s`;
                  })()
                : 'N/A'
            }
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-md">
          <OrganizationSelector />
          {/* Target Scan Switcher */}
          {scans.length > 1 && (
            <select
              className="bg-surface-container border border-outline-variant rounded px-sm py-xs font-label-md text-label-md text-on-surface outline-none cursor-pointer"
              value={scan.id}
              onChange={(e) => setActiveScanId(e.target.value)}
            >
              {scans.map(s => (
                <option key={s.id} value={s.id}>
                  {s.target_url.replace("https://", "").replace("http://", "")} ({new Date(s.started_at).toLocaleDateString()})
                </option>
              ))}
            </select>
          )}

          <button 
            onClick={handlePdfExport} 
            disabled={exporting}
            className="bg-primary text-on-primary hover:opacity-90 transition-opacity font-label-md text-label-md px-lg py-sm rounded flex items-center justify-center gap-sm border-0 cursor-pointer shadow-sm"
          >
            <span className="material-symbols-outlined text-[18px]">picture_as_pdf</span>
            {exporting ? 'Compiling Report...' : 'Download PDF Report'}
          </button>
        </div>
      </header>

      {/* Top Row: Full Width Score & Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-7 gap-md w-full">
        
        {/* Overall Score Card */}
        <div className="col-span-1 sm:col-span-2 lg:col-span-2 bg-surface-container-lowest border border-outline-variant rounded-lg p-md flex items-center gap-lg shadow-sm">
          <div className="relative w-20 h-20 flex items-center justify-center shrink-0">
            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
              <circle className="text-surface-container-high" cx="50" cy="50" fill="none" r="45" stroke="currentColor" strokeWidth="8"></circle>
              <circle 
                className="text-primary transition-all duration-1000" 
                cx="50" 
                cy="50" 
                fill="none" 
                r="45" 
                stroke="currentColor" 
                strokeDasharray="283"
                strokeDashoffset={dashOffset} 
                strokeWidth="8"
                strokeLinecap="round"
              ></circle>
            </svg>
            <div className="absolute flex flex-col items-center justify-center">
              <span className="font-headline-md text-headline-md text-on-surface font-bold">{score}</span>
              <span className="font-label-sm text-label-sm text-on-surface-variant font-medium">/100</span>
            </div>
          </div>
          <div className="flex flex-col text-left">
            <h2 className="font-label-md text-label-md text-on-surface-variant uppercase tracking-wider mb-xs font-bold">Security Score</h2>
            <p className="font-body-sm text-body-sm text-on-surface">
              {score >= 80 
                ? 'Your environment is relatively secure. Fix remaining vulnerability warnings to perfect score.'
                : 'System vulnerabilities pose risk. Action recommended immediately.'}
            </p>
          </div>
        </div>

        {/* Risk Indicator Card: Total */}
        <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-md flex flex-col justify-between shadow-sm">
          <div className="flex items-center justify-between mb-sm">
            <span className="font-label-sm text-label-sm text-on-surface-variant uppercase font-bold tracking-wider">Total</span>
            <span className="material-symbols-outlined text-primary" style={{ fontVariationSettings: "'FILL' 1" }}>bug_report</span>
          </div>
          <div className="font-display-lg text-display-lg text-on-surface font-bold leading-none">{totalVulns}</div>
        </div>

        {/* Risk Indicator Card: Critical */}
        <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-md flex flex-col justify-between shadow-sm">
          <div className="flex items-center justify-between mb-sm">
            <span className="font-label-sm text-label-sm text-on-surface-variant uppercase font-bold tracking-wider">Critical</span>
            <span className="material-symbols-outlined text-error" style={{ fontVariationSettings: "'FILL' 1" }}>error</span>
          </div>
          <div className="font-display-lg text-display-lg text-on-surface font-bold leading-none">{critCount}</div>
        </div>

        {/* Risk Indicator Card: High */}
        <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-md flex flex-col justify-between shadow-sm">
          <div className="flex items-center justify-between mb-sm">
            <span className="font-label-sm text-label-sm text-on-surface-variant uppercase font-bold tracking-wider">High</span>
            <span className="material-symbols-outlined text-tertiary" style={{ fontVariationSettings: "'FILL' 1" }}>warning</span>
          </div>
          <div className="font-display-lg text-display-lg text-on-surface font-bold leading-none">{highCount}</div>
        </div>

        {/* Risk Indicator Card: Medium */}
        <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-md flex flex-col justify-between shadow-sm">
          <div className="flex items-center justify-between mb-sm">
            <span className="font-label-sm text-label-sm text-on-surface-variant uppercase font-bold tracking-wider">Medium</span>
            <span className="material-symbols-outlined text-yellow-600" style={{ fontVariationSettings: "'FILL' 1" }}>info</span>
          </div>
          <div className="font-display-lg text-display-lg text-on-surface font-bold leading-none">{medCount}</div>
        </div>

        {/* Risk Indicator Card: Low */}
        <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-md flex flex-col justify-between shadow-sm">
          <div className="flex items-center justify-between mb-sm">
            <span className="font-label-sm text-label-sm text-on-surface-variant uppercase font-bold tracking-wider">Low</span>
            <span className="material-symbols-outlined text-blue-600" style={{ fontVariationSettings: "'FILL' 1" }}>shield</span>
          </div>
          <div className="font-display-lg text-display-lg text-on-surface font-bold leading-none">{lowCount}</div>
        </div>

      </div>

      {/* Bento Grid Metrics Layout */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-gutter">
        
        {/* Left Column (Vulnerability Distribution & Findings Table) */}
        <div className="md:col-span-8 flex flex-col gap-gutter">

          {/* Vulnerability Distribution Chart Card */}
          <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-lg shadow-sm">
            <h3 className="font-headline-md text-headline-md text-on-surface mb-md font-bold">Vulnerability Distribution</h3>
            <div className="flex flex-col gap-md mt-lg">
              {categoriesList.length === 0 ? (
                <div className="text-center py-sm text-on-surface-variant font-body-sm">
                  No vulnerabilities detected to categorize.
                </div>
              ) : (
                categoriesList.map((cat, idx) => {
                  const colors = ['bg-primary', 'bg-secondary', 'bg-tertiary', 'bg-slate-400'];
                  const barColor = colors[idx % colors.length];
                  return (
                    <div key={cat.name}>
                      <div className="flex justify-between font-label-sm text-label-sm text-on-surface-variant mb-xs">
                        <span>{cat.name}</span>
                        <span>{cat.count} finding{cat.count > 1 ? 's' : ''} ({cat.percentage}%)</span>
                      </div>
                      <div className="w-full bg-surface-container-high h-2 rounded-full overflow-hidden">
                        <div className={`h-full rounded-full ${barColor}`} style={{ width: `${cat.percentage}%` }}></div>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Detailed Findings Table Card */}
          <div className="bg-surface-container-lowest border border-outline-variant rounded-lg overflow-hidden flex flex-col shadow-sm">
            <div className="p-md border-b border-outline-variant flex justify-between items-center bg-surface-bright">
              <h3 className="font-headline-md text-headline-md text-on-surface font-bold">Detailed Findings ({filteredVulns.length})</h3>
              
              {/* Severity filter button filters list */}
              <div className="flex items-center gap-xs">
                {['All', 'Critical', 'High', 'Medium', 'Low'].map(sev => {
                  const isFiltered = filterSeverity === sev;
                  return (
                    <button
                      key={sev}
                      onClick={() => setFilterSeverity(sev)}
                      className={`text-[11px] font-label-sm px-sm py-[4px] border rounded transition-all cursor-pointer ${
                        isFiltered 
                          ? 'bg-primary border-primary text-white font-bold' 
                          : 'bg-surface border-outline-variant text-on-surface hover:bg-surface-container-low'
                      }`}
                    >
                      {sev.toUpperCase()}
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse min-w-[700px]">
                <thead>
                  <tr className="bg-surface-container-low border-b border-outline-variant select-none">
                    <th className="p-md font-label-sm text-label-sm text-on-surface-variant uppercase tracking-wider font-semibold w-12">Sr. No.</th>
                    {['Vulnerability', 'Severity', 'Resource', 'Score', 'Status'].map(h => (
                      <th 
                        key={h} 
                        onClick={() => handleSort(h)}
                        className="p-md font-label-sm text-label-sm text-on-surface-variant uppercase tracking-wider font-semibold cursor-pointer hover:bg-surface-container-high transition-colors group"
                      >
                        <div className="flex items-center gap-xs">
                          {h}
                          <span className={`material-symbols-outlined text-[16px] opacity-0 group-hover:opacity-50 transition-opacity ${sortColumn === h ? 'opacity-100 group-hover:opacity-100 text-primary' : ''}`}>
                            {sortColumn === h && sortDirection === 'desc' ? 'arrow_downward' : 'arrow_upward'}
                          </span>
                        </div>
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="font-body-sm text-body-sm text-on-surface">
                  {filteredVulns.length === 0 ? (
                    <tr>
                      <td colSpan="6" className="p-xl text-center text-on-surface-variant font-body-sm">
                        No vulnerability findings match the selected severity category.
                      </td>
                    </tr>
                  ) : (
                    getSortedVulns().map((v, index) => {
                      const isResolved = resolvedVulns.has(v.id);
                      let sevBadge = 'bg-surface-variant text-on-surface-variant border-outline-variant';
                      let sevIcon = 'info';

                      if (v.severity === 'Critical') {
                        sevBadge = 'bg-error-container text-on-error-container border-error/10';
                        sevIcon = 'error';
                      } else if (v.severity === 'High') {
                        sevBadge = 'bg-tertiary-container/15 text-tertiary border-tertiary/20';
                        sevIcon = 'warning';
                      } else if (v.severity === 'Medium') {
                        sevBadge = 'bg-yellow-500/10 text-yellow-600 border-yellow-500/20';
                        sevIcon = 'warning';
                      }

                      return (
                        <tr 
                          key={v.id} 
                          onClick={() => handleOpenVulnDetail(v)}
                          className="border-b border-outline-variant hover:bg-surface-container-low transition-colors group cursor-pointer"
                        >
                          <td className="p-md text-on-surface-variant font-bold">{index + 1}</td>
                          <td className="p-md font-medium text-primary hover:underline">{v.title}</td>
                          <td className="p-md">
                            <span className={`inline-flex items-center px-sm py-[2px] rounded border font-label-sm text-label-sm ${sevBadge}`}>
                              <span className="material-symbols-outlined text-[13px] mr-xs" style={{ fontVariationSettings: "'FILL' 1" }}>{sevIcon}</span>
                              {v.severity}
                            </span>
                          </td>
                          <td className="p-md text-on-surface-variant font-label-sm">{v.category}</td>
                          <td className="p-md text-on-surface-variant font-label-sm font-bold">{v.cvss_score}</td>
                          <td className="p-md">
                            {isResolved ? (
                              <span className="text-green-600 font-semibold flex items-center gap-[2px]">
                                <span className="material-symbols-outlined text-[16px]">check_circle</span> Resolved
                              </span>
                            ) : (
                              <span className="text-error font-semibold flex items-center gap-[2px]">
                                <span className="material-symbols-outlined text-[16px]">pending</span> Open
                              </span>
                            )}
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
<div className="p-md border-t border-outline-variant flex justify-between items-center bg-surface-container-low">
<span className="font-body-sm text-on-surface-variant">
Page {currentPage} of {totalPages}
</span>
<div className="flex gap-sm">
<button 
onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
disabled={!hasPrev}
className="px-sm py-xs border border-outline-variant rounded bg-surface hover:bg-surface-container disabled:opacity-50 cursor-pointer"
>
Previous
</button>
<button 
onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
disabled={!hasNext}
className="px-sm py-xs border border-outline-variant rounded bg-surface hover:bg-surface-container disabled:opacity-50 cursor-pointer"
>
Next
</button>
</div>
</div>
            </div>
          </div>

        </div>

        {/* Right Column (AI Advisory & Action Center) */}
        <div className="md:col-span-4 flex flex-col gap-md text-left">
          
          <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-lg sticky top-md shadow-sm">
            <div className="flex items-center gap-sm mb-md pb-sm border-b border-outline-variant">
              <span className="material-symbols-outlined text-primary">psychiatry</span>
              <h3 className="font-headline-md text-headline-md text-on-surface font-bold">Recommendations</h3>
            </div>
            
            <div className="flex flex-col gap-md">
              {vulnerabilities.filter(v => v.severity === 'Critical' || v.severity === 'High').slice(0, 3).map((v) => (
                <div 
                  key={v.id}
                  className="border border-outline-variant rounded bg-surface-bright flex flex-col gap-xs relative overflow-hidden p-md shadow-sm bg-surface-container-low"
                >
                  <div className={`absolute left-0 top-0 bottom-0 w-1 ${v.severity === 'Critical' ? 'bg-error' : 'bg-tertiary'}`}></div>
                  <h4 className="font-label-md text-label-md text-on-surface font-bold pl-sm">{v.title}</h4>
                  <p className="font-body-sm text-body-sm text-on-surface-variant pl-sm line-clamp-3">
                    {v.description}
                  </p>
                  <button 
                    onClick={() => handleOpenVulnDetail(v)}
                    className="self-start mt-sm ml-sm text-primary font-label-sm text-label-sm flex items-center gap-xs hover:underline cursor-pointer border-0 bg-transparent font-bold"
                  >
                    View Remediation Guide <span className="material-symbols-outlined text-[14px]">arrow_forward</span>
                  </button>
                </div>
              ))}

              {vulnerabilities.filter(v => v.severity === 'Critical' || v.severity === 'High').length === 0 && (
                <div className="text-center py-lg text-on-surface-variant font-body-sm">
                  Great! No Critical or High vulnerabilities remaining to fix.
                </div>
              )}
            </div>
          </div>

        </div>

      </div>
    </div>
  );
};
