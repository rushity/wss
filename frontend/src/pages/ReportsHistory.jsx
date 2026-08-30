import { useState, useEffect } from 'react';
import { useNavigate, Link, useLocation } from 'react-router-dom';
import { useAuth } from '../components/AuthContext';
import { OrganizationSelector } from '../components/OrganizationSelector';

export const ReportsHistory = () => {
  const location = useLocation();
  const searchParams = new URLSearchParams(location.search);
  const q = searchParams.get('q') || '';

  const [scans, setScans] = useState([]);
  const [searchQuery, setSearchQuery] = useState(q);

  useEffect(() => {
    setSearchQuery(q);
  }, [q]);
  const [scanTypeFilter, setScanTypeFilter] = useState('All Types');
  const [loading, setLoading] = useState(true);
  const [exportingId, setExportingId] = useState(null);
  const [copiedId, setCopiedId] = useState(null);
  const [error, setError] = useState(null);
  const [now, setNow] = useState(new Date());
  
  const [dateFilter, setDateFilter] = useState('all'); // 'all', '7d', '30d'
  const [statusFilter, setStatusFilter] = useState('all'); // 'all', 'completed', 'scanning', 'failed'
  const [showFilters, setShowFilters] = useState(false);
  
  const [sortColumn, setSortColumn] = useState('Date');
  const [sortDirection, setSortDirection] = useState('desc');

  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 15;

  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery, scanTypeFilter, dateFilter, statusFilter]);

  const { token } = useAuth();
  const navigate = useNavigate();

  // Live clock — updates every second for accurate "time ago" display
  useEffect(() => {
    const tick = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(tick);
  }, []);

  useEffect(() => {
    fetchScanHistory();
    // Auto-refresh every 5s so running scans update live
    const interval = setInterval(fetchScanHistory, 5000);
    return () => clearInterval(interval);
  }, [token]);

  const fetchScanHistory = async () => {
    try {
      const res = await fetch('/api/scans/history?limit=100', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setScans(data.scans || []);
      }
    } catch (err) {
      console.error("Error fetching historical scans", err);
    } finally {
      setLoading(false);
    }
  };

  const handlePdfExport = async (e, scanId) => {
    e.stopPropagation();
    setExportingId(scanId);
    try {
      const res = await fetch(`/api/reports/${scanId}/pdf`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        let filename = '';
        const disposition = res.headers.get('Content-Disposition');
        if (disposition && disposition.includes('filename=')) {
          const match = disposition.match(/filename="?([^";]+)"?/);
          if (match && match[1]) {
            filename = match[1];
          }
        }

        if (!filename) {
          const scanItem = scans.find(s => s.id === scanId);
          const orgName = scanItem?.org_name || scanItem?.organization_name || 'Global';
          const cleanOrg = orgName.replace(/[^\w]/g, '') || 'Organization';
          const dateObj = new Date(scanItem?.completed_at || scanItem?.started_at || Date.now());
          const day = String(dateObj.getDate()).padStart(2, '0');
          const month = String(dateObj.getMonth() + 1).padStart(2, '0');
          const year = dateObj.getFullYear();
          filename = `LarShield_${cleanOrg}_Report_${day}${month}${year}.pdf`;
        }

        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => window.URL.revokeObjectURL(url), 100);
      } else {
        setError("Failed to compile PDF Report. Server error.");
      }
    } catch (err) {
      console.error("PDF Export error", err);
    } finally {
      setExportingId(null);
    }
  };

  const handleShare = (e, scanId) => {
    e.stopPropagation();
    const shareUrl = `${window.location.origin}/api/reports/${scanId}/public-pdf`;
    navigator.clipboard.writeText(shareUrl);
    setCopiedId(scanId);
    setTimeout(() => setCopiedId(null), 2500);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-2xl font-label-md text-label-md text-on-surface-variant text-left">
        <span className="material-symbols-outlined animate-spin mr-sm">sync</span>
        Loading Historical Audits...
      </div>
    );
  }

  // Filter & Search logic
  const filteredScans = scans.filter((scan) => {
    const cleanUrl = scan.target_url.toLowerCase();
    const cleanId = scan.id.toLowerCase();
    const cleanStatus = scan.status.toLowerCase();
    const query = searchQuery.toLowerCase();
    const matchesSearch = cleanUrl.includes(query) || cleanId.includes(query) || cleanStatus.includes(query);
    
    const matchesType = scanTypeFilter === 'All Types' || scan.scan_type === scanTypeFilter || (scanTypeFilter === 'Advanced' && scan.scan_type === 'Standard');
    const matchesStatus = statusFilter === 'all' || scan.status === statusFilter;
    
    let matchesDate = true;
    if (dateFilter !== 'all' && scan.started_at) {
        const scanDate = new Date(scan.started_at);
        const diffDays = (now - scanDate) / (1000 * 60 * 60 * 24);
        if (dateFilter === '7d' && diffDays > 7) matchesDate = false;
        if (dateFilter === '30d' && diffDays > 30) matchesDate = false;
    }
    
    return matchesSearch && matchesType && matchesStatus && matchesDate;
  });

  // Format date in local timezone (IST-aware)
  const formatDate = (isoString) => {
    if (!isoString) return 'Unknown';
    return new Date(isoString).toLocaleString('en-IN', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: true
    });
  };

  // Live "X ago" helper
  const timeAgo = (isoString) => {
    if (!isoString) return '';
    const diff = Math.floor((now - new Date(isoString)) / 1000);
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  };

  const handleSort = (column) => {
    if (sortColumn === column) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortColumn(column);
      setSortDirection('asc');
    }
  };

  const getSortedScans = () => {
    return [...filteredScans].sort((a, b) => {
      let aVal, bVal;
      switch (sortColumn) {
        case 'Report ID & Date':
        case 'Date':
          aVal = new Date(a.started_at || 0).getTime(); bVal = new Date(b.started_at || 0).getTime(); break;
        case 'Target Host':
          aVal = a.target_url || ''; bVal = b.target_url || ''; break;
        case 'Engine profile':
          aVal = a.scan_type || ''; bVal = b.scan_type || ''; break;
        case 'Findings Status':
          aVal = a.status || ''; bVal = b.status || ''; break;
        default:
          return 0;
      }
      if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });
  };

  // Calculate Pagination (15 items per page)
  const sortedScans = getSortedScans();
  const totalItems = sortedScans.length;
  const totalPages = Math.ceil(totalItems / itemsPerPage) || 1;
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = Math.min(startIndex + itemsPerPage, totalItems);
  const paginatedScans = sortedScans.slice(startIndex, endIndex);

  return (
    <div className="flex flex-col gap-lg text-left w-full">
      
      {/* Error Toast */}
      {error && (
        <div className="fixed bottom-10 left-1/2 -translate-x-1/2 z-[100] flex items-center bg-error text-on-error px-md py-sm rounded-lg shadow-xl animate-fade-in gap-sm border border-on-error/20">
          <span className="material-symbols-outlined">error</span>
          <span className="font-bold text-[14px]">{error}</span>
          <button onClick={() => setError(null)} className="ml-md text-on-error/80 hover:text-on-error bg-transparent border-0 cursor-pointer p-0 flex items-center">
            <span className="material-symbols-outlined text-[18px]">close</span>
          </button>
        </div>
      )}

      {/* Page Header & Date Actions */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-md">
        <div>
          <h2 className="font-display-lg text-display-lg text-on-surface font-bold tracking-tight">Reports &amp; Logs</h2>
          <p className="font-body-md text-body-md text-on-surface-variant mt-sm">
            View and manage historical security scans and vulnerability logs.
          </p>
        </div>
        <div className="flex items-center gap-sm w-full md:w-auto relative">
          <OrganizationSelector />
          <select 
            className="appearance-none flex items-center gap-xs px-md py-sm bg-surface border border-outline-variant rounded-lg text-on-surface font-label-md text-label-md hover:border-primary transition-all cursor-pointer"
            value={dateFilter}
            onChange={(e) => setDateFilter(e.target.value)}
          >
            <option value="all">🗓 Date: All Time</option>
            <option value="7d">🗓 Last 7 Days</option>
            <option value="30d">🗓 Last 30 Days</option>
          </select>
          
          <button 
            onClick={() => setShowFilters(!showFilters)}
            className={`flex items-center gap-xs px-md py-sm bg-surface border ${showFilters ? 'border-primary' : 'border-outline-variant'} rounded-lg text-on-surface font-label-md text-label-md hover:border-primary transition-all cursor-pointer`}
          >
            <span className="material-symbols-outlined text-[18px]">filter_list</span>
            <span>Filter Status</span>
          </button>
          
          {showFilters && (
            <div className="absolute top-[110%] right-0 bg-surface border border-outline-variant rounded-lg shadow-lg z-50 flex flex-col min-w-[150px] overflow-hidden">
                <button onClick={() => {setStatusFilter('all'); setShowFilters(false)}} className={`text-left px-md py-sm border-b border-outline-variant ${statusFilter === 'all' ? 'bg-primary/10 text-primary' : 'hover:bg-surface-variant text-on-surface'}`}>All Statuses</button>
                <button onClick={() => {setStatusFilter('completed'); setShowFilters(false)}} className={`text-left px-md py-sm border-b border-outline-variant ${statusFilter === 'completed' ? 'bg-primary/10 text-primary' : 'hover:bg-surface-variant text-on-surface'}`}>Completed</button>
                <button onClick={() => {setStatusFilter('scanning'); setShowFilters(false)}} className={`text-left px-md py-sm border-b border-outline-variant ${statusFilter === 'scanning' ? 'bg-primary/10 text-primary' : 'hover:bg-surface-variant text-on-surface'}`}>Scanning</button>
                <button onClick={() => {setStatusFilter('failed'); setShowFilters(false)}} className={`text-left px-md py-sm ${statusFilter === 'failed' ? 'bg-primary/10 text-primary' : 'hover:bg-surface-variant text-on-surface'}`}>Failed</button>
            </div>
          )}
        </div>
      </div>

      {/* Search & Toolbar */}
      <div className="bg-surface border border-outline-variant rounded-xl p-sm flex flex-col sm:flex-row gap-sm items-center shadow-sm">
        <div className="relative flex-grow w-full">
          <span className="material-symbols-outlined absolute left-sm top-1/2 -translate-y-1/2 text-on-surface-variant text-[20px]">search</span>
          <input 
            type="text"
            className="w-full bg-surface-container-low border border-transparent rounded-lg py-sm pl-xl pr-md text-on-surface font-body-sm text-body-sm placeholder-on-surface-variant focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all"
            placeholder="Search reports by ID, Target, or Status..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
        <div className="flex items-center gap-xs w-full sm:w-auto border-t sm:border-t-0 pt-sm sm:pt-0">
          <span className="font-label-sm text-label-sm text-on-surface-variant uppercase px-sm font-bold whitespace-nowrap">Scan Profile:</span>
          <select 
            className="bg-surface border border-outline-variant rounded-lg py-sm px-md text-on-surface font-body-sm text-body-sm focus:outline-none focus:border-primary transition-all w-full sm:w-auto cursor-pointer"
            value={scanTypeFilter}
            onChange={(e) => setScanTypeFilter(e.target.value)}
          >
            <option value="All Types">All Scan Profiles</option>
            <option value="Quick">Quick Scan</option>
            <option value="Advanced">Advanced Scan</option>
            <option value="Deep">Deep Assessment</option>
          </select>
        </div>
      </div>

      {/* Reports List Canvas Card */}
      <div className="bg-surface-container-lowest border border-outline-variant rounded-xl overflow-hidden flex flex-col shadow-sm">
        
        {/* Table Header */}
        <div className="grid grid-cols-12 gap-md px-lg py-sm border-b border-outline-variant bg-surface-container-low items-center hidden md:grid select-none">
          <div onClick={() => handleSort('Date')} className="col-span-3 font-label-sm text-label-sm text-on-surface-variant uppercase font-bold cursor-pointer group flex items-center gap-xs">
            Report ID &amp; Date
            <span className={`material-symbols-outlined text-[16px] opacity-0 group-hover:opacity-50 transition-opacity ${sortColumn === 'Date' ? 'opacity-100 group-hover:opacity-100 text-primary' : ''}`}>
              {sortColumn === 'Date' && sortDirection === 'desc' ? 'arrow_downward' : 'arrow_upward'}
            </span>
          </div>
          <div onClick={() => handleSort('Target Host')} className="col-span-3 font-label-sm text-label-sm text-on-surface-variant uppercase font-bold cursor-pointer group flex items-center gap-xs">
            Target Host
            <span className={`material-symbols-outlined text-[16px] opacity-0 group-hover:opacity-50 transition-opacity ${sortColumn === 'Target Host' ? 'opacity-100 group-hover:opacity-100 text-primary' : ''}`}>
              {sortColumn === 'Target Host' && sortDirection === 'desc' ? 'arrow_downward' : 'arrow_upward'}
            </span>
          </div>
          <div onClick={() => handleSort('Engine profile')} className="col-span-2 font-label-sm text-label-sm text-on-surface-variant uppercase font-bold cursor-pointer group flex items-center gap-xs">
            Engine profile
            <span className={`material-symbols-outlined text-[16px] opacity-0 group-hover:opacity-50 transition-opacity ${sortColumn === 'Engine profile' ? 'opacity-100 group-hover:opacity-100 text-primary' : ''}`}>
              {sortColumn === 'Engine profile' && sortDirection === 'desc' ? 'arrow_downward' : 'arrow_upward'}
            </span>
          </div>
          <div onClick={() => handleSort('Findings Status')} className="col-span-2 font-label-sm text-label-sm text-on-surface-variant uppercase font-bold cursor-pointer group flex items-center gap-xs">
            Findings Status
            <span className={`material-symbols-outlined text-[16px] opacity-0 group-hover:opacity-50 transition-opacity ${sortColumn === 'Findings Status' ? 'opacity-100 group-hover:opacity-100 text-primary' : ''}`}>
              {sortColumn === 'Findings Status' && sortDirection === 'desc' ? 'arrow_downward' : 'arrow_upward'}
            </span>
          </div>
          <div className="col-span-2 font-label-sm text-label-sm text-on-surface-variant uppercase text-right font-bold">Actions</div>
        </div>

        {/* List Items */}
        <div className="flex flex-col divide-y divide-outline-variant">
          {paginatedScans.length === 0 ? (
            <div className="text-center py-2xl text-on-surface-variant font-body-sm">
              No historical security audits match your search query.
            </div>
          ) : (
            paginatedScans.map((s) => {
              const hasCritical = s.vulnerabilities_count?.critical > 0;
              const hasHigh = s.vulnerabilities_count?.high > 0;

              return (
                <div 
                  key={s.id}
                  onClick={() => navigate(`/scans/results?id=${s.id}`)}
                  className="grid grid-cols-1 md:grid-cols-12 gap-md px-lg py-md hover:bg-surface-container-low transition-colors items-center group cursor-pointer"
                >
                  {/* ID & Date */}
                  <div className="col-span-1 md:col-span-3 flex flex-col text-left">
                    <span className="font-label-md text-label-md text-primary font-bold group-hover:underline">
                      REP-{s.id.substring(0, 8).toUpperCase()}
                    </span>
                    <span className="font-body-sm text-body-sm text-on-surface-variant flex items-center gap-xs mt-xs">
                      <span className="material-symbols-outlined text-[14px]">event</span>
                      {formatDate(s.started_at)}
                    </span>
                    <span className="font-body-sm text-body-sm text-on-surface-variant/60 text-[11px] ml-[18px]">
                      {timeAgo(s.started_at)}
                    </span>
                  </div>

                  {/* Target Host */}
                  <div className="col-span-1 md:col-span-3 text-left">
                    <span className="font-body-md text-body-md text-on-surface font-semibold truncate block">
                      {s.target_url.replace("https://", "").replace("http://", "")}
                    </span>
                  </div>

                  {/* Type */}
                  <div className="col-span-1 md:col-span-2 text-left">
                    <span className="inline-flex items-center px-sm py-[2px] rounded bg-surface border border-outline-variant font-label-sm text-label-sm text-on-surface-variant font-bold uppercase tracking-wider">
                      {s.scan_type} Scan
                    </span>
                  </div>

                  {/* Status / Findings */}
                  <div className="col-span-1 md:col-span-2 text-left">
                    {s.status === 'completed' ? (
                      (() => {
                        const counts = s.vulnerabilities_count || {};
                        const total = (counts.critical || 0) + (counts.high || 0) + (counts.medium || 0) + (counts.low || 0) + (counts.info || 0);
                        if (total === 0) {
                          return (
                            <div className="flex items-center gap-sm">
                              <div className="w-2.5 h-2.5 rounded-full bg-green-500"></div>
                              <span className="font-label-md text-label-md font-bold text-green-600">Clean / Safe</span>
                            </div>
                          );
                        }
                        return (
                          <div className="grid grid-cols-2 gap-xs w-fit">
                            {counts.critical > 0 && <span className="text-[11px] font-bold px-1.5 py-0.5 rounded bg-error/10 text-error border border-error/20 text-center" title="Critical">{counts.critical} Crit</span>}
                            {counts.high > 0 && <span className="text-[11px] font-bold px-1.5 py-0.5 rounded bg-orange-500/10 text-orange-600 border border-orange-500/20 text-center" title="High">{counts.high} High</span>}
                            {counts.medium > 0 && <span className="text-[11px] font-bold px-1.5 py-0.5 rounded bg-yellow-500/10 text-yellow-600 border border-yellow-500/20 text-center" title="Medium">{counts.medium} Med</span>}
                            {counts.low > 0 && <span className="text-[11px] font-bold px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-600 border border-blue-500/20 text-center" title="Low">{counts.low} Low</span>}
                            {counts.info > 0 && <span className="text-[11px] font-bold px-1.5 py-0.5 rounded bg-slate-500/10 text-slate-600 border border-slate-500/20 text-center" title="Info">{counts.info} Info</span>}
                          </div>
                        );
                      })()
                    ) : s.status === 'scanning' || s.status === 'queued' ? (
                      <div className="flex items-center gap-sm">
                        <div className="w-2.5 h-2.5 rounded-full bg-yellow-500 animate-pulse"></div>
                        <span className="font-label-md text-label-md text-yellow-600 font-bold uppercase">
                          Running Audit
                        </span>
                      </div>
                    ) : (
                      <div className="flex items-center gap-sm">
                        <div className="w-2.5 h-2.5 rounded-full bg-slate-400"></div>
                        <span className="font-label-md text-label-md text-slate-500 font-bold">
                          Failed Session
                        </span>
                      </div>
                    )}
                  </div>

                  {/* Actions */}
                  <div className="col-span-1 md:col-span-2 flex items-center justify-end gap-sm">
                    <button 
                      onClick={(e) => handlePdfExport(e, s.id)}
                      disabled={exportingId === s.id}
                      className="p-xs text-on-surface-variant hover:text-primary transition-colors border-0 bg-transparent cursor-pointer flex items-center justify-center" 
                      title="Download PDF"
                    >
                      <span className="material-symbols-outlined text-[20px]">
                        {exportingId === s.id ? 'sync' : 'picture_as_pdf'}
                      </span>
                    </button>
                    <button 
                      onClick={(e) => handleShare(e, s.id)}
                      className="p-xs text-on-surface-variant hover:text-primary transition-colors border-0 bg-transparent cursor-pointer flex items-center justify-center relative" 
                      title={copiedId === s.id ? 'Link Copied!' : 'Share Link'}
                    >
                      <span className="material-symbols-outlined text-[20px]">
                        {copiedId === s.id ? 'check_circle' : 'share'}
                      </span>
                    </button>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Standard Pagination footer */}
        <div className="px-lg py-md border-t border-outline-variant bg-surface-container-low flex flex-col sm:flex-row justify-between items-center gap-sm text-[13px] text-on-surface-variant">
          <div className="flex items-center gap-2">
            <span className="font-body-sm text-body-sm text-on-surface-variant">Rows per page:</span>
            <select
              value={itemsPerPage}
              onChange={(e) => {
                setItemsPerPage(Number(e.target.value));
                setCurrentPage(1);
              }}
              className="bg-surface border border-outline-variant text-on-surface rounded px-2 py-1 text-xs font-bold focus:outline-none cursor-pointer"
            >
              <option value={10}>10</option>
              <option value={15}>15</option>
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
            <span className="font-body-sm text-body-sm text-on-surface-variant ml-2 font-medium">
              {totalItems > 0 
                ? `${startIndex + 1} - ${endIndex} of ${totalItems} records`
                : `0 of 0 records`
              }
            </span>
          </div>

          <div className="flex items-center gap-1.5">
            <button 
              onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
              disabled={currentPage === 1}
              className="px-3 py-1.5 rounded-lg border border-outline-variant bg-surface hover:bg-surface-variant text-on-surface font-bold text-xs disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer transition-colors"
            >
              Previous
            </button>

            <div className="flex items-center gap-1 px-1">
              {Array.from({ length: totalPages }, (_, i) => i + 1)
                .filter(p => p === 1 || p === totalPages || Math.abs(p - currentPage) <= 1)
                .map((page, idx, arr) => {
                  const prev = arr[idx - 1];
                  return (
                    <React.Fragment key={page}>
                      {prev && page - prev > 1 && <span className="px-1 text-on-surface-variant text-xs">...</span>}
                      <button
                        onClick={() => setCurrentPage(page)}
                        className={`w-7 h-7 rounded text-xs font-bold transition-colors cursor-pointer ${
                          currentPage === page
                            ? 'bg-primary text-on-primary'
                            : 'bg-surface hover:bg-surface-variant border border-outline-variant text-on-surface'
                        }`}
                      >
                        {page}
                      </button>
                    </React.Fragment>
                  );
                })}
            </div>

            <button 
              onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
              disabled={currentPage >= totalPages}
              className="px-3 py-1.5 rounded-lg border border-outline-variant bg-surface hover:bg-surface-variant text-on-surface font-bold text-xs disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer transition-colors"
            >
              Next
            </button>
          </div>
        </div>

      </div>
    </div>
  );
};
