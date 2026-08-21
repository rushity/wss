import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../components/AuthContext';
import { LabelList, ComposedChart, RadialBarChart, RadialBar, RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis, AreaChart, Area, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend, BarChart, Bar } from 'recharts';

import { Navigate } from 'react-router-dom';
import { OrganizationSelector } from '../components/OrganizationSelector';

const ACTIVE_SCAN_KEY = 'wss_active_scan'; // localStorage key for persistence

const CustomBarTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-[#0f172a] border border-[#334155] rounded-lg px-3 py-1.5 shadow-xl text-left pointer-events-none">
        <div className="text-[12px] font-bold text-sky-400 leading-tight">{label}</div>
        <div className="text-[12px] font-semibold text-slate-200 leading-tight mt-1">
          Findings : <span className="font-extrabold text-white">{payload[0].value}</span>
        </div>
      </div>
    );
  }
  return null;
};

export const Dashboard = () => {
  const { token, refreshAccessToken, user } = useAuth();
  
  if (user?.role === 'executive_user') {
    return <Navigate to="/scans/history" replace />;
  }

  const [summary, setSummary] = useState(null);
  const [recentScans, setRecentScans] = useState([]);
  const [activeScan, setActiveScan] = useState(null);
  const [liveLogs, setLiveLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [completedScanId, setCompletedScanId] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [sortColumn, setSortColumn] = useState('Date');
  const [sortDirection, setSortDirection] = useState('desc');

  const logContainerRef = useRef(null);
  const logPollRef = useRef(null);
  const dashboardPollRef = useRef(null);
  const activeScanRef = useRef(null);
  const completedScanIdRef = useRef(null);

  const markScanAsCompleted = useCallback((id) => {
    completedScanIdRef.current = id;
    setCompletedScanId(id);
  }, []);

  // Always read the latest token from localStorage so the poller works even
  // after a token refresh (avoids stale closure issues)
  const getToken = useCallback(() =>
    localStorage.getItem('wss_token') || token
  , [token]);

  // Auto-scroll log terminal when new logs arrive
  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [liveLogs]);

  // ── Persist active scan to localStorage ─────────────────────
  const persistActiveScan = useCallback((scan) => {
    if (scan) {
      localStorage.setItem(ACTIVE_SCAN_KEY, JSON.stringify({ id: scan.id, target_url: scan.target_url, scan_type: scan.scan_type }));
    } else {
      localStorage.removeItem(ACTIVE_SCAN_KEY);
    }
  }, []);

  // ── Log Polling ─────────────────────────────────────────────
  const stopLogPolling = useCallback(() => {
    if (logPollRef.current) {
      clearInterval(logPollRef.current);
      logPollRef.current = null;
    }
  }, []);

  const startLogPolling = useCallback((scan) => {
    stopLogPolling();
    activeScanRef.current = scan;
    persistActiveScan(scan);
    let consecutiveErrors = 0;
    const MAX_ERRORS = 20; // tolerate up to 20 failures (covers token refresh + brief outages)

    logPollRef.current = setInterval(async () => {
      if (!activeScanRef.current) { stopLogPolling(); return; }

      let activeToken = getToken();

      try {
        let res = await fetch(`/api/scans/${scan.id}/logs`, {
          headers: { 'Authorization': `Bearer ${activeToken}` }
        });

        // Token expired — try to refresh it silently
        if (res.status === 401) {
          const newToken = await refreshAccessToken();
          if (newToken) {
            activeToken = newToken;
            res = await fetch(`/api/scans/${scan.id}/logs`, {
              headers: { 'Authorization': `Bearer ${newToken}` }
            });
          }
        }

        if (!res.ok) {
          consecutiveErrors++;
          if (consecutiveErrors >= MAX_ERRORS) stopLogPolling();
          return;
        }

        consecutiveErrors = 0;
        const data = await res.json();
        if (data.logs && data.logs.length > 0) {
          setLiveLogs(data.logs);
        }

        if (data.status === 'completed' || data.status === 'failed' || data.status === 'terminated') {
          stopLogPolling();
          setActiveScan(null);
          activeScanRef.current = null;
          persistActiveScan(null); // clear localStorage
          markScanAsCompleted(scan.id);
          fetchDashboard();
        }
      } catch (err) {
        consecutiveErrors++;
        console.error('[Dashboard] Log poll error:', err);
        if (consecutiveErrors >= MAX_ERRORS) stopLogPolling();
      }
    }, 1500);
  }, [getToken, refreshAccessToken, stopLogPolling, persistActiveScan, markScanAsCompleted]);

  // ── Dashboard Data Fetch ─────────────────────────────────────
  const fetchDashboard = useCallback(async () => {
    try {
      const activeToken = getToken();
      const [summaryRes, historyRes] = await Promise.all([
        fetch('/api/vulnerabilities/summary', { headers: { 'Authorization': `Bearer ${activeToken}` } }),
        fetch('/api/scans/history',            { headers: { 'Authorization': `Bearer ${activeToken}` } })
      ]);

      if (!summaryRes.ok || !historyRes.ok) return;

      const summaryData = await summaryRes.json();
      const historyData = await historyRes.json();

      setSummary(summaryData.summary);
      setRecentScans(historyData.scans || []);
      setLastUpdated(new Date());

      const running = (historyData.scans || []).find(
        s => (s.status === 'scanning' || s.status === 'queued') && s.id !== completedScanIdRef.current
      );

      if (running) {
        if (!activeScanRef.current || activeScanRef.current.id !== running.id) {
          setActiveScan(running);
          setLiveLogs([]);
          startLogPolling(running);
        }
      } else if (!running && activeScanRef.current && !logPollRef.current) {
        setActiveScan(null);
        activeScanRef.current = null;
        persistActiveScan(null);
        stopLogPolling();
      } else if (!running && activeScanRef.current && activeScanRef.current.id === completedScanIdRef.current) {
        setActiveScan(null);
        activeScanRef.current = null;
        persistActiveScan(null);
        stopLogPolling();
      }
    } catch (err) {
      console.error('[Dashboard] Fetch error:', err);
    } finally {
      setLoading(false);
    }
  }, [getToken, startLogPolling, stopLogPolling, persistActiveScan]);

  // ── Mount — recover active scan from localStorage ─────────────────────────
  useEffect(() => {
    // 1. Immediately try to restore a previously active scan from localStorage
    //    so LIVE AUDIT appears instantly even after refresh or re-login.
    const stored = localStorage.getItem(ACTIVE_SCAN_KEY);
    if (stored && token) {
      try {
        const storedScan = JSON.parse(stored);
        // Validate it's still running before starting the poller
        fetch(`/api/scans/${storedScan.id}/logs`, {
          headers: { 'Authorization': `Bearer ${getToken()}` }
        }).then(async (r) => {
          if (r.ok) {
            const d = await r.json();
            if (d.status === 'scanning' || d.status === 'queued') {
              setActiveScan(storedScan);
              setLiveLogs(d.logs || []);
              startLogPolling(storedScan);
            } else {
              // Scan already done — clean up localStorage
              localStorage.removeItem(ACTIVE_SCAN_KEY);
            }
          }
        }).catch(() => {});
      } catch (_) {
        localStorage.removeItem(ACTIVE_SCAN_KEY);
      }
    }

    // 2. Then do the normal full dashboard fetch
    fetchDashboard();
    dashboardPollRef.current = setInterval(fetchDashboard, 5000);
    return () => {
      clearInterval(dashboardPollRef.current);
      stopLogPolling();
    };
  }, [fetchDashboard, stopLogPolling]); // intentionally shallow — only run on mount


  // ── Derived values ───────────────────────────────────────────
  if (loading) {
    return (
      <div className="flex items-center justify-center py-2xl font-label-md text-label-md text-on-surface-variant">
        <span className="material-symbols-outlined animate-spin mr-sm">sync</span>
        Loading Security Console...
      </div>
    );
  }

  const counts = summary?.vulnerabilities_count || { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
  
  // Real-time dynamic security score calculation
  const score = summary?.average_security_score ?? 100;
  const dashOffset = 283 - (283 * score) / 100;

  let scoreLabel = 'Excellent';
  let scoreColorClass = 'text-primary';
  if (score < 50) { scoreLabel = 'Critical'; scoreColorClass = 'text-error'; }
  else if (score < 80) { scoreLabel = 'Warning'; scoreColorClass = 'text-tertiary'; }

  const getRatingGrade = (s) => {
    if (s === null || s === undefined) return '--';
    if (s >= 90) return 'A'; if (s >= 80) return 'B';
    if (s >= 70) return 'C'; if (s >= 50) return 'D'; return 'F';
  };
  const ratingColor = (g) => ({
    A: 'text-green-600', B: 'text-green-500', C: 'text-yellow-600',
    D: 'text-orange-600', F: 'text-red-600'
  }[g] || 'text-slate-400');

  // Log line coloring — match exactly what backend writes
  const getLogColor = (log) => {
    if (log.includes('[VULN]'))    return 'text-red-400 font-semibold';
    if (log.includes('[WARN]'))    return 'text-yellow-400';
    if (log.includes('[SUCCESS]')) return 'text-green-400 font-semibold';
    if (log.includes('[INFO]'))    return 'text-blue-300';
    if (log.includes('[ERROR]'))   return 'text-red-500 font-bold';
    return 'text-slate-300';
  };

  // Chart: last 7 days line chart data
  const buildChart = () => {
    const days = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
    const today = new Date();
    const buckets = Array.from({ length: 7 }, (_, i) => {
      const d = new Date(today); d.setDate(today.getDate() - (6 - i));
      return { date: d, name: days[d.getDay()], Scans: 0, Threats: 0 };
    });
    recentScans.forEach(scan => {
      if (!scan.started_at) return;
      const sd = new Date(scan.started_at);
      const b = buckets.find(b => b.date.toDateString() === sd.toDateString());
      if (b) {
        b.Scans++;
        const v = scan.vulnerabilities_count || {};
        b.Threats += (v.critical||0) + (v.high||0) + (v.medium||0) + (v.low||0);
      }
    });
    return buckets;
  };

  const chartData = buildChart();

  // Derived totals
  const totalCounts = counts.critical + counts.high + counts.medium + counts.low;

  const handleSort = (column) => {
    if (column === 'Severity' || column === 'Actions') return;
    if (sortColumn === column) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortColumn(column);
      setSortDirection('asc');
    }
  };

  const getSortedScans = () => {
    return [...recentScans].sort((a, b) => {
      let aVal, bVal;
      switch (sortColumn) {
        case 'Status':
          aVal = a.status || ''; bVal = b.status || ''; break;
        case 'Target URL':
          aVal = a.target_url || ''; bVal = b.target_url || ''; break;
        case 'Scan Profile':
          aVal = a.scan_type || ''; bVal = b.scan_type || ''; break;
        case 'Date':
          aVal = new Date(a.started_at || 0).getTime(); bVal = new Date(b.started_at || 0).getTime(); break;
        case 'Rating':
          aVal = a.security_score || 0; bVal = b.security_score || 0; break;
        default:
          return 0;
      }
      if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });
  };

  return (
    <div className="flex flex-col gap-gutter text-left">

      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-sm mb-sm">
        <div>
          <h2 className="font-headline-lg-mobile md:font-headline-lg text-headline-lg-mobile md:text-headline-lg text-on-surface font-bold tracking-tight">
            Security Dashboard
          </h2>
          <p className="font-body-sm text-body-sm text-on-surface-variant mt-xs">
            Real-time infrastructure health and vulnerability monitoring.
          </p>
        </div>
        <div className="flex items-center gap-sm">
          <OrganizationSelector />
          <div className="flex items-center gap-xs text-on-surface-variant bg-surface-container-low px-sm py-xs rounded-md border border-outline-variant">
            <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>schedule</span>
            <span className="font-label-sm text-label-sm uppercase">
              {lastUpdated ? `Updated ${lastUpdated.toLocaleTimeString()}` : 'Loading...'}
            </span>
          </div>
        </div>
      </div>

      {/* ── Live Scan Terminal ── */}
      {activeScan && (
        <div className="w-full bg-[#020617] border border-[#1e293b] rounded-xl overflow-hidden shadow-2xl">
          <div className="bg-[#0f172a] px-md py-sm border-b border-[#1e293b] flex items-center justify-between">
            <div className="flex items-center gap-sm">
              <span className="relative flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-3 w-3 bg-red-500"></span>
              </span>
              <span className="font-label-md text-label-md text-white font-bold tracking-tight ml-1">
                LIVE AUDIT — {activeScan.target_url}
              </span>
            </div>
            <div className="flex items-center gap-sm">
              <span className="font-label-sm text-label-sm text-slate-400 bg-slate-800 px-sm py-[2px] rounded uppercase">
                {activeScan.scan_type} Scan
              </span>
              <span className="font-label-sm text-label-sm text-yellow-400 bg-yellow-400/10 border border-yellow-400/20 px-sm py-[2px] rounded uppercase animate-pulse">
                ● Running
              </span>
            </div>
          </div>

          <div
            ref={logContainerRef}
            className="p-md font-mono text-[12.5px] leading-relaxed h-56 overflow-y-auto flex flex-col gap-[2px] scroll-smooth custom-scrollbar"
          >
            {liveLogs.length === 0 ? (
              <div className="text-slate-500 animate-pulse">⏳ Spawning audit worker threads...</div>
            ) : (
              liveLogs.map((log, i) => (
                <div key={i} className={`${getLogColor(log)} leading-snug`}>{log}</div>
              ))
            )}
          </div>

          <div className="bg-[#0a0f1e] border-t border-[#1e293b] px-md py-xs flex items-center justify-between">
            <span className="font-label-sm text-label-sm text-slate-500">{liveLogs.length} log entries</span>
            <span className="text-slate-400 text-xs animate-pulse">● Scanning in progress...</span>
          </div>
        </div>
      )}

      {/* ── Scan Complete Banner ── */}
      {completedScanId && !activeScan && (
        (() => {
          const scanData = recentScans.find(s => s.id === completedScanId);
          const isFailed = scanData?.status === 'failed';
          const isTerminated = scanData?.status === 'terminated';
          
          if (isTerminated) {
            return (
              <div className="w-full bg-red-50 border border-red-200 rounded-xl p-md flex items-center justify-between shadow-sm">
                <div className="flex items-center gap-sm">
                  <span className="material-symbols-outlined text-red-600 text-[28px]" style={{ fontVariationSettings: "'FILL' 1" }}>error</span>
                  <div>
                    <p className="font-label-md text-label-md text-red-900 font-bold">Scanner Terminated</p>
                    <p className="font-body-sm text-body-sm text-red-700">Sorry, due to some problemes we terminate your scanning and also show that scanner is terminated.</p>
                  </div>
                </div>
                <Link
                  to={`/scans/results?id=${completedScanId}`}
                  className="bg-red-600 hover:bg-red-700 text-white font-label-md text-label-md px-lg py-sm rounded-lg flex items-center gap-sm transition-colors font-bold border-0"
                  style={{ textDecoration: 'none' }}
                >
                  <span className="material-symbols-outlined text-[18px]">open_in_new</span>
                  View Details
                </Link>
              </div>
            );
          }

          if (isFailed) {
            return (
              <div className="w-full bg-red-50 border border-red-200 rounded-xl p-md flex items-center justify-between shadow-sm">
                <div className="flex items-center gap-sm">
                  <span className="material-symbols-outlined text-red-600 text-[28px]" style={{ fontVariationSettings: "'FILL' 1" }}>error</span>
                  <div>
                    <p className="font-label-md text-label-md text-red-900 font-bold">Scan Failed!</p>
                    <p className="font-body-sm text-body-sm text-red-700">The scanner encountered a critical error. View logs for details.</p>
                  </div>
                </div>
                <Link
                  to={`/scans/results?id=${completedScanId}`}
                  className="bg-red-600 hover:bg-red-700 text-white font-label-md text-label-md px-lg py-sm rounded-lg flex items-center gap-sm transition-colors font-bold border-0"
                  style={{ textDecoration: 'none' }}
                >
                  <span className="material-symbols-outlined text-[18px]">open_in_new</span>
                  View Details
                </Link>
              </div>
            );
          }

          return (
            <div className="w-full bg-green-50 border border-green-200 rounded-xl p-md flex items-center justify-between shadow-sm">
              <div className="flex items-center gap-sm">
                <span className="material-symbols-outlined text-green-600 text-[28px]" style={{ fontVariationSettings: "'FILL' 1" }}>check_circle</span>
                <div>
                  <p className="font-label-md text-label-md text-green-900 font-bold">Scan Complete!</p>
                  <p className="font-body-sm text-body-sm text-green-700">Vulnerability analysis finished. View the full report below.</p>
                </div>
              </div>
              <Link
                to={`/scans/results?id=${completedScanId}`}
                className="bg-green-600 hover:bg-green-700 text-white font-label-md text-label-md px-lg py-sm rounded-lg flex items-center gap-sm transition-colors font-bold border-0"
                style={{ textDecoration: 'none' }}
              >
                <span className="material-symbols-outlined text-[18px]">open_in_new</span>
                View Full Report
              </Link>
            </div>
          );
        })()
      )}

      {/* ── Bento Grid ── */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-gutter">

        {/* Security Score Gauge */}
        <div className="md:col-span-6 bg-surface-container-lowest border border-outline-variant rounded-xl p-lg flex flex-col justify-between shadow-sm relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-full bg-gradient-to-br from-primary/5 to-transparent pointer-events-none"></div>
          <div>
            <h3 className="font-headline-md text-headline-md text-on-surface tracking-tight">Security Score</h3>
            <p className="font-body-sm text-body-sm text-on-surface-variant mt-xs">Overall system resilience</p>
          </div>
          <div className="flex-grow flex flex-col items-center justify-center py-xl">
            <div className="relative w-48 h-48 flex items-center justify-center">
              <svg className="w-full h-full absolute transform -rotate-90" viewBox="0 0 100 100">
                <circle cx="50" cy="50" fill="none" r="45" stroke="#e5eeff" strokeWidth="8"></circle>
              </svg>
              <svg className="w-full h-full absolute transform -rotate-90" viewBox="0 0 100 100">
                <circle
                  className="transition-all duration-1000 ease-out"
                  cx="50" cy="50" fill="none" r="45"
                  stroke={score < 50 ? '#ba1a1a' : score < 80 ? '#bc4800' : '#004ac6'}
                  strokeDasharray="283"
                  strokeDashoffset={dashOffset}
                  strokeLinecap="round"
                  strokeWidth="8"
                />
              </svg>
              <div className="text-center flex flex-col items-center z-10">
                <span className="font-display-lg text-display-lg text-primary tracking-tighter">{score}</span>
                <span className={`font-label-sm text-label-sm uppercase tracking-widest bg-primary/10 px-xs py-[2px] rounded-sm mt-xs ${scoreColorClass}`}>
                  {scoreLabel}
                </span>
                <span className="font-label-sm text-label-sm text-on-surface-variant/70 mt-base">
                  {score >= 80 ? 'System Protected' : 'Remediation Required'}
                </span>
              </div>
            </div>
          </div>
          <div className="flex items-center justify-between text-body-sm font-body-sm border-t border-outline-variant pt-sm mt-sm">
            <span className="text-on-surface-variant">Live security posture</span>
            <span className={`font-medium flex items-center ${
              score >= 80 ? 'text-green-600' : score >= 50 ? 'text-orange-600' : 'text-error'
            }`}>
              <span className="material-symbols-outlined text-[16px] mr-[2px]">
                {score >= 80 ? 'trending_up' : score >= 50 ? 'trending_flat' : 'trending_down'}
              </span>
              {score >= 80 ? 'Stable' : score >= 50 ? 'Needs Attention' : 'Critical Risk'}
            </span>
          </div>
        </div>

        {/* Stats + Chart */}
        <div className="md:col-span-6 flex flex-col gap-gutter">
          
          {/* Vulnerability Category Breakdown Bar Chart with Visible Numbers */}
          <div className="w-full h-full bg-surface-container-lowest border border-outline-variant rounded-xl p-lg shadow-sm flex flex-col">
            <div className="w-full flex justify-between items-center mb-md">
              <h3 className="font-headline-md text-headline-md text-on-surface tracking-tight font-bold">Vulnerability Categories</h3>
              <span className="text-[12px] font-bold text-on-surface-variant bg-surface-container px-2 py-0.5 rounded border border-outline-variant">
                Top Vectors
              </span>
            </div>
            <div className="flex-grow min-h-[260px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={[
                    { category: 'Critical', count: counts.critical || 0 },
                    { category: 'High', count: counts.high || 0 },
                    { category: 'Medium', count: counts.medium || 0 },
                    { category: 'Low', count: counts.low || 0 }
                  ]}
                  margin={{ top: 30, right: 15, left: -10, bottom: 25 }}
                >
                  <defs>
                    <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#ef4444" stopOpacity={1}/>
                      <stop offset="100%" stopColor="#991b1b" stopOpacity={0.95}/>
                    </linearGradient>
                    <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#f97316" stopOpacity={1}/>
                      <stop offset="100%" stopColor="#c2410c" stopOpacity={0.95}/>
                    </linearGradient>
                    <linearGradient id="colorMedium" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#eab308" stopOpacity={1}/>
                      <stop offset="100%" stopColor="#854d0e" stopOpacity={0.95}/>
                    </linearGradient>
                    <linearGradient id="colorLow" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#3b82f6" stopOpacity={1}/>
                      <stop offset="100%" stopColor="#1e40af" stopOpacity={0.95}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
                  <XAxis 
                    dataKey="category" 
                    stroke="#475569" 
                    fontSize={12} 
                    tickLine={false}
                    tick={{ fill: '#000000', fontSize: 12, fontWeight: 'bold' }}
                    angle={0}
                    textAnchor="middle"
                    height={30}
                    interval={0}
                  />
                  <YAxis 
                    stroke="#475569" 
                    fontSize={11} 
                    tickLine={false} 
                    axisLine={false} 
                    allowDecimals={false} 
                    tick={{ fill: '#000000', fontSize: 11, fontWeight: 'bold' }} 
                  />
                  <RechartsTooltip content={<CustomBarTooltip />} />
                  <Bar dataKey="count" name="Findings" radius={[8, 8, 0, 0]} barSize={45}>
                    <Cell key="cell-0" fill="url(#colorCritical)" />
                    <Cell key="cell-1" fill="url(#colorHigh)" />
                    <Cell key="cell-2" fill="url(#colorMedium)" />
                    <Cell key="cell-3" fill="url(#colorLow)" />
                    <LabelList 
                      dataKey="count" 
                      position="top" 
                      fill="#000000" 
                      fontSize={12} 
                      fontWeight="bold" 
                      offset={8} 
                    />
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="bg-surface-container-lowest border border-outline-variant rounded-xl shadow-sm flex flex-col overflow-hidden">
        <div className="p-lg border-b border-outline-variant flex justify-between items-center">
          <h3 className="font-headline-md text-headline-md text-on-surface tracking-tight">Configured Target Assets</h3>
          <Link className="font-label-md text-label-md text-primary hover:underline" to="/scans/history" style={{ textDecoration: 'none' }}>
            View Full Audit Log
          </Link>
        </div>

        {recentScans.length === 0 ? (
          <div className="text-center py-2xl text-on-surface-variant font-body-sm">
            No target domains scanned yet. Launch your first website scan under the New Scan tab!
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse min-w-[800px]">
              <thead>
                <tr className="bg-surface-container-low border-b border-outline-variant">
                  {['Status','Target URL','Scan Profile','Date','Rating','Severity','Actions'].map((h, i) => (
                    <th 
                      key={h} 
                      onClick={() => handleSort(h)}
                      className={`py-sm px-lg font-label-sm text-label-sm text-on-surface-variant uppercase tracking-wider font-medium ${i === 6 ? 'text-right' : ''} ${(h !== 'Severity' && h !== 'Actions') ? 'cursor-pointer hover:bg-surface-container-high transition-colors select-none group' : ''}`}
                    >
                      <div className={`flex items-center gap-xs ${i === 6 ? 'justify-end' : ''}`}>
                        {h}
                        {(h !== 'Severity' && h !== 'Actions') && (
                          <span className={`material-symbols-outlined text-[16px] opacity-0 group-hover:opacity-50 transition-opacity ${sortColumn === h ? 'opacity-100 group-hover:opacity-100 text-primary' : ''}`}>
                            {sortColumn === h && sortDirection === 'desc' ? 'arrow_downward' : 'arrow_upward'}
                          </span>
                        )}
                      </div>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="font-body-sm text-body-sm text-on-surface">
                {getSortedScans().slice(0, 8).map((scan) => {
                  let dot = 'bg-primary', statusText = 'Clean', rowBg = '';
                  if (scan.status === 'completed') {
                    if (scan.security_score < 60)      { dot = 'bg-error animate-pulse'; statusText = 'Critical'; rowBg = 'bg-error/5'; }
                    else if (scan.security_score < 80) { dot = 'bg-tertiary'; statusText = 'Warning'; }
                    else                               { dot = 'bg-green-500'; statusText = 'Secure'; }
                  } else if (scan.status === 'scanning' || scan.status === 'queued') {
                    dot = 'bg-yellow-500 animate-pulse'; statusText = 'Scanning';
                  } else if (scan.status === 'terminated') {
                    dot = 'bg-slate-400'; statusText = 'Terminated';
                  } else {
                    dot = 'bg-slate-400'; statusText = 'Failed';
                  }
                  const grade = getRatingGrade(scan.security_score);

                  return (
                    <tr key={scan.id} className={`border-b border-outline-variant/50 hover:bg-surface-bright transition-colors ${rowBg}`}>
                      <td className="py-md px-lg">
                        <div className="flex items-center gap-xs">
                          <div className={`w-2.5 h-2.5 rounded-full ${dot}`}></div>
                          <span className="font-medium">{statusText}</span>
                        </div>
                      </td>
                      <td className="py-md px-lg font-label-md text-on-surface-variant font-bold max-w-[200px] truncate">{scan.target_url}</td>
                      <td className="py-md px-lg text-on-surface-variant">{scan.scan_type} Assessment</td>
                      <td className="py-md px-lg text-on-surface-variant font-medium text-xs">
                        {scan.started_at ? new Date(scan.started_at).toLocaleString('en-US', {
                          day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit'
                        }) : 'Pending'}
                      </td>
                      <td className="py-md px-lg">
                        <span className={`font-mono text-[20px] font-extrabold ${ratingColor(grade)}`}>{grade}</span>
                        {scan.security_score !== null && <span className="text-on-surface-variant text-xs ml-1 opacity-70">({scan.security_score})</span>}
                      </td>
                      <td className="py-md px-lg">
                        <div className="flex gap-sm flex-wrap">
                          {(scan.vulnerabilities_count?.critical > 0) && <span className="bg-red-500/10 text-red-600 px-sm py-[2px] rounded text-xs font-bold border border-red-500/20">{scan.vulnerabilities_count.critical} Crit</span>}
                          {(scan.vulnerabilities_count?.high > 0) && <span className="bg-orange-500/10 text-orange-600 px-sm py-[2px] rounded text-xs font-bold border border-orange-500/20">{scan.vulnerabilities_count.high} High</span>}
                          {(scan.vulnerabilities_count?.total === 0) && <span className="bg-green-500/10 text-green-600 px-sm py-[2px] rounded text-xs font-bold border border-green-500/20">Clean</span>}
                          {scan.status === 'scanning' && <span className="bg-yellow-500/10 text-yellow-600 px-sm py-[2px] rounded text-xs font-bold border border-yellow-500/20 animate-pulse">Scanning...</span>}
                        </div>
                      </td>
                      <td className="py-md px-lg text-right">
                        <Link to={`/scans/results?id=${scan.id}`} className="text-primary hover:text-primary-container font-semibold inline-flex items-center gap-xs" style={{ textDecoration: 'none' }}>
                          Details <span className="material-symbols-outlined text-[16px]">arrow_forward</span>
                        </Link>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

    </div>
  );
};
