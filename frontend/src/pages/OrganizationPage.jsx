import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../components/AuthContext';
import { Shield, Activity, Users, Globe, Lock, ShieldAlert, ArrowLeft, BarChart3, PieChart as PieChartIcon } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, LineChart, Line, PieChart, Pie, Cell, Legend, LabelList, ComposedChart } from 'recharts';

const SEVERITY_COLORS = ['#EF4444', '#F97316', '#EAB308', '#3B82F6']; // Critical, High, Medium, Low
const SCAN_TYPE_COLORS = ['#3B82F6', '#8B5CF6', '#10B981', '#F59E0B'];

const CustomChartTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-[#0f172a] border border-[#334155] rounded-lg px-3 py-1.5 shadow-xl text-left pointer-events-none">
        {label && <div className="text-[12px] font-bold text-sky-400 leading-tight mb-1">{label}</div>}
        {payload.map((item, index) => (
          <div key={index} className="text-[12px] font-medium text-slate-200 leading-tight">
            <span style={{ color: item.color || '#38bdf8' }}>{item.name || item.dataKey}</span> : <span className="font-bold text-white">{item.value}</span>
          </div>
        ))}
      </div>
    );
  }
  return null;
};

export const OrganizationPage = () => {
  const { user, token, loading: authLoading } = useAuth();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  
  const [summaryData, setSummaryData] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [filterOrg, setFilterOrg] = useState('All');
  const [filterWebsite, setFilterWebsite] = useState('All');

  const getToken = useCallback(() => localStorage.getItem('wss_token') || localStorage.getItem('wss_token') || token, [token]);

  const fetchData = useCallback(async () => {
    try {
      const activeToken = getToken();
      if (!activeToken) {
        setLoading(false);
        return;
      }
      const [summaryRes, historyRes] = await Promise.all([
        fetch('/api/vulnerabilities/summary?global=true', { headers: { 'Authorization': `Bearer ${activeToken}` } }),
        fetch('/api/scans/history?global=true&limit=100', { headers: { 'Authorization': `Bearer ${activeToken}` } })
      ]);

      if (!summaryRes.ok || !historyRes.ok) return;

      const summaryJson = await summaryRes.json();
      const historyJson = await historyRes.json();

      setSummaryData(summaryJson.summary);
      setScanHistory(historyJson.scans || []);
    } catch (err) {
      console.error("Failed to fetch organization data:", err);
    } finally {
      setLoading(false);
    }
  }, [getToken]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000); // Polling real-time data every 5s
    return () => clearInterval(interval);
  }, [fetchData]);

  if (loading || authLoading) {
    return (
      <div className="flex h-[80vh] items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
      </div>
    );
  }

  // Extract Unique Orgs & Websites for filters
  const uniqueOrgs = [...new Set(scanHistory.map(s => s.org_name).filter(Boolean))];
  const uniqueWebsites = [...new Set(scanHistory.map(s => s.target_url).filter(Boolean))];

  // Apply Filters
  const filteredScans = scanHistory
    .filter(scan => filterOrg === 'All' || scan.org_name === filterOrg)
    .filter(scan => filterWebsite === 'All' || scan.target_url === filterWebsite);

  // Derive metrics dynamically from filteredScans
  const completedScans = filteredScans.filter(s => s.status === 'completed' && s.security_score !== null);
  const score = completedScans.length > 0 
    ? Math.round(completedScans.reduce((sum, s) => sum + s.security_score, 0) / completedScans.length) 
    : 100;

  const totalVulnerabilities = filteredScans.reduce((sum, s) => {
    const vc = s.vulnerabilities_count;
    return sum + (vc ? (vc.critical + vc.high + vc.medium + vc.low) : (s.total_vulnerabilities || 0));
  }, 0);
  
  // Active Assets (unique target URLs)
  const activeAssets = new Set(filteredScans.map(s => s.target_url).filter(Boolean)).size;

  // Vulnerability Distribution Pie Chart Data
  const vulnCounts = filteredScans.reduce((acc, s) => {
    if (s.vulnerabilities_count) {
      acc.critical += s.vulnerabilities_count.critical || 0;
      acc.high += s.vulnerabilities_count.high || 0;
      acc.medium += s.vulnerabilities_count.medium || 0;
      acc.low += s.vulnerabilities_count.low || 0;
    }
    return acc;
  }, { critical: 0, high: 0, medium: 0, low: 0 });

  const vulnerabilityTypes = [
    { name: 'Critical', value: vulnCounts.critical },
    { name: 'High', value: vulnCounts.high },
    { name: 'Medium', value: vulnCounts.medium },
    { name: 'Low', value: vulnCounts.low },
  ].filter(v => v.value > 0);

  if (vulnerabilityTypes.length === 0) {
    vulnerabilityTypes.push({ name: 'Clean / No Risks', value: 1 });
  }

  // Risk Score Trend (Last 10 Scans)
  const riskTrendData = [...filteredScans]
    .filter(s => s.started_at)
    .sort((a, b) => new Date(a.started_at) - new Date(b.started_at))
    .slice(-10)
    .map((scan, index) => {
      const totalVulns = scan.vulnerabilities_count 
        ? (scan.vulnerabilities_count.critical + scan.vulnerabilities_count.high + scan.vulnerabilities_count.medium + scan.vulnerabilities_count.low)
        : (scan.total_vulnerabilities || 0);
      return {
        name: scan.target_url ? scan.target_url.replace('https://', '').replace('http://', '').replace(/\/$/, '') : `Scan ${index + 1}`,
        securityScore: Math.round(scan.security_score ?? 100),
        vulnerabilities: totalVulns
      };
    });

  // Group Scans by Month for Bar Chart
  const monthsData = {};
  filteredScans.forEach(scan => {
    const d = new Date(scan.started_at || scan.created_at);
    if (isNaN(d.getTime())) return;
    const month = d.toLocaleString('en-US', { month: 'short', year: 'numeric' });
    if (!monthsData[month]) monthsData[month] = { month, scans: 0, issues: 0 };
    monthsData[month].scans += 1;
    const totalVulns = scan.vulnerabilities_count 
      ? (scan.vulnerabilities_count.critical + scan.vulnerabilities_count.high + scan.vulnerabilities_count.medium + scan.vulnerabilities_count.low)
      : (scan.total_vulnerabilities || 0);
    monthsData[month].issues += totalVulns;
  });
  const scanHistoryChartData = Object.values(monthsData);

  // Top Vulnerability Categories Chart Data
  const categoriesData = Object.entries(summaryData?.by_category || {})
    .map(([cat, count]) => ({ category: cat || 'General Security', count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);

  // Extract Unique Orgs & Websites for filters is moved up.

  // Scan Types Breakdown Chart Data (Filtered)
  const scanTypeCounts = {};
  filteredScans.forEach(scan => {
    const type = scan.scan_type ? (scan.scan_type.charAt(0).toUpperCase() + scan.scan_type.slice(1)) + ' Scan' : 'Advanced Scan';
    scanTypeCounts[type] = (scanTypeCounts[type] || 0) + 1;
  });
  const scanTypeChartData = Object.entries(scanTypeCounts).map(([name, value]) => ({ name, value }));

  return (
    <div className="w-full text-on-surface animate-fade-in pb-xl">
      <div className="flex flex-col md:flex-row md:items-center justify-between mb-xl gap-sm border-b border-outline-variant/60 pb-md">
        <div>
          <h1 className="font-extrabold text-on-surface tracking-tight text-[24px] m-0 flex items-center gap-1.5">
            {user?.role === 'support_engineer' ? (
              <>Support Engineer <span className="text-primary">Operations</span></>
            ) : (
              <>LarShield <span className="text-primary">Global Management</span></>
            )}
          </h1>
          <p className="font-body-md text-on-surface-variant text-[13.5px] mt-1 m-0">
            {user?.role === 'support_engineer' 
              ? 'Client environment inspection, troubleshooting assistance, and system logs.' 
              : 'Centralized oversight for all client organizations, scans, and security nodes.'}
          </p>
        </div>
        <div className="flex gap-sm flex-wrap items-center">
          <button onClick={fetchData} className="flex items-center px-3.5 py-1.5 bg-surface-container border border-outline-variant text-on-surface rounded-lg hover:bg-surface-container-high transition-colors font-bold text-[12.5px] cursor-pointer shadow-2xs">
            <Activity className={`w-3.5 h-3.5 mr-1.5 text-primary ${loading ? 'animate-spin' : ''}`} /> Sync Metrics
          </button>
          <button onClick={() => navigate(user?.role === 'support_engineer' ? '/support' : '/super-admin')} className="flex items-center px-3.5 py-1.5 bg-surface-container border border-outline-variant text-on-surface rounded-lg hover:bg-surface-container-high transition-colors font-bold text-[12.5px] cursor-pointer shadow-2xs">
            <Shield className="w-3.5 h-3.5 mr-1.5 text-primary" /> Global Management
          </button>
          <button onClick={() => navigate('/super-admin/logs')} className="flex items-center px-3.5 py-1.5 bg-surface-container border border-outline-variant text-on-surface rounded-lg hover:bg-surface-container-high transition-colors font-bold text-[12.5px] cursor-pointer shadow-2xs">
            <ShieldAlert className="w-3.5 h-3.5 mr-1.5 text-primary" /> Logs & Threats
          </button>
          <button onClick={() => navigate(-1)} className="flex items-center px-4 py-1.5 bg-primary text-white rounded-lg hover:brightness-110 transition-all font-bold text-[13px] border-0 cursor-pointer shadow-sm">
            <ArrowLeft className="w-3.5 h-3.5 mr-1" /> Back
          </button>
        </div>
      </div>

      {/* Top Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-md mb-xl">
        {[
          { title: 'SECURITY SCORE', value: `${score}/100`, icon: Shield, color: score > 80 ? 'text-green-500' : score > 50 ? 'text-orange-500' : 'text-error', bg: score > 80 ? 'bg-green-500/10 border-green-500/20' : score > 50 ? 'bg-orange-500/10 border-orange-500/20' : 'bg-error/10 border-error/20' },
          { title: 'ACTIVE ASSETS', value: activeAssets.toString(), icon: Globe, color: 'text-blue-500', bg: 'bg-blue-500/10 border-blue-500/20' },
          { title: 'TOTAL SCANS', value: filteredScans.length.toString(), icon: Activity, color: 'text-purple-500', bg: 'bg-purple-500/10 border-purple-500/20' },
          { title: 'OPEN RISKS', value: totalVulnerabilities.toString(), icon: ShieldAlert, color: totalVulnerabilities > 0 ? 'text-orange-500' : 'text-green-500', bg: totalVulnerabilities > 0 ? 'bg-orange-500/10 border-orange-500/20' : 'bg-green-500/10 border-green-500/20' }
        ].map((metric, i) => (
          <div key={i} className="bg-surface-container-lowest border border-outline-variant p-lg rounded-2xl shadow-2xs hover:shadow-md transition-all group">
            <div className="flex justify-between items-center">
              <div>
                <p className="text-on-surface-variant font-bold text-[12px] uppercase tracking-wider mb-1.5">{metric.title}</p>
                <h3 className="text-[30px] font-extrabold tracking-tight text-on-surface leading-none">{metric.value}</h3>
              </div>
              <div className={`${metric.bg} p-3 rounded-xl border group-hover:scale-110 transition-transform flex items-center justify-center`}>
                <metric.icon className={`${metric.color} w-6 h-6`} />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Scan Engine Distribution */}
      {scanTypeChartData.length > 0 && (
        <div className="bg-surface-container-lowest border border-outline-variant p-lg rounded-2xl shadow-sm mb-xl">
          <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 gap-4">
            <h2 className="font-headline-sm font-bold text-on-surface text-[18px] flex items-center gap-2">
              <PieChartIcon className="w-5 h-5 text-purple-400" />
              Scan Mode Distribution
            </h2>
            <div className="flex gap-sm">
              <select 
                value={filterOrg} 
                onChange={e => setFilterOrg(e.target.value)} 
                className="bg-surface-container border border-outline-variant text-on-surface rounded-lg px-3 py-1.5 text-sm font-bold outline-none"
              >
                <option value="All">All Organizations</option>
                {uniqueOrgs.map(org => <option key={org} value={org}>{org}</option>)}
              </select>
              <select 
                value={filterWebsite} 
                onChange={e => setFilterWebsite(e.target.value)} 
                className="bg-surface-container border border-outline-variant text-on-surface rounded-lg px-3 py-1.5 text-sm font-bold outline-none"
              >
                <option value="All">All Websites</option>
                {uniqueWebsites.map(web => <option key={web} value={web}>{web.replace(/^https?:\/\//, '')}</option>)}
              </select>
            </div>
          </div>
          <div className="h-[250px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={scanTypeChartData}
                  cx="50%"
                  cy="50%"
                  outerRadius={85}
                  dataKey="value"
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                >
                  {scanTypeChartData.map((entry, index) => (
                    <Cell key={`scan-cell-${index}`} fill={SCAN_TYPE_COLORS[index % SCAN_TYPE_COLORS.length]} />
                  ))}
                </Pie>
                <RechartsTooltip content={<CustomChartTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Row 1: Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-lg mb-xl">
        {/* Risk Trend Line Chart */}
        <div className="bg-surface-container-lowest border border-outline-variant p-lg rounded-2xl shadow-sm">
          <h2 className="font-headline-sm font-bold text-on-surface mb-6 text-[18px] flex items-center gap-2">
            <Activity className="w-5 h-5 text-primary" />
            Security Score Trend (Recent {riskTrendData.length} Scans)
          </h2>
          <div className="h-[300px] w-full">
            {riskTrendData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={riskTrendData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" vertical={false} />
                  <XAxis dataKey="name" stroke="#9CA3AF" tick={{ fill: '#9CA3AF', fontSize: 11 }} />
                  <YAxis stroke="#9CA3AF" tick={{ fill: '#9CA3AF', fontSize: 12 }} domain={[0, 100]} />
                  <RechartsTooltip content={<CustomChartTooltip />} />
                  <Line type="monotone" dataKey="securityScore" name="Security Score" stroke="#3B82F6" strokeWidth={3} dot={{ r: 4, fill: '#3B82F6', strokeWidth: 2 }} activeDot={{ r: 6 }} />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center justify-center text-on-surface-variant">No scan history available.</div>
            )}
          </div>
        </div>

        {/* Vulnerability Distribution Bar Chart */}
        <div className="bg-surface-container-lowest border border-outline-variant p-lg rounded-2xl shadow-sm">
          <h2 className="font-headline-sm font-bold text-on-surface mb-6 text-[18px] flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-primary" />
            Severity Level Breakdown
          </h2>
          <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={vulnerabilityTypes} margin={{ top: 20, right: 30, left: 0, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" vertical={false} />
                <XAxis dataKey="name" stroke="#9CA3AF" tick={{ fill: '#9CA3AF', fontSize: 12 }} />
                <YAxis stroke="#9CA3AF" tick={{ fill: '#9CA3AF', fontSize: 12 }} />
                <RechartsTooltip content={<CustomChartTooltip />} />
                <Bar dataKey="value" name="Risks" radius={[4, 4, 0, 0]}>
                  <LabelList dataKey="value" position="top" fill="#9CA3AF" fontSize={12} fontWeight="bold" />
                  {vulnerabilityTypes.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.name.includes('Clean') ? '#10B981' : SEVERITY_COLORS[index % SEVERITY_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Row 2: Secondary Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-lg mb-xl">
        {/* Scan Frequency vs Issues Found */}
        <div className="bg-surface-container-lowest border border-outline-variant p-lg rounded-2xl shadow-sm">
          <h2 className="font-headline-sm font-bold text-on-surface mb-6 text-[18px] flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-primary" />
            Monthly Scans vs Issues Found
          </h2>
          <div className="h-[300px] w-full">
            {scanHistoryChartData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <ComposedChart data={scanHistoryChartData} margin={{ top: 20, right: 30, left: 0, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" vertical={false} />
                  <XAxis dataKey="month" stroke="#9CA3AF" tick={{ fill: '#9CA3AF', fontSize: 12 }} />
                  <YAxis yAxisId="left" orientation="left" stroke="#9CA3AF" tick={{ fill: '#9CA3AF', fontSize: 12 }} />
                  <YAxis yAxisId="right" orientation="right" stroke="#9CA3AF" tick={{ fill: '#9CA3AF', fontSize: 12 }} />
                  <RechartsTooltip content={<CustomChartTooltip />} />
                  <Legend wrapperStyle={{ fontSize: '12px' }} />
                  <Bar yAxisId="left" dataKey="scans" name="Total Scans" fill="#3B82F6" radius={[4, 4, 0, 0]} maxBarSize={40}>
                    <LabelList dataKey="scans" position="insideTop" fill="#ffffff" fontSize={11} fontWeight="bold" offset={10} />
                  </Bar>
                  <Line yAxisId="right" type="monotone" dataKey="issues" name="Issues Found" stroke="#EF4444" strokeWidth={3} dot={{ r: 4, fill: '#EF4444', strokeWidth: 2 }} activeDot={{ r: 6 }}>
                    <LabelList dataKey="issues" position="top" fill="#EF4444" fontSize={12} fontWeight="bold" offset={10} />
                  </Line>
                </ComposedChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center justify-center text-on-surface-variant">No scan history available.</div>
            )}
          </div>
        </div>

        {/* Top Vulnerability Categories */}
        <div className="bg-surface-container-lowest border border-outline-variant p-lg rounded-2xl shadow-sm">
          <h2 className="font-headline-sm font-bold text-on-surface mb-6 text-[18px] flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-orange-500" />
            Top Vulnerability Categories (OWASP)
          </h2>
          <div className="h-[300px] w-full">
            {categoriesData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={categoriesData} layout="vertical" margin={{ top: 10, right: 30, left: 40, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" horizontal={false} />
                  <XAxis type="number" stroke="#9CA3AF" tick={{ fill: '#9CA3AF', fontSize: 12 }} />
                  <YAxis dataKey="category" type="category" stroke="#9CA3AF" tick={{ fill: '#9CA3AF', fontSize: 11 }} width={110} />
                  <RechartsTooltip content={<CustomChartTooltip />} />
                  <Bar dataKey="count" name="Detections" fill="#F97316" radius={[0, 4, 4, 0]}>
                    <LabelList dataKey="count" position="right" fill="#9CA3AF" fontSize={11} fontWeight="bold" />
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center justify-center text-on-surface-variant">No category breakdown available.</div>
            )}
          </div>
        </div>
      </div>

    </div>
  );
};
