import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../components/AuthContext';
import toast from 'react-hot-toast';

export const NewScan = () => {
  const [targetUrl, setTargetUrl] = useState('');
  const [scanType, setScanType] = useState('Quick');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [customHeaders, setCustomHeaders] = useState('');
  const [crawlDepth, setCrawlDepth] = useState('3');
  const [excludePaths, setExcludePaths] = useState('');
  const [enableRedTeam, setEnableRedTeam] = useState(false);
  const [scanConfig, setScanConfig] = useState([]);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [showUpgradeModal, setShowUpgradeModal] = useState(false);
  const [showQuotaExceededModal, setShowQuotaExceededModal] = useState(false);
  const [attemptedScan, setAttemptedScan] = useState('');
  const [quotas, setQuotas] = useState([]);

  const [isScheduled, setIsScheduled] = useState(false);
  const [scheduleFrequency, setScheduleFrequency] = useState('daily');
  const [scheduleTime, setScheduleTime] = useState('02:00');

  // Legal & Confirmation Modal States
  const [showConfirmModal, setShowConfirmModal] = useState(false);
  const [showPolicyModal, setShowPolicyModal] = useState(false);
  const [hasReadPolicy, setHasReadPolicy] = useState(false);
  const [policyCheck1, setPolicyCheck1] = useState(false);
  const [policyCheck2, setPolicyCheck2] = useState(false);
  const [isConfirmedChecked, setIsConfirmedChecked] = useState(false);

  const { token, user } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    fetch('/api/scans/config')
      .then(res => res.json())
      .then(data => {
        if (data.config) {
          setScanConfig(data.config);
        }
      })
      .catch(err => console.error("Failed to fetch scan config", err));
  }, []);

  useEffect(() => {
    if (user?.org_id && token) {
      fetch(`/api/auth/organizations/${user.org_id}/quotas`, {
        headers: { 'Authorization': `Bearer ${token}` }
      })
      .then(res => res.json())
      .then(data => {
        if (Array.isArray(data)) {
            setQuotas(data);
        } else if (data.quotas) {
            setQuotas(data.quotas);
        }
      })
      .catch(console.error);
    }
  }, [user?.org_id, token]);

  useEffect(() => {
    if (scanType === 'Deep') {
      setEnableRedTeam(true);
      setCrawlDepth('20');
    } else if (scanType === 'Advanced') {
      setEnableRedTeam(true);
      setCrawlDepth('10');
    } else if (scanType === 'Quick') {
      setEnableRedTeam(false);
      setCrawlDepth('3');
    }
  }, [scanType]);

  const hasQuota = (methodId) => {
    if (user?.role === 'admin' || user?.role === 'super_admin') return true;
    if (!quotas || quotas.length === 0) return true;
    const q = quotas.find(q => q.scan_type.toLowerCase() === methodId.toLowerCase());
    if (!q) return true;
    if (q.allocated_count === -1) return true;
    return (q.allocated_count - q.used_count) > 0;
  };

  const handleLaunch = (e) => {
    e.preventDefault();
    setError('');

    if (!hasQuota(scanType)) {
      setAttemptedScan(scanType);
      setShowQuotaExceededModal(true);
      return;
    }

    if (!targetUrl) {
      setError('Please provide a target host URL.');
      return;
    }

    try {
      const urlObj = new URL(targetUrl);
      if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
        setError('Please enter a valid website URL (must start with http:// or https://)');
        return;
      }
      if (!urlObj.hostname.includes('.')) {
        setError('Please enter a valid website URL (must have a valid domain structure)');
        return;
      }
    } catch (_) {
      setError('Please enter a valid website URL (must start with http:// or https://)');
      return;
    }

    // Open confirmation modal before actual launch
    setShowConfirmModal(true);
  };

  const executeScan = async () => {
    setShowConfirmModal(false);
    setLoading(true);

    try {
      let parsedAuthHeaders = {};
      if (customHeaders) {
          const lines = customHeaders.split('\n');
          lines.forEach(line => {
              const parts = line.split(':');
              if (parts.length >= 2) {
                  const key = parts[0].trim();
                  const value = parts.slice(1).join(':').trim();
                  if (key && value) parsedAuthHeaders[key] = value;
              }
          });
      }

      if (isScheduled) {
        const res = await fetch('/api/scans/schedule', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          },
          body: JSON.stringify({
            target_url: targetUrl,
            scan_type: scanType,
            frequency: scheduleFrequency,
            schedule_time: scheduleTime
          })
        });
        const data = await res.json();
        if (res.ok) {
          toast.success('Scan scheduled successfully!');
          navigate('/dashboard');
        } else {
          if (res.status === 403 || res.status === 402 || data.message?.toLowerCase().includes('quota')) {
            setAttemptedScan(scanType);
            setShowQuotaExceededModal(true);
          } else {
            toast.error(data.message || 'Failed to schedule scan.');
          }
        }
      } else {
        const res = await fetch('/api/scans/new', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          },
          body: JSON.stringify({
            target_url: targetUrl,
            scan_type: scanType,
            auth_headers: parsedAuthHeaders,
            custom_headers: customHeaders,
            crawl_depth: crawlDepth,
            exclude_paths: excludePaths,
            enable_red_team: enableRedTeam
          })
        });

        const data = await res.json();
        if (res.ok) {
          if (data.scan) {
            const existingActive = localStorage.getItem('wss_active_scan');
            if (!existingActive) {
              localStorage.setItem('wss_active_scan', JSON.stringify(data.scan));
            }
          }
          toast.success('Scan pipeline initiated successfully!');
          navigate('/dashboard');
        } else {
          if (res.status === 403 || res.status === 402 || data.message?.toLowerCase().includes('quota')) {
            setAttemptedScan(scanType);
            setShowQuotaExceededModal(true);
          } else {
            setError(data.message || 'Failed to initialize vulnerability scanning thread.');
          }
        }
      }
    } catch (err) {
      setError('Connection timeout. Scanner microservice unavailable.');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const scanMethodologies = [
    {
      id: 'Quick',
      title: 'Quick Scan',
      icon: 'bolt',
      desc: 'Rapid recon: HTTP headers audit, Nmap top-100 ports, SSLyze TLS check, technology fingerprinting & DNS lookup.',
      tools: ['Nmap', 'SSLyze', 'Headers', 'WHOIS'],
      duration: '~2-5 mins',
      price: '$4.99',
      colorClass: 'text-primary',
      requiredTier: 'free'
    },
    {
      id: 'Advanced',
      title: 'Advanced Scan',
      icon: 'security',
      desc: 'Comprehensive deep crawl: All security modules, XSS/SQLi fuzzing, path traversal, Nuclei templates & OWASP ZAP passive analysis.',
      tools: ['Nuclei', 'ZAP Passive', 'Fuzzer', 'Dir Scan', 'Subfinder', 'Amass'],
      duration: '~20-40 mins',
      price: '$44.99',
      colorClass: 'text-primary',
      requiredTier: 'pro'
    },
    {
      id: 'Deep',
      title: 'Deep Scan',
      icon: 'radar',
      desc: 'Exhaustive audit: All-port Nmap with vuln scripts, full TLS audit, OWASP ZAP active spider + active attack simulation.',
      tools: ['Nmap Full', 'ZAP Active', 'NSE Scripts', 'All Modules'],
      duration: '~1 hour+',
      price: '$99.99',
      colorClass: 'text-primary',
      requiredTier: 'enterprise'
    }
  ];

  const getTierLevel = (tier) => {
    if (tier === 'enterprise') return 3;
    if (tier === 'pro') return 2;
    return 1;
  };

  const userTierLevel = (user?.role === 'admin' || user?.role === 'super_admin') ? 3 : getTierLevel(user?.subscription_tier || 'free');

  return (
    <div className="max-w-4xl mx-auto w-full flex flex-col gap-lg text-left">

      {/* Page Header */}
      <header className="flex flex-col gap-base border-b border-outline-variant pb-md">
        <h1 className="font-headline-lg text-headline-lg text-on-surface">Initiate Scan</h1>
        <p className="font-body-md text-body-md text-on-surface-variant">
          Configure target parameters and execution methodology for a new vulnerability assessment.
        </p>
      </header>

      {/* Configuration Form Card */}
      <form onSubmit={handleLaunch} className="bg-surface-container-lowest border border-outline-variant rounded-xl p-lg flex flex-col gap-xl shadow-sm">

        {/* Error Alert Display */}
        {error && (
          <div className="flex gap-sm bg-error-container/20 border border-error/30 rounded-lg p-md text-error font-body-sm text-body-sm items-center">
            <span className="material-symbols-outlined shrink-0">error</span>
            <div>{error}</div>
          </div>
        )}

        {/* Target Configuration */}
        <div className="flex flex-col gap-sm">
          <label className="font-label-sm text-label-sm text-on-surface uppercase tracking-widest flex items-center gap-xs" htmlFor="target-url">
            <span className="material-symbols-outlined text-[16px]">language</span>
            Target Selection
          </label>
          <div className="relative flex items-center">
            <span className="absolute left-md text-on-surface-variant material-symbols-outlined pointer-events-none text-[20px]">link</span>
            <input
              id="target-url"
              name="target-url"
              type="url"
              required
              className="w-full bg-surface-container-low border border-outline-variant rounded-lg py-md pl-12 pr-md font-label-md text-label-md text-on-surface placeholder:text-outline focus:outline-none focus:border-primary focus:ring-2 focus:ring-primary/20 transition-all shadow-sm"
              placeholder="https://app.example.com"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
            />
          </div>
          <p className="font-body-sm text-body-sm text-on-surface-variant mt-xs">
            Ensure you have authorization to scan the specified domain or IP address.
          </p>
        </div>
        <hr className="border-outline-variant border-t" />

        {/* Scan Methodology Section */}
        <div className="flex flex-col gap-md">
          <div className="flex flex-col gap-xs">
            <label className="font-label-sm text-label-sm text-on-surface uppercase tracking-widest flex items-center gap-xs">
              <span className="material-symbols-outlined text-[16px]">tune</span>
              Scan Methodology
            </label>
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              Select your scanning depth profile. Standard tiers include allocated vulnerability audit quotas.
            </p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-md">
            {scanMethodologies.map((method) => {
              const config = scanConfig.find(c => c.scan_type === method.id);
              const requiredTier = config ? config.required_tier : method.requiredTier;
              const isEnabled = config ? config.is_enabled : true;

              const isSelected = scanType === method.id;
              const isQuotaAvailable = hasQuota(method.id);
              const isTierLocked = !isQuotaAvailable && (userTierLevel < getTierLevel(requiredTier));
              const isQuotaExceeded = !isQuotaAvailable;
              const isLocked = isTierLocked || isQuotaExceeded;

              if (!isEnabled) {
                  return (
                    <div key={method.id} className="border border-outline-variant bg-surface-container-highest/20 rounded-lg p-md flex flex-col gap-sm relative opacity-50 cursor-not-allowed">
                       <div className="flex justify-between items-start">
                        <div className="h-10 w-10 rounded-full flex items-center justify-center bg-surface-container-high text-outline">
                          <span className="material-symbols-outlined">block</span>
                        </div>
                        <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-1 bg-surface-container-high text-on-surface-variant rounded-md">Disabled</span>
                      </div>
                      <div className="flex flex-col gap-xs mt-sm text-left">
                        <span className="font-label-md text-label-md text-on-surface font-bold">{method.title}</span>
                        <span className="font-body-sm text-body-sm text-on-surface-variant line-clamp-3">Currently unavailable.</span>
                      </div>
                    </div>
                  );
              }

              return (
                <div
                  key={method.id}
                  onClick={() => {
                    if (isTierLocked) {
                      setAttemptedScan(method.title);
                      setShowUpgradeModal(true);
                      return;
                    }
                    if (isQuotaExceeded) {
                      setAttemptedScan(method.title);
                      setShowQuotaExceededModal(true);
                      return;
                    }
                    setScanType(method.id);
                  }}
                  className={`border rounded-lg p-md cursor-pointer transition-all flex flex-col gap-sm relative group ${
                    isLocked ? 'border-outline-variant bg-surface-container/50 hover:bg-surface-container opacity-70' :
                    isSelected
                      ? 'border-primary bg-primary/5 shadow-[0_0_0_1px_#2563eb]'
                      : 'border-outline-variant bg-surface-container-lowest hover:bg-surface-container-low'
                  }`}
                >
                  <div className="flex justify-between items-start">
                    <div className={`h-10 w-10 rounded-full flex items-center justify-center transition-colors ${
                      isLocked ? 'bg-surface-container-high text-outline' :
                      isSelected
                        ? 'bg-primary/10 text-primary'
                        : 'bg-surface-container text-secondary group-hover:bg-surface-container-high'
                    }`}>
                      <span className="material-symbols-outlined">{isLocked ? (isQuotaExceeded ? 'workspace_premium' : 'lock') : method.icon}</span>
                    </div>

                    {!isLocked && (
                      <span className={`material-symbols-outlined transition-all ${isSelected
                          ? 'opacity-100 text-primary'
                          : 'opacity-0 text-outline'
                        }`} style={{ fontVariationSettings: isSelected ? "'FILL' 1" : "normal" }}>
                        check_circle
                      </span>
                    )}
                    {isLocked && (
                      <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-1 bg-surface-container-high text-on-surface-variant rounded-md">
                        {isQuotaExceeded ? '0 Quota' : requiredTier}
                      </span>
                    )}
                  </div>

                  <div className="flex flex-col gap-xs mt-sm text-left">
                    <div className="flex items-center justify-between">
                      <span className="font-label-md text-label-md text-on-surface font-bold">
                        {method.title}
                      </span>
                      <span className="text-[11px] font-extrabold px-2 py-0.5 rounded-full bg-primary/10 text-primary border border-primary/20">
                        {method.price}
                      </span>
                    </div>
                    <span className="font-body-sm text-body-sm text-on-surface-variant line-clamp-3">
                      {method.desc}
                    </span>
                    {method.tools && (
                      <div className="flex flex-wrap gap-xs mt-xs">
                        {method.tools.map(tool => (
                          <span key={tool} className={`text-[10px] font-bold uppercase tracking-wider px-[6px] py-[2px] rounded-full border ${
                            isLocked ? 'border-outline-variant text-outline bg-transparent' :
                            isSelected
                              ? 'border-primary/40 text-primary bg-primary/10'
                              : 'border-outline-variant text-on-surface-variant bg-surface-container'
                          }`}>
                            {tool}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="flex items-center justify-between mt-auto pt-sm">
                    <span className={`font-label-sm text-label-sm ${
                      isLocked ? 'text-outline font-bold' :
                      isSelected ? 'text-primary font-bold' : 'text-secondary'
                    }`}>
                      ⏱ {method.duration}
                    </span>
                    <span className="text-[11px] font-semibold text-on-surface-variant">
                      {method.id === 'Quick' ? '13 modules' : method.id === 'Advanced' ? '36 modules' : '89 modules'}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <hr className="border-outline-variant border-t" />

        {/* Schedule Scan Section */}
        <div className="flex flex-col gap-sm">
          <label className="flex items-center gap-sm cursor-pointer font-body-sm text-on-surface">
            <input
              type="checkbox"
              checked={isScheduled}
              onChange={(e) => setIsScheduled(e.target.checked)}
              className="h-4 w-4 rounded border-outline-variant text-primary focus:ring-primary/30"
            />
            <span className="font-semibold uppercase tracking-wider font-label-sm">Schedule Automated Scans</span>
            <span className="text-on-surface-variant text-[12px]">— Setup recurring scans (Enterprise feature)</span>
          </label>
          
          {isScheduled && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-md p-md bg-surface-container-low dark:bg-inverse-surface rounded-lg mt-xs border border-outline-variant/60">
              <div className="flex flex-col gap-xs">
                <label className="font-label-sm text-label-sm text-on-surface-variant uppercase tracking-wider font-semibold">Frequency</label>
                <select
                  className="w-full bg-surface-container-lowest border border-outline-variant rounded px-md py-sm font-body-sm text-on-surface focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all cursor-pointer"
                  value={scheduleFrequency}
                  onChange={(e) => setScheduleFrequency(e.target.value)}
                >
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly (Sundays)</option>
                </select>
              </div>
              <div className="flex flex-col gap-xs">
                <label className="font-label-sm text-label-sm text-on-surface-variant uppercase tracking-wider font-semibold">Time (UTC)</label>
                <input
                  type="time"
                  className="w-full bg-surface-container-lowest border border-outline-variant rounded px-md py-sm font-body-sm text-on-surface focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all"
                  value={scheduleTime}
                  onChange={(e) => setScheduleTime(e.target.value)}
                />
              </div>
            </div>
          )}
        </div>

        <hr className="border-outline-variant border-t" />

        {/* Legal Warning Notice */}
        <div className="bg-surface-container-low dark:bg-inverse-surface border-l-4 border-primary p-md rounded-lg text-body-sm font-body-sm text-on-surface-variant leading-relaxed">
          <strong className="text-on-surface font-semibold uppercase tracking-wider block mb-[4px]">
            Operator Notice & Policy Compliance
          </strong>
          Conducting vulnerability analysis scans against networks or hosts without explicit, verified written authorization is illegal. By executing this scan, you certify that you possess the necessary regulatory clearance to target this host.
        </div>

        {/* Action Area */}
        <div className="flex justify-end pt-sm border-t border-outline-variant/50">
          <button
            type="submit"
            disabled={loading}
            className="bg-primary text-on-primary font-label-md text-label-md px-xl py-md rounded-lg flex items-center gap-sm hover:opacity-90 transition-opacity shadow-sm font-bold border-0 cursor-pointer"
          >
            {loading ? (
              <>
                <span className="material-symbols-outlined animate-spin text-[18px]">sync</span>
                {isScheduled ? "Scheduling..." : "Executing Pipeline..."}
              </>
            ) : (
              <>
                <span className="material-symbols-outlined text-[18px]" style={{ fontVariationSettings: "'FILL' 1" }}>
                  {isScheduled ? "calendar_month" : "play_arrow"}
                </span>
                {isScheduled ? "Schedule Automation" : "Execute Scan Pipeline"}
              </>
            )}
          </button>
        </div>
      </form>

      {/* Subscription Tier Required Modal */}
      {showUpgradeModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-md">
          <div className="absolute inset-0 bg-scrim/50 backdrop-blur-sm" onClick={() => setShowUpgradeModal(false)}></div>
          <div className="relative bg-surface-container border border-outline-variant rounded-xl shadow-lg max-w-md w-full flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-200">
            <div className="bg-surface-container-highest p-md border-b border-outline-variant flex justify-between items-center">
              <h3 className="font-headline-sm text-headline-sm text-on-surface flex items-center gap-sm">
                <span className="material-symbols-outlined text-primary">lock</span>
                Subscription Required
              </h3>
              <button onClick={() => setShowUpgradeModal(false)} className="text-on-surface-variant hover:text-on-surface transition-colors cursor-pointer bg-transparent border-0">
                <span className="material-symbols-outlined">close</span>
              </button>
            </div>
            <div className="p-xl flex flex-col gap-md text-left">
              <p className="font-body-md text-body-md text-on-surface-variant">
                You cannot use the <strong className="text-on-surface">{attemptedScan}</strong> methodology on your current plan.
              </p>
              <p className="font-body-md text-body-md text-on-surface-variant">
                If you need to use this feature, please upgrade your subscription plan to unlock advanced vulnerability scanning capabilities.
              </p>
            </div>
            <div className="p-md bg-surface-container-low border-t border-outline-variant flex justify-end gap-sm">
              <button 
                onClick={() => setShowUpgradeModal(false)}
                className="px-md py-sm rounded-lg font-label-md text-label-md text-on-surface hover:bg-surface-container-highest transition-colors cursor-pointer border border-outline-variant bg-transparent"
              >
                Cancel
              </button>
              <button 
                onClick={() => {
                  setShowUpgradeModal(false);
                  navigate('/pricing');
                }}
                className="px-md py-sm rounded-lg font-label-md text-label-md bg-primary text-on-primary hover:opacity-90 transition-opacity cursor-pointer border-0 shadow-sm flex items-center gap-xs"
              >
                View Plans
                <span className="material-symbols-outlined text-[18px]">arrow_forward</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Scan Quota Exceeded Modal Popup */}
      {showQuotaExceededModal && (
        <div className="fixed inset-0 z-[9999] flex items-center justify-center p-4">
          {/* Backdrop */}
          <div 
            className="fixed inset-0 bg-slate-900/60 backdrop-blur-sm transition-opacity animate-fade-in"
            onClick={() => setShowQuotaExceededModal(false)}
          ></div>

          {/* Modal Content */}
          <div className="relative bg-white rounded-3xl border border-slate-200 shadow-2xl max-w-md w-full p-8 overflow-hidden z-10 animate-slide-up text-left">
            
            {/* Top Glowing Icon Circle */}
            <div className="w-14 h-14 rounded-2xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center mb-5">
              <span className="material-symbols-outlined text-amber-600 text-[32px]">workspace_premium</span>
            </div>

            {/* Header Badge */}
            <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-amber-50 border border-amber-200 text-amber-700 text-xs font-bold mb-3">
              <span className="w-2 h-2 rounded-full bg-amber-500 animate-pulse"></span>
              <span>Quota Limit Reached (0 Scans Left)</span>
            </div>

            {/* Modal Title */}
            <h3 className="text-2xl font-bold text-slate-900 tracking-tight mb-2">
              Scanning Quota Exhausted
            </h3>

            {/* Modal Description */}
            <p className="text-sm text-slate-600 leading-relaxed mb-6">
              Your organization has used all allocated scan credits for <strong className="text-slate-900">{attemptedScan || scanType} Scans</strong>. To execute additional vulnerability scans, please upgrade your plan or purchase scan credits.
            </p>

            {/* Action Buttons */}
            <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-100">
              <button
                type="button"
                onClick={() => setShowQuotaExceededModal(false)}
                className="px-5 py-2.5 rounded-xl text-sm font-semibold text-slate-600 hover:bg-slate-100 transition-colors border border-slate-200 cursor-pointer bg-white"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => {
                  setShowQuotaExceededModal(false);
                  navigate('/pricing');
                }}
                className="px-5 py-2.5 rounded-xl text-sm font-semibold text-white bg-blue-600 hover:bg-blue-700 active:scale-95 transition-all shadow-md shadow-blue-600/20 flex items-center gap-2 cursor-pointer border-0"
              >
                <span>Upgrade Plan</span>
                <span className="material-symbols-outlined text-[18px]">arrow_forward</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Confirm Scan Execution Modal Popup */}
      {showConfirmModal && (
        <div className="fixed inset-0 z-[9999] flex items-center justify-center p-4">
          {/* Backdrop */}
          <div 
            className="fixed inset-0 bg-slate-900/60 backdrop-blur-sm transition-opacity animate-fade-in"
            onClick={() => setShowConfirmModal(false)}
          ></div>

          {/* Modal Content */}
          <div className="relative bg-white rounded-2xl border border-slate-200 shadow-2xl max-w-[480px] w-full p-6 overflow-hidden z-10 animate-slide-up text-left font-sans">
            
            {/* Header */}
            <div className="flex items-start justify-between pb-3.5 border-b border-slate-100">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-full bg-blue-100 text-blue-600 flex items-center justify-center text-sm font-bold shrink-0 shadow-xs">
                  <span className="material-symbols-outlined text-[18px]">alternate_email</span>
                </div>
                <div>
                  <h3 className="text-[17px] font-extrabold text-slate-900 tracking-tight leading-tight">
                    Confirm Scan Execution
                  </h3>
                  <p className="text-[12px] font-medium text-slate-500 mt-[2px]">
                    Review target parameters before starting the scan pipeline
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setShowConfirmModal(false)}
                className="text-slate-400 hover:text-slate-600 transition-colors bg-transparent border-0 cursor-pointer p-1 rounded-full hover:bg-slate-100 flex items-center justify-center"
              >
                <span className="material-symbols-outlined text-[18px]">close</span>
              </button>
            </div>

            {/* Target Parameters Card */}
            <div className="my-4 p-3.5 rounded-xl bg-[#f8fafc] border border-slate-200/80 flex flex-col gap-2.5 text-[12px]">
              <div className="flex items-center justify-between">
                <span className="text-slate-500 font-bold uppercase tracking-wider text-[11px]">TARGET URL</span>
                <span className="text-blue-600 font-bold font-mono break-all max-w-[280px] text-right">{targetUrl}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-500 font-bold uppercase tracking-wider text-[11px]">SCAN INTENSITY</span>
                <span className="px-2.5 py-0.5 rounded-full bg-blue-50 text-blue-600 border border-blue-200 text-[11px] font-bold">{scanType} Scan</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-500 font-bold uppercase tracking-wider text-[11px]">EXECUTION TYPE</span>
                <span className="text-slate-800 font-semibold">{isScheduled ? 'Scheduled Execution' : 'Immediate Execution'}</span>
              </div>
            </div>

            {/* Confirmation Checkbox & Policy Link */}
            <div className="flex flex-col gap-1.5 mb-4">
              <label className={`flex items-start gap-2.5 text-[12px] font-normal text-slate-700 cursor-pointer ${!hasReadPolicy ? 'opacity-60 cursor-not-allowed' : ''}`}>
                <input
                  type="checkbox"
                  disabled={!hasReadPolicy}
                  checked={isConfirmedChecked}
                  onChange={(e) => setIsConfirmedChecked(e.target.checked)}
                  className="mt-0.5 h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500 cursor-pointer disabled:cursor-not-allowed shrink-0"
                />
                <span className="leading-snug">
                  I confirm that I have <strong className="font-extrabold text-slate-900">explicit written authorization</strong> to execute active penetration testing against <strong className="font-extrabold text-slate-900">{targetUrl}</strong>.
                </span>
              </label>

              <div className="pl-6.5">
                {hasReadPolicy ? (
                  <span className="inline-flex items-center gap-1 text-[12px] font-semibold text-emerald-600">
                    <span className="material-symbols-outlined text-[16px]">check_circle</span>
                    Security Policy Read & Accepted
                  </span>
                ) : (
                  <button
                    type="button"
                    onClick={() => setShowPolicyModal(true)}
                    className="text-[12px] font-bold text-blue-600 hover:underline bg-transparent border-0 p-0 cursor-pointer text-left"
                  >
                    Read Security Policy & Authorization Terms
                  </button>
                )}
              </div>
            </div>

            {/* Warning Alert Box */}
            <div className="p-3.5 rounded-xl bg-[#fffbeb] border border-[#fde68a] text-[#b45309] text-[12px] leading-relaxed flex items-start gap-2.5 mb-5">
              <span className="material-symbols-outlined text-[#d97706] text-[18px] shrink-0 mt-0.5">help_outline</span>
              <div>
                Are you sure you want to run this scan on <strong className="font-bold text-[#92400e]">{targetUrl}?</strong> If you are sure, read the security policy to enable the confirmation box, check it, and click <strong className="font-bold text-[#92400e]">Yes, Start Scan.</strong>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex items-center justify-end gap-3 pt-3.5 border-t border-slate-100">
              <button
                type="button"
                onClick={() => setShowConfirmModal(false)}
                className="px-4 py-2 rounded-xl text-[12px] font-bold text-slate-700 bg-slate-100 border border-slate-200 hover:bg-slate-200 transition-colors cursor-pointer"
              >
                No, Cancel
              </button>
              <button
                type="button"
                disabled={!hasReadPolicy || !isConfirmedChecked || loading}
                onClick={executeScan}
                className="px-4 py-2 rounded-xl text-[12px] font-bold text-white bg-[#6366f1] hover:bg-[#4f46e5] disabled:opacity-40 disabled:cursor-not-allowed transition-all shadow-md shadow-indigo-500/20 flex items-center gap-1.5 cursor-pointer border-0"
              >
                <span className="material-symbols-outlined text-[16px]">play_circle</span>
                <span>{loading ? "Initiating..." : "Yes, Start Scan"}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Security Policy & Legal Disclaimer Modal */}
      {showPolicyModal && (
        <div className="fixed inset-0 z-[10000] flex items-center justify-center p-4">
          {/* Backdrop */}
          <div 
            className="fixed inset-0 bg-slate-900/70 backdrop-blur-md transition-opacity animate-fade-in"
            onClick={() => setShowPolicyModal(false)}
          ></div>

          {/* Modal Content */}
          <div className="relative bg-white dark:bg-slate-900 rounded-3xl border border-slate-200 dark:border-slate-800 shadow-2xl max-w-2xl w-full p-6 overflow-hidden z-10 animate-slide-up text-left flex flex-col max-h-[85vh]">
            
            {/* Modal Header */}
            <div className="flex items-center justify-between pb-4 border-b border-slate-100 dark:border-slate-800 shrink-0">
              <div className="flex items-center gap-2.5">
                <span className="material-symbols-outlined text-blue-600 dark:text-blue-400 text-[24px]">gavel</span>
                <h3 className="text-lg font-bold text-slate-900 dark:text-white tracking-tight">
                  Security Policy & Legal Disclaimer
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setShowPolicyModal(false)}
                className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors bg-transparent border-0 cursor-pointer p-1"
              >
                <span className="material-symbols-outlined text-[20px]">close</span>
              </button>
            </div>

            {/* Modal Body - Policy Content (Scrollable) */}
            <div className="my-4 overflow-y-auto pr-2 flex-1 text-xs text-slate-600 dark:text-slate-300 leading-relaxed space-y-4 font-sans">
              <div className="p-3 bg-slate-50 dark:bg-slate-800/50 rounded-xl border border-slate-200/60 dark:border-slate-700/60 font-mono text-[11px] text-slate-500">
                <div><strong>Effective Date:</strong> August 15, 2026</div>
                <div><strong>Applies to:</strong> All users of the Larshield vulnerability scanning platform ("the Service")</div>
              </div>

              <div>
                <h4 className="font-bold text-slate-900 dark:text-white text-xs mb-1">1. Explicit Authorization and Legal Compliance</h4>
                <p>By initiating any scan, probe, or assessment through Larshield, you explicitly certify, represent, and warrant that you possess full, documented, and legally verifiable authorization from the owner of the target system to conduct active security assessments, penetration testing, or vulnerability scanning against it.</p>
                <p className="mt-2">You acknowledge that scanning any computer, network, or application without proper authorization is illegal under applicable law — including, without limitation, the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), the Information Technology Act (India), and equivalent statutes in other jurisdictions. Larshield is intended strictly for authorized security testing, such as systems you own, systems within a scope you have been contractually engaged to test, or environments explicitly designated for security research (e.g., CTF ranges, bug bounty programs with defined scope).</p>
              </div>

              <div>
                <h4 className="font-bold text-slate-900 dark:text-white text-xs mb-1">2. Assumption of Risk & Potential Impact</h4>
                <p>You acknowledge that vulnerability scanning and penetration testing are inherently intrusive activities. Depending on configuration, they may involve port scanning, service fingerprinting, exploitation simulation, or payload delivery, any of which could cause service degradation, data loss, or downtime on the target system.</p>
                <p className="mt-2">By using Larshield, you accept full responsibility for any operational impact resulting from your use of the tool, and you agree to take reasonable precautions (e.g., scheduling scans during maintenance windows, using rate-limited or passive modes where appropriate) when testing production systems.</p>
              </div>

              <div>
                <h4 className="font-bold text-slate-900 dark:text-white text-xs mb-1">3. Indemnification and Hold Harmless</h4>
                <p>You agree to indemnify, defend, and hold harmless the Larshield project, its developer(s), contributors, and affiliates from any claims, damages, liabilities, costs, or losses (including reasonable legal fees) arising from your use of the Service — including any unauthorized or improper use.</p>
                <p className="mt-2">Larshield is provided on an "AS IS" and "AS AVAILABLE" basis, without warranties of any kind, express or implied, including but not limited to fitness for a particular purpose or non-infringement. Larshield and its creators shall not be liable for any direct, indirect, incidental, or consequential damages resulting from use or misuse of the Service.</p>
              </div>

              <div>
                <h4 className="font-bold text-slate-900 dark:text-white text-xs mb-1">4. Audit Logging and Cooperation with Authorities</h4>
                <p>Larshield logs scan activity, including origin IP address, timestamp, scan configuration, and target parameters, for security, abuse-prevention, and accountability purposes.</p>
                <p className="mt-2">In the event of an investigation into unauthorized access, abuse, or a legal inquiry, Larshield reserves the right to share relevant audit logs with law enforcement, hosting providers, or the affected system owner, as required or permitted by law.</p>
              </div>

              <div>
                <h4 className="font-bold text-slate-900 dark:text-white text-xs mb-1">5. Acceptable Use</h4>
                <p>You agree not to use Larshield to:</p>
                <ul className="list-disc pl-5 mt-1 space-y-1">
                  <li>Scan or test any system without documented authorization from its owner</li>
                  <li>Deliver malicious payloads intended to cause damage beyond what is necessary for a legitimate, authorized assessment</li>
                  <li>Circumvent rate limits or access controls of third-party systems outside an agreed testing scope</li>
                </ul>
              </div>

              <div>
                <h4 className="font-bold text-slate-900 dark:text-white text-xs mb-1">6. Data Handling</h4>
                <p>Scan results are stored per-user and are not shared with third parties except as required under Section 4.</p>
              </div>

              <div>
                <h4 className="font-bold text-slate-900 dark:text-white text-xs mb-1">7. Changes to This Policy</h4>
                <p>Larshield may update this policy from time to time. Continued use of the Service after changes are posted constitutes acceptance of the revised policy.</p>
              </div>

              <p className="pt-2 font-semibold text-slate-900 dark:text-white">
                By clicking "I Accept" below, you confirm that you have read, understood, and agree to be bound by this Security Policy & EULA.
              </p>

              {/* Checkbox Section inside Modal */}
              <div className="p-4 bg-slate-100 dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 flex flex-col gap-2.5 mt-4">
                <label className="flex items-center gap-2.5 text-xs font-semibold text-slate-800 dark:text-slate-200 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={policyCheck1}
                    onChange={(e) => setPolicyCheck1(e.target.checked)}
                    className="h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500 cursor-pointer"
                  />
                  <span>I have read and agree to the terms above</span>
                </label>
                <label className="flex items-center gap-2.5 text-xs font-semibold text-slate-800 dark:text-slate-200 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={policyCheck2}
                    onChange={(e) => setPolicyCheck2(e.target.checked)}
                    className="h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500 cursor-pointer"
                  />
                  <span>I certify that I have authorization to scan any target(s) I submit to this Service</span>
                </label>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-100 dark:border-slate-800 shrink-0">
              <button
                type="button"
                onClick={() => setShowPolicyModal(false)}
                className="px-5 py-2.5 rounded-xl text-xs font-bold text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={!policyCheck1 || !policyCheck2}
                onClick={() => {
                  setHasReadPolicy(true);
                  setShowPolicyModal(false);
                }}
                className="px-6 py-2.5 rounded-xl text-xs font-bold text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed transition-all shadow-md shadow-blue-600/20 cursor-pointer border-0"
              >
                I Accept
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};
