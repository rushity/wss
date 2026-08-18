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
  const [attemptedScan, setAttemptedScan] = useState('');
  const [quotas, setQuotas] = useState([]);
  
  const [isScheduled, setIsScheduled] = useState(false);
  const [scheduleFrequency, setScheduleFrequency] = useState('daily');
  const [scheduleTime, setScheduleTime] = useState('02:00');

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
        // The backend returns an array directly if it's the result variable, 
        // wait, let's log or safely set it. I will set it to data if data is an array, else data.quotas
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

  const handleLaunch = async (e) => {
    e.preventDefault();
    setError('');

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
          toast.error(data.message || 'Failed to schedule scan.');
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
          navigate('/dashboard');
        } else {
          setError(data.message || 'Failed to initialize vulnerability scanning thread.');
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

  const userTierLevel = getTierLevel(user?.subscription_tier || 'free');

  const hasQuota = (methodId) => {
    const q = quotas.find(q => q.scan_type.toLowerCase() === methodId.toLowerCase());
    return q && (q.allocated_count > -1 && q.allocated_count - q.used_count > 0);
  };

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
              Purchasing a plan provides <strong>3 full scans</strong> for your target website property.
            </p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-md">
            {scanMethodologies.map((method) => {
              const config = scanConfig.find(c => c.scan_type === method.id);
              const requiredTier = config ? config.required_tier : method.requiredTier;
              const isEnabled = config ? config.is_enabled : true;

              const isSelected = scanType === method.id;
              const isLocked = userTierLevel < getTierLevel(requiredTier) && !hasQuota(method.id);

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
                    if (isLocked) {
                      setAttemptedScan(method.title);
                      setShowUpgradeModal(true);
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
                      <span className="material-symbols-outlined">{isLocked ? 'lock' : method.icon}</span>
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
                        {requiredTier}
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

        {/* Legal Warning Notice (Bento style block from previous and template combined) */}
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


      {/* Upgrade Modal */}
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
                onClick={() => navigate('/pricing')}
                className="px-md py-sm rounded-lg font-label-md text-label-md bg-primary text-on-primary hover:opacity-90 transition-opacity cursor-pointer border-0 shadow-sm flex items-center gap-xs"
              >
                View Plans
                <span className="material-symbols-outlined text-[18px]">arrow_forward</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
