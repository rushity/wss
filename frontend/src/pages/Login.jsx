import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../components/AuthContext';

export const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [legalModal, setLegalModal] = useState(null);
  const { login } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    // Remove dark mode to enforce the white theme
    document.documentElement.classList.remove('dark');
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      const data = await res.json();
      if (res.ok) {
        login(data.access_token || data.token, data.refresh_token, data.user);
        if (rememberMe) {
          localStorage.setItem('wss_remember_email', email);
        } else {
          localStorage.removeItem('wss_remember_email');
        }
        navigate('/dashboard');
      } else {
        setError(data.message || 'Authentication failed. Please verify credentials.');
      }
    } catch (err) {
      setError('Could not establish connection to the security server API.');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const savedEmail = localStorage.getItem('wss_remember_email');
    if (savedEmail) {
      setEmail(savedEmail);
      setRememberMe(true);
    }
  }, []);

  return (
    <div className="bg-slate-50 min-h-screen flex flex-col justify-center items-center p-md relative overflow-hidden w-full text-slate-900 font-sans">
      
      {/* Background Gradients & Floating Elements for Light Mode */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-[-10%] left-[-10%] w-[500px] h-[500px] rounded-full bg-blue-400/20 blur-[120px] animate-float"></div>
        <div className="absolute bottom-[-20%] right-[-10%] w-[600px] h-[600px] rounded-full bg-indigo-400/10 blur-[150px] animate-float-delayed"></div>
        <div className="absolute top-[20%] right-[20%] w-[300px] h-[300px] rounded-full bg-sky-300/20 blur-[80px] animate-float"></div>
      </div>

      {/* Auth Container */}
      <main className="w-full max-w-[440px] bg-white/80 backdrop-blur-xl border border-slate-200 rounded-3xl shadow-[0_8px_30px_rgb(0,0,0,0.04)] p-10 flex flex-col gap-8 z-10 animate-slide-up relative overflow-hidden">
        
        {/* Header / Branding */}
        <div className="flex flex-col items-center gap-4 relative z-10">
          <div className="w-16 h-16 mb-2 flex items-center justify-center">
            <img src="/logo.png" alt="LarShield Logo" className="w-full h-full object-contain" />
          </div>
          <div className="text-center">
            <h1 className="text-3xl font-bold tracking-tight text-slate-900 mb-2">Welcome Back</h1>
            <p className="text-sm text-slate-500">Sign in to access your security console.</p>
          </div>
        </div>

        {/* Error Alert Box */}
        {error && (
          <div className="flex gap-3 bg-red-50 border border-red-200 rounded-xl p-4 text-red-700 text-sm items-center animate-fade-in relative z-10">
            <span className="material-symbols-outlined text-red-500">warning</span>
            <div>{error}</div>
          </div>
        )}

        {/* Login Form */}
        <form className="flex flex-col gap-5 relative z-10" onSubmit={handleSubmit}>
          
          <div className="flex flex-col gap-2">
            <label className="text-xs font-semibold text-slate-500 uppercase tracking-widest" htmlFor="email">Email Address</label>
            <div className="relative group">
              <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none transition-colors group-focus-within:text-blue-600 text-slate-400">
                <span className="material-symbols-outlined text-[20px]">mail</span>
              </div>
              <input 
                className="w-full bg-slate-50 border border-slate-200 rounded-xl pl-12 pr-4 py-3.5 text-sm text-slate-900 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all placeholder:text-slate-400" 
                id="email" 
                placeholder="admin@organization.com" 
                required 
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
          </div>

          <div className="flex flex-col gap-2">
            <div className="flex justify-between items-center">
              <label className="text-xs font-semibold text-slate-500 uppercase tracking-widest" htmlFor="password">Password</label>
              <a className="text-xs text-blue-600 hover:text-blue-700 hover:underline transition-colors font-medium" href="#">Forgot password?</a>
            </div>
            <div className="relative group">
              <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none transition-colors group-focus-within:text-blue-600 text-slate-400">
                <span className="material-symbols-outlined text-[20px]">lock</span>
              </div>
              <input 
                className="w-full bg-slate-50 border border-slate-200 rounded-xl pl-12 pr-12 py-3.5 text-sm text-slate-900 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all placeholder:text-slate-400" 
                id="password" 
                placeholder="••••••••" 
                required 
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <button
                type="button"
                className="absolute inset-y-0 right-0 pr-4 flex items-center text-slate-400 hover:text-blue-600 transition-colors"
                onClick={() => setShowPassword(!showPassword)}
                tabIndex="-1"
              >
                <span className="material-symbols-outlined text-[20px]">
                  {showPassword ? 'visibility_off' : 'visibility'}
                </span>
              </button>
            </div>

            {/* Password Validation Checklist - Only shown when typing password */}
            {password.length > 0 && (
              <div className="flex flex-col gap-1.5 mt-2 p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs animate-fade-in">
                <div className={`flex items-center gap-2 font-medium transition-colors ${password.length >= 8 ? 'text-emerald-600 font-semibold' : 'text-slate-500'}`}>
                  <span className="material-symbols-outlined text-[16px]">
                    {password.length >= 8 ? 'check_circle' : 'radio_button_unchecked'}
                  </span>
                  <span>At least 8 characters</span>
                </div>
                <div className={`flex items-center gap-2 font-medium transition-colors ${/[A-Z]/.test(password) ? 'text-emerald-600 font-semibold' : 'text-slate-500'}`}>
                  <span className="material-symbols-outlined text-[16px]">
                    {/[A-Z]/.test(password) ? 'check_circle' : 'radio_button_unchecked'}
                  </span>
                  <span>One uppercase letter</span>
                </div>
                <div className={`flex items-center gap-2 font-medium transition-colors ${/[a-z]/.test(password) ? 'text-emerald-600 font-semibold' : 'text-slate-500'}`}>
                  <span className="material-symbols-outlined text-[16px]">
                    {/[a-z]/.test(password) ? 'check_circle' : 'radio_button_unchecked'}
                  </span>
                  <span>One lowercase letter</span>
                </div>
                <div className={`flex items-center gap-2 font-medium transition-colors ${/[^A-Za-z0-9]/.test(password) ? 'text-emerald-600 font-semibold' : 'text-slate-500'}`}>
                  <span className="material-symbols-outlined text-[16px]">
                    {/[^A-Za-z0-9]/.test(password) ? 'check_circle' : 'radio_button_unchecked'}
                  </span>
                  <span>One special character</span>
                </div>
              </div>
            )}
          </div>

          <div className="flex items-center gap-3 mt-1">
            <div className="relative flex items-center">
              <input 
                className="peer w-5 h-5 appearance-none rounded-md border border-slate-300 bg-white checked:bg-blue-600 checked:border-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-500/30 transition-all cursor-pointer" 
                id="remember" 
                type="checkbox"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
              />
              <span className="material-symbols-outlined absolute text-white text-[16px] pointer-events-none opacity-0 peer-checked:opacity-100 left-[2px] top-[2px]">check</span>
            </div>
            <label className="text-sm text-slate-600 cursor-pointer select-none hover:text-slate-900 transition-colors font-medium" htmlFor="remember">Remember me</label>
          </div>

          <button 
            className="w-full bg-blue-600 text-white font-semibold rounded-xl py-4 mt-4 hover:bg-blue-700 hover:shadow-lg hover:shadow-blue-600/20 active:scale-[0.98] transition-all flex justify-center items-center gap-2 border-0 cursor-pointer relative overflow-hidden group" 
            type="submit"
            disabled={loading}
          >
            <span className="relative z-10">{loading ? 'Signing In...' : 'Sign In'}</span>
            <span className="material-symbols-outlined text-[20px] relative z-10">arrow_forward</span>
          </button>
        </form>

        <p className="text-xs text-slate-500 text-center mt-5 leading-relaxed relative z-10">
          By signing in, you agree to our{' '}
          <button
            type="button"
            onClick={() => setLegalModal('terms')}
            className="text-blue-600 hover:underline font-medium bg-transparent border-0 cursor-pointer p-0"
          >
            Terms of Service
          </button>{' '}
          and{' '}
          <button
            type="button"
            onClick={() => setLegalModal('aup')}
            className="text-blue-600 hover:underline font-medium bg-transparent border-0 cursor-pointer p-0"
          >
            Acceptable Use Policy
          </button>
          .
        </p>

        <div className="mt-6 pt-6 text-center border-t border-slate-100 relative z-10">
          <p className="text-sm text-slate-500">
            Don't have an account?{' '}
            <Link className="text-blue-600 hover:text-blue-700 hover:underline font-semibold transition-colors ml-1" to="/register">Create an account</Link>
          </p>
        </div>
      </main>

      {/* Legal Policies Modal */}
      {legalModal && (
        <div className="fixed inset-0 z-[9999] flex items-center justify-center p-4">
          <div 
            className="fixed inset-0 bg-black/60 backdrop-blur-sm transition-opacity"
            onClick={() => setLegalModal(null)}
          />
          
          <div className="bg-white border border-slate-200 shadow-2xl rounded-2xl w-full max-w-2xl relative z-10 animate-fade-in flex flex-col max-h-[90vh] overflow-hidden text-slate-900">
            
            {/* Header */}
            <div className="flex justify-between items-center px-6 py-4 border-b border-slate-200 bg-slate-50">
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined text-blue-600 text-[24px]">gavel</span>
                <h3 className="font-bold text-slate-900 text-lg">Legal Policies</h3>
              </div>
              <button 
                type="button"
                onClick={() => setLegalModal(null)}
                className="text-slate-400 hover:text-slate-700 hover:bg-slate-200/60 p-2 rounded-full transition-colors border-0 bg-transparent cursor-pointer flex items-center justify-center"
                title="Close"
              >
                <span className="material-symbols-outlined text-[20px]">close</span>
              </button>
            </div>

            {/* Policy Tab Switcher */}
            <div className="flex border-b border-slate-200 bg-white px-6 overflow-x-auto">
              <button
                type="button"
                onClick={() => setLegalModal('terms')}
                className={`py-3 px-4 text-xs font-bold border-b-2 transition-all cursor-pointer bg-transparent border-0 whitespace-nowrap ${
                  legalModal === 'terms' 
                    ? 'border-blue-600 text-blue-600' 
                    : 'border-transparent text-slate-500 hover:text-slate-900'
                }`}
              >
                Terms of Service
              </button>
              <button
                type="button"
                onClick={() => setLegalModal('aup')}
                className={`py-3 px-4 text-xs font-bold border-b-2 transition-all cursor-pointer bg-transparent border-0 whitespace-nowrap ${
                  legalModal === 'aup' 
                    ? 'border-blue-600 text-blue-600' 
                    : 'border-transparent text-slate-500 hover:text-slate-900'
                }`}
              >
                Acceptable Use Policy (AUP)
              </button>
              <button
                type="button"
                onClick={() => setLegalModal('privacy')}
                className={`py-3 px-4 text-xs font-bold border-b-2 transition-all cursor-pointer bg-transparent border-0 whitespace-nowrap ${
                  legalModal === 'privacy' 
                    ? 'border-blue-600 text-blue-600' 
                    : 'border-transparent text-slate-500 hover:text-slate-900'
                }`}
              >
                Privacy Policy
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto max-h-[60vh] text-left text-sm leading-relaxed text-slate-600 space-y-4">
              {legalModal === 'terms' && (
                <div>
                  <h3 className="text-xl font-bold text-slate-900 mb-1">Terms of Service</h3>
                  <p className="text-xs font-bold text-blue-600 mb-4">Effective Date: August 15, 2026</p>

                  <div className="space-y-4">
                    <div>
                      <h4 className="font-bold text-slate-900 text-sm">1. Acceptance of Terms</h4>
                      <p className="mt-1">By accessing or using the Larshield platform (the "Service"), you agree to be bound by these Terms of Service. If you do not agree, you may not access the Service.</p>
                    </div>

                    <div>
                      <h4 className="font-bold text-slate-900 text-sm">2. Description of Service</h4>
                      <p className="mt-1">Larshield provides automated vulnerability scanning, active penetration testing, and security posture management tools. The Service actively probes designated targets to identify security flaws, misconfigurations, and compliance violations.</p>
                    </div>

                    <div>
                      <h4 className="font-bold text-slate-900 text-sm">3. Authorization and Legal Use</h4>
                      <p className="mt-1">You explicitly certify that you possess full, legally verifiable authorization from the system owner to conduct active security assessments against any target URL you submit. Unauthorized scanning is illegal and strictly prohibited. You assume all liability for damages resulting from unauthorized use of the Service.</p>
                    </div>

                    <div>
                      <h4 className="font-bold text-slate-900 text-sm">4. Limitation of Liability</h4>
                      <p className="mt-1">Larshield is provided "AS IS". Vulnerability scanning can cause unintended disruptions, including data loss or system crashes. To the maximum extent permitted by law, Larshield shall not be liable for any direct, indirect, incidental, special, or consequential damages resulting from the use or inability to use the Service.</p>
                    </div>

                    <div>
                      <h4 className="font-bold text-slate-900 text-sm">5. Termination</h4>
                      <p className="mt-1">We reserve the right to suspend or terminate your account immediately, without prior notice or liability, for any reason, including without limitation if you breach the Terms, particularly regarding unauthorized target scanning.</p>
                    </div>
                  </div>
                </div>
              )}

              {legalModal === 'aup' && (
                <div>
                  <h3 className="text-xl font-bold text-slate-900 mb-1">Acceptable Use Policy (Rules of Engagement)</h3>
                  <p className="text-xs font-bold text-blue-600 mb-3">Effective Date: August 15, 2026</p>
                  
                  <p className="text-sm text-slate-600 mb-4 bg-amber-50 border border-amber-200 rounded-xl p-3 text-amber-900 font-medium">
                    This Acceptable Use Policy (AUP) sets the rules of engagement for utilizing the Larshield platform. Violating this policy will result in immediate account termination and potential legal referral.
                  </p>

                  <div className="space-y-4">
                    <div>
                      <h4 className="font-bold text-slate-900 text-sm">1. Prohibited Activities</h4>
                      <ul className="list-disc pl-5 mt-1 space-y-1.5">
                        <li><strong>Unauthorized Scanning:</strong> Scanning infrastructure, applications, or networks that you do not own or lack explicit, documented consent to test.</li>
                        <li><strong>Denial of Service (DoS/DDoS):</strong> Utilizing Larshield's infrastructure to intentionally flood, exhaust, or deny access to a target system.</li>
                        <li><strong>Destructive Payloads:</strong> Modifying, deleting, or exfiltrating data from a target system beyond what is strictly necessary to demonstrate a proof-of-concept for a vulnerability.</li>
                        <li><strong>Government &amp; Healthcare Infrastructure:</strong> You may not scan government, military, emergency services, or critical healthcare infrastructure without verifying compliance with local regulations.</li>
                      </ul>
                    </div>

                    <div>
                      <h4 className="font-bold text-slate-900 text-sm">2. Abuse Prevention and Monitoring</h4>
                      <p className="mt-1">Larshield implements automated heuristics to detect abuse. We reserve the right to instantly halt any active scan that triggers abuse thresholds, resembles a DoS attack, or targets known blacklisted domains.</p>
                    </div>
                  </div>
                </div>
              )}

              {legalModal === 'privacy' && (
                <div>
                  <h3 className="text-xl font-bold text-slate-900 mb-1">Privacy Policy</h3>
                  <p className="text-xs font-bold text-blue-600 mb-4">Effective Date: August 15, 2026</p>
                  
                  <p className="text-sm text-slate-600 leading-relaxed mb-4">
                    This Privacy Policy describes how Larshield ("we", "us", or "our") collects, uses, and shares your personal information. We are committed to complying with global data protection laws including the GDPR, CCPA, and India's DPDP Act.
                  </p>

                  <div className="space-y-4">
                    <div>
                      <h4 className="font-bold text-slate-900 text-sm">1. Information We Collect</h4>
                      <p className="mt-1"><strong>Account Data:</strong> Email address, name, billing information, and organization details.</p>
                      <p className="mt-1"><strong>Scan Data:</strong> Target URLs, scan configurations, identified vulnerabilities, and generated PDF reports.</p>
                      <p className="mt-1"><strong>Audit Logs:</strong> Origin IP addresses, access timestamps, and API request logs for security and compliance monitoring.</p>
                    </div>

                    <div>
                      <h4 className="font-bold text-slate-900 text-sm">2. How We Use Your Information</h4>
                      <p className="mt-1">We use your data strictly to provide, maintain, and improve the Service, process payments, and ensure legal compliance. We do not sell your personal data or scan results to third parties.</p>
                    </div>

                    <div>
                      <h4 className="font-bold text-slate-900 text-sm">3. Data Security</h4>
                      <p className="mt-1">Scan results and user data are encrypted at rest (AES-256) and in transit (TLS 1.3). We enforce strict role-based access controls internally. However, no internet transmission is entirely secure, and you use the Service at your own risk.</p>
                    </div>

                    <div>
                      <h4 className="font-bold text-slate-900 text-sm">4. Your Rights (GDPR &amp; CCPA)</h4>
                      <p className="mt-1">Depending on your jurisdiction, you have the right to access, correct, delete, or restrict the processing of your personal data. You can request a complete data export or account deletion by contacting <a href="mailto:info@larxius.com" className="text-blue-600 font-semibold hover:underline">info@larxius.com</a>.</p>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="flex justify-end p-4 border-t border-slate-200 bg-slate-50">
              <button
                type="button"
                onClick={() => setLegalModal(null)}
                className="bg-blue-600 text-white font-semibold py-2.5 px-6 rounded-xl hover:bg-blue-700 active:scale-95 transition-all text-sm border-0 cursor-pointer shadow-md shadow-blue-600/20"
              >
                I Understand
              </button>
            </div>

          </div>
        </div>
      )}
    </div>
  );
};
