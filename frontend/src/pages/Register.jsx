import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../components/AuthContext';

export const Register = () => {
  const [fullName, setFullName] = useState('');
  const [companyName, setCompanyName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [agreeTerms, setAgreeTerms] = useState(false);
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

    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    if (!agreeTerms) {
      setError('You must agree to the Terms of Service and Privacy Policy.');
      return;
    }

    setLoading(true);

    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      const data = await res.json();
      if (res.ok) {
        login(data.access_token || data.token, data.refresh_token, data.user);
        navigate('/dashboard');
      } else {
        setError(data.message || 'Registration failed. Please try again.');
      }
    } catch (err) {
      setError('Could not establish connection to the security server API.');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-slate-50 min-h-screen flex selection:bg-blue-100 selection:text-blue-900 w-full text-slate-900 font-sans">
      
      {/* Left Side: Branding & Visual Context */}
      <div className="hidden lg:flex w-5/12 bg-white flex-col justify-between p-12 relative overflow-hidden shrink-0 border-r border-slate-200">
        
        {/* Background Gradients */}
        <div className="absolute inset-0 overflow-hidden pointer-events-none z-0">
          <div className="absolute top-[-10%] left-[-20%] w-[600px] h-[600px] rounded-full bg-blue-100/50 blur-[120px] animate-float"></div>
          <div className="absolute bottom-[10%] right-[-10%] w-[400px] h-[400px] rounded-full bg-indigo-100/50 blur-[100px] animate-float-delayed"></div>
        </div>

        {/* Brand Anchor */}
        <div className="flex items-center gap-3 z-10 text-left animate-slide-up">
          <div className="w-12 h-12 flex items-center justify-center">
            <img src="/LarShield Symbol logo.png" alt="LarShield Logo" className="w-full h-full object-contain" />
          </div>
          <span className="text-2xl font-bold tracking-tight brand-gradient">LarShield</span>
        </div>
        
        {/* Value Proposition */}
        <div className="z-10 max-w-md text-left animate-slide-up" style={{ animationDelay: '100ms' }}>
          <div className="mb-6 flex justify-center lg:justify-start">
            <img src="/shield-graphic.png" alt="LarShield Security Graphic" className="w-64 max-w-full h-auto object-contain drop-shadow-xl hover:scale-105 transition-transform duration-300" />
          </div>
          <h2 className="text-3xl font-bold text-slate-900 mb-4 leading-tight">Secure your infrastructure with confidence.</h2>
          <p className="text-base text-slate-600 mb-8 leading-relaxed">Join elite engineering teams deploying LarShield to monitor complex threat vectors in real-time. Fast, reliable, and exceptionally accurate.</p>
          
          <div className="flex items-center gap-4 p-4 rounded-xl bg-slate-50 border border-slate-100">
            <div className="flex -space-x-3">
              <div className="w-10 h-10 rounded-full border-2 border-white bg-blue-100 flex items-center justify-center text-xs font-semibold text-blue-700">CISO</div>
              <div className="w-10 h-10 rounded-full border-2 border-white bg-indigo-100 flex items-center justify-center text-xs font-semibold text-indigo-700">SEC</div>
              <div className="w-10 h-10 rounded-full border-2 border-white bg-slate-200 flex items-center justify-center text-xs font-semibold text-slate-700">+1K</div>
            </div>
            <div className="text-sm">
              <p className="text-slate-900 font-semibold">Trusted by 2,000+ Enterprises</p>
              <p className="text-slate-500 text-xs mt-0.5">Global security leaders</p>
            </div>
          </div>
        </div>
      </div>

      {/* Right Side: Registration Form Canvas */}
      <div className="w-full lg:w-7/12 flex flex-col relative text-left bg-slate-50 overflow-y-auto">
        
        {/* Contextual Navigation */}
        <div className="absolute top-6 right-6 lg:top-8 lg:right-12 flex items-center gap-2 text-sm text-slate-500 animate-fade-in z-20">
          <span>Already have an account?</span>
          <Link className="text-blue-600 hover:text-blue-700 transition-colors font-semibold flex items-center gap-1 group" to="/login">
            Sign in
            <span className="material-symbols-outlined text-[16px] group-hover:translate-x-1 transition-transform">arrow_forward</span>
          </Link>
        </div>

        {/* Form Container */}
        <div className="flex-grow flex items-center justify-center p-6 sm:p-12 lg:px-24 w-full pt-24 lg:pt-12 relative">
          
          <div className="w-full max-w-[500px] relative z-10 animate-slide-up">
            
            {/* Shield Logo Graphic above Create an Account */}
            <div className="flex justify-center mb-6">
              <img 
                src="/shield-graphic.png" 
                alt="LarShield Graphic Logo" 
                className="w-44 sm:w-52 h-auto object-contain drop-shadow-xl hover:scale-105 transition-transform duration-300"
              />
            </div>

            {/* Mobile Brand Anchor */}
            <div className="lg:hidden flex items-center justify-center gap-3 mb-6">
              <span className="text-xl font-bold tracking-tight brand-gradient">LarShield Security</span>
            </div>

            {/* Header */}
            <div className="mb-8 text-center sm:text-left">
              <h1 className="text-3xl sm:text-4xl font-bold text-slate-900 tracking-tight mb-2">Create an Account</h1>
              <p className="text-base text-slate-500">Get started by creating your administrative profile.</p>
            </div>

            {/* Error Alert Box */}
            {error && (
              <div className="flex gap-3 bg-red-50 border border-red-200 rounded-xl p-4 text-red-700 text-sm mb-6 items-center animate-fade-in">
                <span className="material-symbols-outlined text-red-500">warning</span>
                <div>{error}</div>
              </div>
            )}

            {/* Registration Form */}
            <form className="flex flex-col gap-6" onSubmit={handleSubmit}>
              
              {/* Row 1: Identity */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
                <div className="flex flex-col gap-2">
                  <label className="text-xs font-semibold text-slate-500 uppercase tracking-widest" htmlFor="fullName">Full Name</label>
                  <input 
                    className="h-12 px-4 bg-white border border-slate-200 rounded-xl text-slate-900 text-sm focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all placeholder:text-slate-400" 
                    id="fullName" 
                    placeholder="e.g. Jane Doe" 
                    required 
                    type="text"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                  />
                </div>
                <div className="flex flex-col gap-2">
                  <label className="text-xs font-semibold text-slate-500 uppercase tracking-widest" htmlFor="companyName">Organization</label>
                  <input 
                    className="h-12 px-4 bg-white border border-slate-200 rounded-xl text-slate-900 text-sm focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all placeholder:text-slate-400" 
                    id="companyName" 
                    placeholder="Acme Corp" 
                    required 
                    type="text"
                    value={companyName}
                    onChange={(e) => setCompanyName(e.target.value)}
                  />
                </div>
              </div>

              {/* Row 2: Email */}
              <div className="flex flex-col gap-2">
                <label className="text-xs font-semibold text-slate-500 uppercase tracking-widest" htmlFor="email">Work Email</label>
                <div className="relative group">
                  <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none transition-colors group-focus-within:text-blue-600 text-slate-400">
                    <span className="material-symbols-outlined text-[20px]">mail</span>
                  </div>
                  <input 
                    className="w-full bg-white border border-slate-200 rounded-xl pl-12 pr-4 py-3.5 text-sm text-slate-900 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all placeholder:text-slate-400" 
                    id="email" 
                    placeholder="admin@organization.com" 
                    required 
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                  />
                </div>
              </div>

              {/* Row 3: Passwords */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
                <div className="flex flex-col gap-2">
                  <label className="text-xs font-semibold text-slate-500 uppercase tracking-widest" htmlFor="password">Password</label>
                  <div className="relative group">
                    <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none transition-colors group-focus-within:text-blue-600 text-slate-400">
                      <span className="material-symbols-outlined text-[20px]">lock</span>
                    </div>
                    <input 
                      className="w-full bg-white border border-slate-200 rounded-xl pl-12 pr-12 py-3.5 text-sm text-slate-900 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all placeholder:text-slate-400" 
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
                </div>
                <div className="flex flex-col gap-2">
                  <label className="text-xs font-semibold text-slate-500 uppercase tracking-widest" htmlFor="confirmPassword">Confirm Password</label>
                  <div className="relative group">
                    <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none transition-colors group-focus-within:text-blue-600 text-slate-400">
                      <span className="material-symbols-outlined text-[20px]">verified_user</span>
                    </div>
                    <input 
                      className="w-full bg-white border border-slate-200 rounded-xl pl-12 pr-12 py-3.5 text-sm text-slate-900 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all placeholder:text-slate-400" 
                      id="confirmPassword" 
                      placeholder="••••••••" 
                      required 
                      type={showConfirmPassword ? "text" : "password"}
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                    />
                    <button
                      type="button"
                      className="absolute inset-y-0 right-0 pr-4 flex items-center text-slate-400 hover:text-blue-600 transition-colors"
                      onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                      tabIndex="-1"
                    >
                      <span className="material-symbols-outlined text-[20px]">
                        {showConfirmPassword ? 'visibility_off' : 'visibility'}
                      </span>
                    </button>
                  </div>
                </div>
              </div>

              {/* Password Validation Checklist - Only shown when typing password */}
              {password.length > 0 && (
                <div className="flex flex-col gap-1.5 p-3 bg-white border border-slate-200 rounded-xl text-xs animate-fade-in">
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

              {/* Agreement */}
              <div className="flex items-start gap-3 mt-2">
                <div className="relative flex items-center pt-0.5">
                  <input 
                    className="peer w-5 h-5 appearance-none rounded-md border border-slate-300 bg-white checked:bg-blue-600 checked:border-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-500/30 transition-all cursor-pointer" 
                    id="terms" 
                    type="checkbox"
                    checked={agreeTerms}
                    onChange={(e) => setAgreeTerms(e.target.checked)}
                  />
                  <span className="material-symbols-outlined absolute text-white text-[16px] pointer-events-none opacity-0 peer-checked:opacity-100 left-[2px] top-[4px]">check</span>
                </div>
                <label className="text-sm text-slate-600 cursor-pointer select-none hover:text-slate-900 transition-colors leading-relaxed" htmlFor="terms">
                  I agree to the <button type="button" onClick={() => setLegalModal('terms')} className="text-blue-600 hover:underline font-medium bg-transparent border-0 cursor-pointer p-0">Terms of Service</button> and <button type="button" onClick={() => setLegalModal('privacy')} className="text-blue-600 hover:underline font-medium bg-transparent border-0 cursor-pointer p-0">Privacy Policy</button>.
                </label>
              </div>

              {/* Submit Button */}
              <button 
                className="w-full bg-blue-600 text-white font-semibold rounded-xl py-4 mt-2 hover:bg-blue-700 hover:shadow-lg hover:shadow-blue-600/20 active:scale-[0.98] transition-all flex justify-center items-center gap-2 border-0 cursor-pointer relative overflow-hidden group" 
                type="submit"
                disabled={loading}
              >
                <span className="relative z-10">{loading ? 'Creating Account...' : 'Create Account'}</span>
                <span className="material-symbols-outlined text-[20px] relative z-10">rocket_launch</span>
              </button>
            </form>
          </div>
        </div>
      </div>

      {/* Legal Policies Modal */}
      {legalModal && (
        <div className="fixed inset-0 z-[9999] flex items-center justify-center p-4">
          <div 
            className="fixed inset-0 bg-black/60 backdrop-blur-sm transition-opacity"
            onClick={() => setLegalModal(null)}
          />
          
          <div className="bg-white border border-slate-200 shadow-2xl rounded-2xl w-full max-w-2xl relative z-10 animate-fade-in flex flex-col max-h-[90vh] overflow-hidden text-slate-900">
            
            {/* Header */}
            <div className="flex justify-between items-center px-6 py-4 border-b border-slate-100 bg-white">
              <div className="flex items-center gap-2.5">
                <span className="material-symbols-outlined text-blue-600 text-[22px]">gavel</span>
                <h3 className="font-bold text-slate-900 text-base tracking-tight">Legal Policies</h3>
              </div>
              <button 
                type="button"
                onClick={() => setLegalModal(null)}
                className="text-slate-400 hover:text-slate-700 hover:bg-slate-100 p-1.5 rounded-full transition-colors border-0 bg-transparent cursor-pointer flex items-center justify-center"
                title="Close"
              >
                <span className="material-symbols-outlined text-[18px]">close</span>
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-8 overflow-y-auto max-h-[65vh] text-left text-sm leading-relaxed text-slate-600 space-y-6">
              {legalModal === 'terms' && (
                <div>
                  <h2 className="text-2xl font-bold text-slate-900 mb-1">Terms of Service</h2>
                  <p className="text-xs font-semibold text-slate-500 mb-5">Effective Date: August 15, 2026</p>

                  <div className="space-y-6">
                    <div>
                      <h3 className="font-bold text-slate-900 text-base mb-2">1. Acceptance of Terms</h3>
                      <p className="text-sm text-slate-600 leading-relaxed">By accessing or using the Larshield platform (the "Service"), you agree to be bound by these Terms of Service. If you do not agree, you may not access the Service.</p>
                    </div>

                    <div>
                      <h3 className="font-bold text-slate-900 text-base mb-2">2. Description of Service</h3>
                      <p className="text-sm text-slate-600 leading-relaxed">Larshield provides automated vulnerability scanning, active penetration testing, and security posture management tools. The Service actively probes designated targets to identify security flaws, misconfigurations, and compliance violations.</p>
                    </div>

                    <div>
                      <h3 className="font-bold text-slate-900 text-base mb-2">3. Authorization and Legal Use</h3>
                      <p className="text-sm text-slate-600 leading-relaxed">You explicitly certify that you possess full, legally verifiable authorization from the system owner to conduct active security assessments against any target URL you submit. Unauthorized scanning is illegal and strictly prohibited. You assume all liability for damages resulting from unauthorized use of the Service.</p>
                    </div>

                    <div>
                      <h3 className="font-bold text-slate-900 text-base mb-2">4. Limitation of Liability</h3>
                      <p className="text-sm text-slate-600 leading-relaxed">Larshield is provided "AS IS". Vulnerability scanning can cause unintended disruptions, including data loss or system crashes. To the maximum extent permitted by law, Larshield shall not be liable for any direct, indirect, incidental, special, or consequential damages resulting from the use or inability to use the Service.</p>
                    </div>

                    <div>
                      <h3 className="font-bold text-slate-900 text-base mb-2">5. Termination</h3>
                      <p className="text-sm text-slate-600 leading-relaxed">We reserve the right to suspend or terminate your account immediately, without prior notice or liability, for any reason, including without limitation if you breach the Terms, particularly regarding unauthorized target scanning.</p>
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
