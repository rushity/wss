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
            <img src="/logo.png" alt="LarShield Logo" className="w-full h-full object-contain" />
          </div>
          <span className="text-2xl font-bold tracking-tight brand-gradient">LarShield</span>
        </div>
        
        {/* Value Proposition */}
        <div className="z-10 max-w-md text-left animate-slide-up" style={{ animationDelay: '100ms' }}>
          <h2 className="text-4xl font-bold text-slate-900 mb-6 leading-tight">Secure your infrastructure with confidence.</h2>
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
            
            {/* Mobile Brand Anchor */}
            <div className="lg:hidden flex items-center gap-3 mb-10">
              <div className="w-10 h-10 flex items-center justify-center">
                <img src="/logo.png" alt="LarShield Logo" className="w-full h-full object-contain" />
              </div>
              <span className="text-xl font-bold tracking-tight brand-gradient">LarShield</span>
            </div>

            {/* Header */}
            <div className="mb-10">
              <h1 className="text-4xl font-bold text-slate-900 tracking-tight mb-3">Create an Account</h1>
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
                  I agree to the <a href="#" className="text-blue-600 hover:underline font-medium">Terms of Service</a> and <a href="#" className="text-blue-600 hover:underline font-medium">Privacy Policy</a>.
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
    </div>
  );
};
