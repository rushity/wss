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

        <div className="mt-2 pt-6 text-center border-t border-slate-100 relative z-10">
          <p className="text-sm text-slate-500">
            Don't have an account? <br/>
            <Link className="text-blue-600 hover:text-blue-700 hover:underline mt-2 inline-block font-semibold transition-colors" to="/register">Create an account</Link>
          </p>
        </div>
      </main>
    </div>
  );
};
