import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../components/AuthContext';

export const SuperAdminLogin = () => {
  const [adminPassword, setAdminPassword] = useState('');
  const [adminError, setAdminError] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();
  const { login } = useAuth();

  const handleAdminAccess = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setAdminError('');
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'superadmin@gmail.com', password: adminPassword })
      });
      const data = await res.json();
      if (res.ok) {
        login(data.access_token || data.token, data.refresh_token, data.user);
        sessionStorage.setItem('superAdminAuth', 'true');
        navigate('/super-admin');
      } else {
        setAdminError(data.message || 'Incorrect password');
      }
    } catch {
      setAdminError('Could not connect to API');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="bg-surface text-on-surface font-body-md min-h-screen flex items-center justify-center selection:bg-primary/10 relative overflow-hidden">
      {/* Background aesthetics */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full max-w-container-max h-full -z-10 pointer-events-none opacity-50">
        <div className="absolute top-[-100px] left-[10%] w-[500px] h-[500px] bg-[radial-gradient(circle,rgba(0,74,198,0.07)_0%,transparent_70%)] rounded-full blur-3xl"></div>
        <div className="absolute bottom-[-100px] right-[10%] w-[500px] h-[500px] bg-[radial-gradient(circle,rgba(37,99,235,0.05)_0%,transparent_70%)] rounded-full blur-3xl"></div>
      </div>

      <div className="bg-surface-container-lowest p-2xl rounded-3xl w-full max-w-md border border-outline-variant shadow-2xl animate-fade-in mx-gutter relative">
        <div className="flex justify-center mb-xl">
          <div className="w-16 h-16 flex items-center justify-center">
            <img src="/logo.png" alt="LarShield Logo" className="w-full h-full object-contain" />
          </div>
        </div>

        <div className="text-center mb-xl">
          <h1 className="font-headline-lg text-on-surface font-extrabold mb-sm text-[28px] tracking-tight brand-gradient">Global Management</h1>
          <p className="text-on-surface-variant text-[14px] leading-relaxed">Enter the master password to access LarShield Global Management.</p>
        </div>

        <form onSubmit={handleAdminAccess} className="flex flex-col gap-lg">
          <div className="flex flex-col gap-xs">
            <div className="relative w-full">
              <input
                type={showPassword ? "text" : "password"}
                value={adminPassword}
                onChange={(e) => setAdminPassword(e.target.value)}
                placeholder="Master Password"
                autoFocus
                className="w-full border border-outline-variant rounded-xl py-md pl-lg pr-12 focus:ring-2 focus:ring-primary focus:border-primary bg-surface-container text-on-surface text-[15px] outline-none transition-all"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-on-surface-variant hover:text-primary transition-colors bg-transparent border-0 cursor-pointer flex items-center justify-center p-1"
                aria-label={showPassword ? "Hide password" : "Show password"}
              >
                <span className="material-symbols-outlined text-[20px]">
                  {showPassword ? 'visibility_off' : 'visibility'}
                </span>
              </button>
            </div>
            {adminError && <p className="text-error font-semibold text-[13px] mt-1 text-center">{adminError}</p>}
          </div>

          <button
            type="submit"
            disabled={isLoading || !adminPassword}
            className="w-full bg-primary text-white py-md rounded-xl font-bold hover:brightness-110 active:scale-[0.98] transition-all border-0 cursor-pointer text-[15px] shadow-lg shadow-primary/20 flex items-center justify-center disabled:opacity-70 disabled:cursor-not-allowed"
          >
            {isLoading ? (
              <span className="material-symbols-outlined animate-spin text-[20px]">sync</span>
            ) : (
              'Authenticate'
            )}
          </button>
        </form>

        <div className="mt-xl text-center">
          <button onClick={() => navigate('/')} className="text-on-surface-variant hover:text-primary transition-colors text-[13px] font-semibold bg-transparent border-0 cursor-pointer">
            ← Return to Public Site
          </button>
        </div>
      </div>
    </div>
  );
};
