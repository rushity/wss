import React, { useState, useEffect } from 'react';
import { useAuth } from '../components/AuthContext';
import { toast } from 'react-hot-toast';

export const Profile = () => {
  const { token, logout } = useAuth();
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [reportLogoUrl, setReportLogoUrl] = useState('');

  useEffect(() => {
    const fetchProfile = async () => {
      try {
        const res = await fetch('/api/auth/profile', {
          headers: { 'Authorization': `Bearer ${token}` }
        });

        if (res.ok) {
          const data = await res.json();
          setProfile(data.user);
        } else {
          setError("Failed to fetch profile data. Please try again.");
        }
      } catch (err) {
        setError("Network error while fetching profile data.");
        console.error(err);
      } finally {
        setLoading(false);
      }
    };

    const fetchBranding = async () => {
      try {
        const res = await fetch('/api/auth/organizations/webhook', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (res.ok) {
          const data = await res.json();
          setReportLogoUrl(data.report_logo_url || '');
        }
      } catch (err) {
        console.error("Error loading branding info", err);
      }
    };

    fetchProfile();
    fetchBranding();
  }, [token]);

  const fetchBrandingManual = async () => {
    try {
      const res = await fetch('/api/auth/organizations/webhook', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setReportLogoUrl(data.report_logo_url || '');
      }
    } catch (err) {
      console.error("Error loading branding info", err);
    }
  };

  const [isDragging, setIsDragging] = useState(false);
  const [uploadingLogo, setUploadingLogo] = useState(false);

  const handleUploadLogoFile = async (file) => {
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) {
      toast.error("File size exceeds 5MB limit.");
      return;
    }
    setUploadingLogo(true);
    const formData = new FormData();
    formData.append('logo', file);
    try {
      const res = await fetch('/api/auth/organizations/logo', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` },
        body: formData
      });
      if (res.ok) {
        toast.success("Report branding updated! Future PDF reports will include your logo.");
        fetchBrandingManual();
      } else {
        const data = await res.json();
        toast.error(data.message || "Failed to update report branding.");
      }
    } catch (err) {
      toast.error("Error uploading logo.");
    } finally {
      setUploadingLogo(false);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      if (!file.type.startsWith('image/')) {
        toast.error("Please upload an image file (PNG, JPG, WebP, SVG)");
        return;
      }
      handleUploadLogoFile(file);
    }
  };

  const [passwordData, setPasswordData] = useState({ currentPassword: '', newPassword: '', confirmPassword: '' });
  const [passwordStatus, setPasswordStatus] = useState({ loading: false, error: null, success: false });
  const [showPassword, setShowPassword] = useState({ current: false, new: false, confirm: false });

  const [showEditModal, setShowEditModal] = useState(false);
  const [editData, setEditData] = useState({ first_name: '', last_name: '', email: '', contact_no: '', org_name: '' });
  const [editStatus, setEditStatus] = useState({ loading: false, error: null });

  const handleEditOpen = () => {
    setEditData({
      first_name: profile.first_name || '',
      last_name: profile.last_name || '',
      email: profile.email || '',
      contact_no: profile.contact_no || '',
      org_name: profile.org_name || 'LarShield Organization'
    });
    setShowEditModal(true);
  };

  const handleEditSubmit = async (e) => {
    e.preventDefault();
    setEditStatus({ loading: true, error: null });
    try {
      // Update User Profile
      const userRes = await fetch(`/api/auth/users/${profile.id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          ...profile,
          first_name: editData.first_name,
          last_name: editData.last_name,
          email: editData.email,
          contact_no: editData.contact_no
        })
      });
      const userData = await userRes.json();

      if (!userRes.ok) {
        setEditStatus({ loading: false, error: userData.message || "Failed to update profile" });
        toast.error(userData.message || "Failed to update profile");
        return;
      }

      // Update Organization Name if changed and user has permission
      if (editData.org_name !== profile.org_name && (profile.role === 'org_admin' || profile.role === 'super_admin')) {
        const orgRes = await fetch(`/api/auth/organizations/${profile.org_id}`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          },
          body: JSON.stringify({ name: editData.org_name })
        });

        if (!orgRes.ok) {
          const orgData = await orgRes.json();
          toast.error(orgData.message || "Failed to update organization name");
        }
      }

      toast.success("Profile updated successfully!");
      setProfile({
        ...profile,
        first_name: editData.first_name,
        last_name: editData.last_name,
        email: editData.email,
        contact_no: editData.contact_no,
        org_name: editData.org_name
      });
      setShowEditModal(false);
      setEditStatus({ loading: false, error: null });

    } catch (err) {
      setEditStatus({ loading: false, error: "Network error" });
      toast.error("Network error");
    }
  };

  const handlePasswordChange = async (e) => {
    e.preventDefault();
    setPasswordStatus({ loading: true, error: null, success: false });

    if (passwordData.newPassword !== passwordData.confirmPassword) {
      setPasswordStatus({ loading: false, error: "New passwords do not match", success: false });
      return;
    }

    if (passwordData.newPassword.length < 6) {
      setPasswordStatus({ loading: false, error: "New password must be at least 6 characters", success: false });
      return;
    }

    try {
      const res = await fetch('/api/auth/password', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          currentPassword: passwordData.currentPassword,
          newPassword: passwordData.newPassword
        })
      });

      let data = {};
      try {
        data = await res.json();
      } catch (e) {
        if (res.status === 429) {
          data = { message: "Too many attempts. Please try again later." };
        } else {
          data = { message: "Unexpected server error occurred." };
        }
      }

      if (res.ok) {
        setPasswordStatus({ loading: false, error: null, success: true });
        setPasswordData({ currentPassword: '', newPassword: '', confirmPassword: '' });
        toast.success("Password updated successfully!");
        setTimeout(() => setPasswordStatus(prev => ({ ...prev, success: false })), 3000);
      } else {
        const errorMsg = data.message || "Failed to update password";
        setPasswordStatus({ loading: false, error: errorMsg, success: false });
        toast.error(errorMsg);
      }
    } catch (err) {
      setPasswordStatus({ loading: false, error: "Network error occurred", success: false });
      toast.error("Network error occurred");
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-2xl font-label-md text-label-md text-on-surface-variant">
        <span className="material-symbols-outlined animate-spin mr-sm">sync</span>
        Loading Profile Data...
      </div>
    );
  }

  if (error || !profile) {
    return (
      <div className="text-center py-2xl bg-surface-container-lowest border border-outline-variant rounded-xl max-w-lg mx-auto p-xl flex flex-col items-center gap-md">
        <span className="material-symbols-outlined text-[48px] text-error">error</span>
        <h2 className="font-headline-md text-on-surface">Unable to load profile</h2>
        <p className="font-body-md text-on-surface-variant">{error || "Profile data not found."}</p>
      </div>
    );
  }



  return (
    <div className="flex flex-col gap-6 text-left w-full max-w-7xl mx-auto pb-8">
      {/* Main Grid Layout - 3 Equal Columns */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-stretch">

        {/* Card 1: Identity Card */}
        <div className="bg-surface-container-lowest border border-outline-variant rounded-lg shadow-sm p-6 flex flex-col h-full">
          <div className="flex items-center justify-between border-b border-outline-variant pb-4 mb-4">
            <h3 className="font-semibold text-on-surface m-0 flex items-center gap-2 text-lg">
              <span className="material-symbols-outlined text-primary">person</span>
              Organization Profile
            </h3>
            <button onClick={handleEditOpen} className="text-primary hover:text-on-primary-container bg-primary-container/20 hover:bg-primary-container px-3 py-1.5 rounded-lg text-xs font-semibold uppercase tracking-wider transition-colors flex items-center gap-1 cursor-pointer border-none">
              <span className="material-symbols-outlined text-[14px]">edit</span>
              Edit Profile
            </button>
          </div>

          <div className="flex flex-col items-center text-center mt-2 mb-6">
            <div className="w-20 h-20 rounded-full bg-primary-container/50 flex items-center justify-center mb-4">
              <span className="text-primary text-3xl font-bold uppercase">
                {profile.email ? profile.email.charAt(0) : '?'}
              </span>
            </div>
            <h2 className="font-bold text-on-surface m-0 text-xl">
              {profile.first_name || profile.last_name ? `${profile.first_name || ''} ${profile.last_name || ''}`.trim() : profile.email.split('@')[0]}
            </h2>
            <div className="mt-2 inline-flex items-center px-3 py-1 rounded-full bg-primary-container/30 text-primary font-semibold uppercase tracking-wider text-xs border border-primary/20">
              {(profile.role || 'user').replace(/_/g, ' ')}
            </div>
          </div>

          <div className="flex flex-col w-full mb-6">
            <div className="flex items-center justify-between py-3 border-b border-outline-variant">
              <div className="flex items-center gap-2 text-on-surface-variant">
                <span className="material-symbols-outlined text-[18px]">mail</span>
                <span className="font-medium text-sm">Email</span>
              </div>
              <span className="text-on-surface font-medium text-sm truncate max-w-[150px]" title={profile.email}>{profile.email}</span>
            </div>

            <div className="flex items-center justify-between py-3 border-b border-outline-variant">
              <div className="flex items-center gap-2 text-on-surface-variant">
                <span className="material-symbols-outlined text-[18px]">calendar_today</span>
                <span className="font-medium text-sm">Joined</span>
              </div>
              <span className="text-on-surface font-medium text-sm">
                {profile.created_at ? new Date(profile.created_at).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }).replace(/ /g, '-') : 'N/A'}
              </span>
            </div>
          </div>

          <div className="mt-auto">
            <button
              onClick={logout}
              className="w-full bg-transparent text-error border border-error/50 hover:bg-error/10 font-medium px-4 py-2.5 rounded-lg transition-colors flex items-center justify-center gap-2 text-sm cursor-pointer"
            >
              <span className="material-symbols-outlined text-[18px]">logout</span>
              Sign Out Securely
            </button>
          </div>
        </div>

        {/* Card 2: Security Configuration */}
        <div className="bg-surface-container-lowest border border-outline-variant rounded-lg shadow-sm p-6 flex flex-col h-full">
          <h3 className="font-semibold text-on-surface m-0 mb-4 flex items-center gap-2 border-b border-outline-variant pb-4 text-lg">
            <span className="material-symbols-outlined text-primary">security</span>
            Security Config
          </h3>

          <div className="flex flex-col flex-1">
            <div className="mb-5">
              <h4 className="font-semibold text-on-surface m-0 text-sm">Password Management</h4>
              <p className="text-on-surface-variant m-0 mt-1 text-xs">Update your account password securely.</p>
            </div>

            {(profile.role === 'soc_analyst' || profile.role === 'executive_user') ? (
              <div className="bg-error/10 rounded-lg p-4 flex flex-col items-center text-center gap-3 text-error border border-error/20 mt-auto mb-auto">
                <span className="material-symbols-outlined text-[24px]">lock</span>
                <p className="text-sm m-0 font-medium">
                  Your account type is not permitted to change its own password. Please contact your administrator.
                </p>
              </div>
            ) : (
              <form onSubmit={handlePasswordChange} className="flex flex-col gap-4 flex-1">
                {passwordStatus.error && (
                  <div className="bg-error/10 text-error px-md py-sm rounded-lg text-sm border border-error/20 flex items-center gap-2">
                    <span className="material-symbols-outlined text-[16px]">error</span>
                    {passwordStatus.error}
                  </div>
                )}
                {passwordStatus.success && (
                  <div className="bg-primary-container/20 text-primary px-md py-sm rounded-lg text-sm border border-primary/20 flex items-center gap-2">
                    <span className="material-symbols-outlined text-[16px]">check_circle</span>
                    Password updated successfully!
                  </div>
                )}

                <div className="flex flex-col">
                  <label className="block text-label-sm font-label-sm text-on-surface-variant mb-xs">Current Password</label>
                  <div className="relative">
                    <input
                      type={showPassword.current ? "text" : "password"}
                      required
                      value={passwordData.currentPassword}
                      onChange={(e) => setPasswordData({ ...passwordData, currentPassword: e.target.value })}
                      className="w-full bg-surface-container border border-outline-variant text-on-surface rounded-lg px-md py-sm focus:border-primary focus:ring-1 focus:ring-primary outline-none transition-colors pr-10"
                    />
                    <button type="button" onClick={() => setShowPassword({ ...showPassword, current: !showPassword.current })} className="absolute inset-y-0 right-0 pr-3 flex items-center text-on-surface-variant hover:text-on-surface bg-transparent border-none cursor-pointer">
                      <span className="material-symbols-outlined text-[18px]">{showPassword.current ? 'visibility_off' : 'visibility'}</span>
                    </button>
                  </div>
                </div>

                <div className="flex flex-col">
                  <label className="block text-label-sm font-label-sm text-on-surface-variant mb-xs">New Password</label>
                  <div className="relative">
                    <input
                      type={showPassword.new ? "text" : "password"}
                      required
                      minLength={6}
                      value={passwordData.newPassword}
                      onChange={(e) => setPasswordData({ ...passwordData, newPassword: e.target.value })}
                      className="w-full bg-surface-container border border-outline-variant text-on-surface rounded-lg px-md py-sm focus:border-primary focus:ring-1 focus:ring-primary outline-none transition-colors pr-10"
                    />
                    <button type="button" onClick={() => setShowPassword({ ...showPassword, new: !showPassword.new })} className="absolute inset-y-0 right-0 pr-3 flex items-center text-on-surface-variant hover:text-on-surface bg-transparent border-none cursor-pointer">
                      <span className="material-symbols-outlined text-[18px]">{showPassword.new ? 'visibility_off' : 'visibility'}</span>
                    </button>
                  </div>
                </div>

                <div className="flex flex-col">
                  <label className="block text-label-sm font-label-sm text-on-surface-variant mb-xs">Confirm New Password</label>
                  <div className="relative">
                    <input
                      type={showPassword.confirm ? "text" : "password"}
                      required
                      minLength={6}
                      value={passwordData.confirmPassword}
                      onChange={(e) => setPasswordData({ ...passwordData, confirmPassword: e.target.value })}
                      className="w-full bg-surface-container border border-outline-variant text-on-surface rounded-lg px-md py-sm focus:border-primary focus:ring-1 focus:ring-primary outline-none transition-colors pr-10"
                    />
                    <button type="button" onClick={() => setShowPassword({ ...showPassword, confirm: !showPassword.confirm })} className="absolute inset-y-0 right-0 pr-3 flex items-center text-on-surface-variant hover:text-on-surface bg-transparent border-none cursor-pointer">
                      <span className="material-symbols-outlined text-[18px]">{showPassword.confirm ? 'visibility_off' : 'visibility'}</span>
                    </button>
                  </div>
                </div>

                <div className="mt-auto pt-2">
                  <button
                    type="submit"
                    disabled={passwordStatus.loading}
                    className="w-full bg-primary hover:brightness-110 border-none cursor-pointer text-on-primary font-medium px-4 py-2.5 rounded-lg transition-colors flex items-center justify-center gap-2 disabled:opacity-50 text-sm"
                  >
                    {passwordStatus.loading ? (
                      <><span className="material-symbols-outlined animate-spin text-[18px]">sync</span> Updating...</>
                    ) : (
                      <><span className="material-symbols-outlined text-[18px]">key</span> Update Password</>
                    )}
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>

        {/* Card 3: Subscription Card */}
        <div className="bg-surface-container-lowest border border-outline-variant rounded-lg shadow-sm p-6 flex flex-col h-full">
          <h3 className="font-semibold text-on-surface m-0 mb-6 flex items-center gap-2 border-b border-outline-variant pb-4 text-lg">
            <span className="material-symbols-outlined text-primary">workspace_premium</span>
            Subscription Status
          </h3>

          <div className="flex flex-col w-full mb-6 flex-1">
            <div className="flex items-center justify-between py-4 border-b border-outline-variant">
              <div className="flex items-center gap-2 text-on-surface-variant">
                <span className="material-symbols-outlined text-[20px]">inventory_2</span>
                <span className="font-medium text-sm">Current Plan</span>
              </div>
              <span className="text-primary font-bold text-sm uppercase tracking-widest bg-primary-container/30 px-3 py-1 rounded-full border border-primary/20">
                {profile.role === 'super_admin' ? 'Enterprise' : profile.subscription_tier || 'Free'}
              </span>
            </div>

            <div className="flex items-center justify-between py-4 border-b border-outline-variant">
              <div className="flex items-center gap-2 text-on-surface-variant">
                <span className="material-symbols-outlined text-[20px]">speed</span>
                <span className="font-medium text-sm">Status</span>
              </div>
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${profile.role === 'super_admin' || profile.subscription_status === 'active' ? 'bg-green-500' : 'bg-yellow-500'}`}></div>
                <span className={`font-bold uppercase tracking-wide text-sm ${profile.role === 'super_admin' || profile.subscription_status === 'active' ? 'text-green-600' : 'text-yellow-600'}`}>
                  {profile.role === 'super_admin' ? 'Active' : profile.subscription_status || 'Inactive'}
                </span>
              </div>
            </div>
          </div>

          <div className="mt-auto">
            <div className="bg-surface-variant/30 border border-outline-variant/50 rounded-lg p-4 flex items-start gap-3">
              <span className="material-symbols-outlined text-primary text-[18px] shrink-0 mt-0.5">info</span>
              <p className="text-on-surface-variant m-0 text-xs leading-relaxed">
                Need higher API limits, custom proxy integrations, or VIP enterprise support? Contact your organization admin or LarShield sales to upgrade your tier.
              </p>
            </div>
          </div>
        </div>

      </div>

      {/* Second Row for Report Branding */}
      {(profile.role === 'super_admin' || profile.role === 'org_admin') && (
        <div className="w-full bg-surface-container-lowest border border-outline-variant/70 rounded-2xl shadow-2xs p-6 mt-6">
          <div className="flex items-center gap-2 mb-1">
            <span className="material-symbols-outlined text-[#2563eb] text-[24px]">palette</span>
            <h3 className="font-bold text-on-surface text-[18px] m-0">
              Report Branding
            </h3>
          </div>
          <p className="text-on-surface-variant text-sm mb-6 m-0">
            Customize generated PDF security reports with your organization's logo.
          </p>

          <div className="border-t border-outline-variant/40 pt-6">
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              className={`border-2 border-dashed rounded-xl p-10 flex flex-col items-center justify-center text-center transition-all duration-200 ${
                isDragging
                  ? 'border-[#2563eb] bg-[#2563eb]/10 scale-[1.01]'
                  : 'border-outline-variant/60 bg-surface-container-low/30 hover:border-[#2563eb]/60 hover:bg-surface-container-low/60'
              }`}
            >
              <span className={`material-symbols-outlined text-[44px] mb-3 transition-transform ${isDragging ? 'text-[#2563eb] scale-110' : 'text-[#2563eb]'} ${uploadingLogo ? 'animate-spin' : ''}`}>
                {uploadingLogo ? 'sync' : 'cloud_upload'}
              </span>
              
              <h4 className="font-bold text-on-surface text-[16px] mb-1">
                {isDragging ? 'Drop Image Here to Upload' : 'Upload Organization Logo'}
              </h4>
              <p className="text-on-surface-variant text-sm mb-5">
                {isDragging ? 'Release to upload your custom logo immediately' : 'Drag & drop your logo image here or click the button below to browse'}
              </p>

              {reportLogoUrl && (
                <div className="mb-4 p-2 bg-surface-container rounded-lg border border-outline-variant/40">
                  <img src={reportLogoUrl} alt="Organization Logo" className="max-h-20 max-w-full object-contain rounded" />
                </div>
              )}

              <button
                type="button"
                disabled={uploadingLogo}
                onClick={() => {
                  const fileInput = document.createElement('input');
                  fileInput.type = 'file';
                  fileInput.accept = 'image/*';
                  fileInput.onchange = (e) => {
                    if (e.target.files && e.target.files[0]) {
                      handleUploadLogoFile(e.target.files[0]);
                    }
                  };
                  fileInput.click();
                }}
                className="bg-[#2563eb] hover:bg-[#1d4ed8] text-white font-bold px-6 py-2.5 rounded-lg flex items-center gap-2 text-sm transition-all cursor-pointer shadow-2xs mb-4 disabled:opacity-50"
              >
                <span className={`material-symbols-outlined text-[18px] ${uploadingLogo ? 'animate-spin' : ''}`}>
                  {uploadingLogo ? 'sync' : 'upload'}
                </span>
                <span>{uploadingLogo ? 'Uploading...' : (reportLogoUrl ? 'Change Logo' : 'Upload Here')}</span>
              </button>

              <p className="text-on-surface-variant text-[12px] m-0 font-medium">
                Supported formats: PNG, JPG, WebP, SVG (Max 5MB) &bull; Drag & Drop Supported
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Edit Profile Modal */}
      {showEditModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 animate-fade-in">
          <div className="bg-surface-container-lowest border border-outline-variant rounded-lg overflow-hidden shadow-xl max-w-md w-full">
            <div className="p-6 border-b border-outline-variant bg-surface-container/50 flex justify-between items-center">
              <h3 className="text-xl font-bold flex items-center text-on-surface m-0">
                <span className="material-symbols-outlined text-primary mr-2">edit</span>
                Edit Profile
              </h3>
              <button
                onClick={() => setShowEditModal(false)}
                className="text-on-surface-variant hover:text-on-surface rounded-full p-1 transition-colors cursor-pointer border-0 bg-transparent flex items-center justify-center"
              >
                <span className="material-symbols-outlined text-[20px]">close</span>
              </button>
            </div>

            <form onSubmit={handleEditSubmit} className="p-6 flex flex-col gap-4">
              {editStatus.error && (
                <div className="bg-error/10 text-error px-md py-sm rounded-lg text-sm border border-error/20 flex items-center gap-2">
                  <span className="material-symbols-outlined text-[16px]">error</span>
                  {editStatus.error}
                </div>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="flex flex-col">
                  <label className="block text-label-sm font-label-sm text-on-surface-variant mb-xs">First Name</label>
                  <input
                    type="text"
                    value={editData.first_name}
                    onChange={(e) => setEditData({ ...editData, first_name: e.target.value })}
                    className="w-full bg-surface-container border border-outline-variant text-on-surface rounded-lg px-md py-sm focus:border-primary focus:ring-1 focus:ring-primary outline-none transition-colors"
                    placeholder="Enter first name"
                  />
                </div>

                <div className="flex flex-col">
                  <label className="block text-label-sm font-label-sm text-on-surface-variant mb-xs">Last Name</label>
                  <input
                    type="text"
                    value={editData.last_name}
                    onChange={(e) => setEditData({ ...editData, last_name: e.target.value })}
                    className="w-full bg-surface-container border border-outline-variant text-on-surface rounded-lg px-md py-sm focus:border-primary focus:ring-1 focus:ring-primary outline-none transition-colors"
                    placeholder="Enter last name"
                  />
                </div>
              </div>

              <div className="flex flex-col">
                <label className="block text-label-sm font-label-sm text-on-surface-variant mb-xs">Email Address</label>
                <input
                  type="email"
                  value={editData.email}
                  onChange={(e) => setEditData({ ...editData, email: e.target.value })}
                  className="w-full bg-surface-container border border-outline-variant text-on-surface rounded-lg px-md py-sm focus:border-primary focus:ring-1 focus:ring-primary outline-none transition-colors"
                  placeholder="Enter email address"
                  required
                />
              </div>

              <div className="flex flex-col">
                <label className="block text-label-sm font-label-sm text-on-surface-variant mb-xs">Contact No</label>
                <input
                  type="tel"
                  value={editData.contact_no}
                  onChange={(e) => setEditData({ ...editData, contact_no: e.target.value })}
                  className="w-full bg-surface-container border border-outline-variant text-on-surface rounded-lg px-md py-sm focus:border-primary focus:ring-1 focus:ring-primary outline-none transition-colors"
                  placeholder="+1 (555) 000-0000"
                />
              </div>

              <div className="flex flex-col">
                <div className="flex items-center justify-between mb-xs">
                  <label className="block text-label-sm font-label-sm text-on-surface-variant">Organization Name</label>
                  {profile.role !== 'org_admin' && profile.role !== 'super_admin' && (
                    <span className="text-[10px] bg-surface-variant text-on-surface-variant px-2 py-0.5 rounded uppercase tracking-wider font-bold">Admin Only</span>
                  )}
                </div>
                <input
                  type="text"
                  value={editData.org_name}
                  onChange={(e) => setEditData({ ...editData, org_name: e.target.value })}
                  disabled={profile.role !== 'org_admin' && profile.role !== 'super_admin'}
                  className={`w-full rounded-lg px-md py-sm outline-none transition-colors ${profile.role === 'org_admin' || profile.role === 'super_admin' ? 'bg-surface-container border border-outline-variant text-on-surface focus:border-primary focus:ring-1 focus:ring-primary' : 'bg-surface-variant/50 border border-outline-variant text-on-surface-variant cursor-not-allowed'}`}
                />
              </div>

              <div className="mt-2 flex gap-sm justify-end">
                <button
                  type="button"
                  onClick={() => setShowEditModal(false)}
                  className="px-xl py-sm bg-transparent border border-outline-variant rounded-lg font-label-md text-on-surface hover:bg-surface-variant transition-colors cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={editStatus.loading}
                  className="px-xl py-sm bg-primary text-on-primary rounded-lg font-label-md hover:brightness-110 transition-all border-none cursor-pointer flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  {editStatus.loading ? (
                    <><span className="material-symbols-outlined animate-spin text-[16px]">sync</span> Saving...</>
                  ) : (
                    "Save Changes"
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default Profile;

