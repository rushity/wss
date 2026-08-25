import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from '../components/AuthContext';
import { getInitials } from '../components/Layout';
import { toast } from 'react-hot-toast';

export const Profile = () => {
  const { token, logout } = useAuth();
  const fileInputRef = useRef(null);
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

  useEffect(() => {
    const preventWindowDrop = (e) => {
      e.preventDefault();
    };
    window.addEventListener('dragover', preventWindowDrop);
    window.addEventListener('drop', preventWindowDrop);
    return () => {
      window.removeEventListener('dragover', preventWindowDrop);
      window.removeEventListener('drop', preventWindowDrop);
    };
  }, []);

  const [isDragging, setIsDragging] = useState(false);
  const [uploadingLogo, setUploadingLogo] = useState(false);

  const handleUploadLogoUrl = async (imageUrl) => {
    setUploadingLogo(true);
    try {
      const res = await fetch('/api/auth/organizations/logo', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ logo_url: imageUrl })
      });
      if (res.ok) {
        toast.success("Report branding updated! Future PDF reports will include your logo.");
        fetchBrandingManual();
      } else {
        const data = await res.json();
        toast.error(data.message || "Failed to download and process web image.");
      }
    } catch (err) {
      toast.error("Error uploading logo URL.");
    } finally {
      setUploadingLogo(false);
    }
  };

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
      const data = await res.json();
      if (res.ok) {
        if (data.report_logo_url) {
          setReportLogoUrl(data.report_logo_url);
        }
        toast.success("Report branding updated! Future PDF reports will include your logo.");
        fetchBrandingManual();
      } else {
        toast.error(data.message || "Failed to update report branding.");
      }
    } catch (err) {
      toast.error("Error uploading logo.");
    } finally {
      setUploadingLogo(false);
    }
  };

  const handleRemoveLogo = async () => {
    try {
      const res = await fetch('/api/auth/organizations/logo', {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        setReportLogoUrl('');
        toast.success("Logo removed successfully.");
        fetchBrandingManual();
      } else {
        toast.error("Failed to remove logo.");
      }
    } catch (err) {
      toast.error("Error removing logo.");
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.dataTransfer) {
      e.dataTransfer.dropEffect = 'copy';
    }
    if (!isDragging) setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    // Only set false if leaving the main drop container
    if (e.currentTarget && e.relatedTarget && e.currentTarget.contains(e.relatedTarget)) {
      return;
    }
    setIsDragging(false);
  };

  const handleDrop = async (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    // 1. Direct File Drop (from File Explorer or Desktop)
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      if (file && (file.type.startsWith('image/') || file.type === '' || file.name.match(/\.(png|jpe?g|webp|svg|gif|bmp)$/i))) {
        await handleUploadLogoFile(file);
        return;
      }
    }

    // 2. DataTransfer Items (Dragging image element or file item from browser window)
    if (e.dataTransfer.items && e.dataTransfer.items.length > 0) {
      for (let i = 0; i < e.dataTransfer.items.length; i++) {
        const item = e.dataTransfer.items[i];
        if (item.kind === 'file') {
          const file = item.getAsFile();
          if (file && (file.type.startsWith('image/') || file.name.match(/\.(png|jpe?g|webp|svg|gif|bmp)$/i))) {
            await handleUploadLogoFile(file);
            return;
          }
        }
      }
    }

    // 3. Chrome / Web Image / HTML / URL Drag
    const htmlData = e.dataTransfer.getData('text/html');
    const uriData = e.dataTransfer.getData('text/uri-list') || e.dataTransfer.getData('URL') || e.dataTransfer.getData('text/plain');

    let imageUrl = '';
    if (htmlData) {
      try {
        const parser = new DOMParser();
        const doc = parser.parseFromString(htmlData, 'text/html');
        const img = doc.querySelector('img');
        if (img && img.src) {
          imageUrl = img.src;
        }
      } catch (err) {
        console.warn("Could not parse dragged HTML", err);
      }
    }

    if (!imageUrl && uriData && uriData.trim().match(/^https?:\/\/.+/i)) {
      imageUrl = uriData.trim();
    }

    if (imageUrl) {
      // Base64 Data URL handling
      if (imageUrl.startsWith('data:image/')) {
        try {
          const arr = imageUrl.split(',');
          const mime = arr[0].match(/:(.*?);/)[1];
          const bstr = atob(arr[1]);
          let n = bstr.length;
          const u8arr = new Uint8Array(n);
          while (n--) {
            u8arr[n] = bstr.charCodeAt(n);
          }
          const file = new File([u8arr], 'dragged_logo.png', { type: mime });
          await handleUploadLogoFile(file);
        } catch (err) {
          toast.error("Invalid base64 image data.");
        }
        return;
      }

      // Web HTTP/HTTPS URL handling - First try frontend fetch, fallback to backend fetch
      setUploadingLogo(true);
      try {
        const res = await fetch(imageUrl, { mode: 'cors' });
        if (!res.ok) throw new Error("CORS or HTTP error");
        const blob = await res.blob();
        const contentType = blob.type || 'image/png';
        const fileExt = contentType.split('/')[1] || 'png';
        const file = new File([blob], `dragged_logo.${fileExt}`, { type: contentType });
        await handleUploadLogoFile(file);
      } catch (frontendErr) {
        // Fallback: send web image URL to backend to download server-side (bypasses CORS!)
        await handleUploadLogoUrl(imageUrl);
      } finally {
        setUploadingLogo(false);
      }
      return;
    }

    toast.error("Please drop a valid image file (PNG, JPG, WebP, SVG).");
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
            <div className="w-20 h-20 rounded-full bg-primary-container/50 border-2 border-primary/20 flex items-center justify-center mb-4 shadow-sm">
              <span className="text-primary text-3xl font-bold uppercase tracking-wider">
                {getInitials(profile)}
              </span>
            </div>
            <h2 className="font-bold text-on-surface m-0 text-xl">
              {profile.first_name || profile.last_name ? `${profile.first_name || ''} ${profile.last_name || ''}`.trim() : (profile.name || profile.email.split('@')[0])}
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
        <div className="w-full bg-white border border-[#e5e7eb] rounded-xl shadow-xs p-6 md:p-8 mt-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4">
            <div>
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined text-[#2563eb] text-[22px]">palette</span>
                <h3 className="font-bold text-[#111827] text-[18px] m-0">
                  Report Branding
                </h3>
              </div>
              <p className="text-[#4b5563] text-sm mt-1 m-0">
                Customize generated PDF security reports with your organization's logo.
              </p>
            </div>

            {reportLogoUrl && (
              <button
                type="button"
                onClick={handleRemoveLogo}
                className="shrink-0 border border-[#fecaca] hover:bg-[#fef2f2] hover:border-[#fca5a5] text-[#dc2626] font-medium text-xs px-3.5 py-2 rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer border-solid self-start sm:self-auto"
              >
                <span className="material-symbols-outlined text-[16px]">delete</span>
                <span>Remove Logo</span>
              </button>
            )}
          </div>

          <div className="border-t border-[#e5e7eb] pt-6">
            <div
              onDragOver={handleDragOver}
              onDragEnter={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`relative border-2 border-dashed rounded-xl py-10 px-6 flex flex-col items-center justify-center text-center transition-all duration-200 cursor-pointer ${
                isDragging
                  ? 'border-[#2563eb] bg-[#eff6ff] scale-[1.005]'
                  : 'border-[#d1d5db] bg-[#f9fafb] hover:border-[#9ca3af] hover:bg-[#f3f4f6]'
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept="image/*"
                onChange={(e) => {
                  if (e.target.files && e.target.files[0]) {
                    handleUploadLogoFile(e.target.files[0]);
                  }
                }}
                className="hidden"
              />

              {reportLogoUrl && (
                <div className="mb-6 p-4 bg-white rounded-xl border border-[#e5e7eb] shadow-xs flex items-center justify-center max-w-sm w-full pointer-events-auto">
                  <img src={reportLogoUrl} alt="Organization Logo" className="max-h-24 max-w-full object-contain" />
                </div>
              )}

              <button
                type="button"
                disabled={uploadingLogo}
                onClick={(e) => {
                  e.stopPropagation();
                  fileInputRef.current?.click();
                }}
                className="relative z-20 bg-[#2563eb] hover:bg-[#1d4ed8] text-white font-semibold px-6 py-2.5 rounded-lg flex items-center gap-2 text-sm shadow-xs transition-colors cursor-pointer mb-4 disabled:opacity-50"
              >
                <span className={`material-symbols-outlined text-[18px] ${uploadingLogo ? 'animate-spin' : ''}`}>
                  {uploadingLogo ? 'sync' : 'upload_file'}
                </span>
                <span>{uploadingLogo ? 'Uploading...' : 'Upload Here (Change Logo)'}</span>
              </button>

              <p className="text-[#6b7280] text-sm m-0 font-normal pointer-events-none">
                Or drag and drop a new logo file above (PNG, JPG, WebP, SVG up to 5MB)
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

