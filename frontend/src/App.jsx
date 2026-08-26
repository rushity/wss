import React, { Suspense } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './components/AuthContext';
import { ProtectedRoute } from './components/ProtectedRoute';
import { Layout } from './components/Layout';
import { ErrorBoundary } from './components/ErrorBoundary';
import { Toaster } from 'react-hot-toast';

const LandingPage = React.lazy(() => import('./pages/LandingPage').then(module => ({ default: module.LandingPage })));
const Login = React.lazy(() => import('./pages/Login').then(module => ({ default: module.Login })));
const Register = React.lazy(() => import('./pages/Register').then(module => ({ default: module.Register })));
const Dashboard = React.lazy(() => import('./pages/Dashboard').then(module => ({ default: module.Dashboard })));
const NewScan = React.lazy(() => import('./pages/NewScan').then(module => ({ default: module.NewScan })));
const ScanResults = React.lazy(() => import('./pages/ScanResults').then(module => ({ default: module.ScanResults })));
const AlertSettingsPage = React.lazy(() => import('./pages/Settings').then(module => ({ default: module.AlertSettingsPage })));
const ReportsHistory = React.lazy(() => import('./pages/ReportsHistory').then(module => ({ default: module.ReportsHistory })));
const AdminPage = React.lazy(() => import('./pages/AdminPage').then(module => ({ default: module.AdminPage })));
const Pricing = React.lazy(() => import('./pages/Pricing'));
const SuperAdminLogin = React.lazy(() => import('./pages/SuperAdminLogin').then(module => ({ default: module.SuperAdminLogin })));
const SuperAdminPanel = React.lazy(() => import('./pages/SuperAdminPanel'));
const SupportEngineerPanel = React.lazy(() => import('./pages/SupportEngineerPanel'));

const OrganizationPage = React.lazy(() => import('./pages/OrganizationPage').then(module => ({ default: module.OrganizationPage })));
const LogsAndThreats = React.lazy(() => import('./pages/LogsAndThreats'));
const Profile = React.lazy(() => import('./pages/Profile'));
const Help = React.lazy(() => import('./pages/Help').then(module => ({ default: module.Help })));
const LegalPage = React.lazy(() => import('./pages/LegalPage').then(module => ({ default: module.LegalPage })));

function App() {
  return (
    <Router>
      <ErrorBoundary>
        <AuthProvider>
          <Toaster position="top-center" toastOptions={{
            style: {
              background: 'var(--surface-container-lowest)',
              color: 'var(--on-surface)',
              border: '1px solid var(--outline-variant)',
            },
            success: { iconTheme: { primary: '#10b981', secondary: 'white' } },
            error: { iconTheme: { primary: '#ef4444', secondary: 'white' } }
          }} />
          <Suspense fallback={<div className="flex h-screen items-center justify-center bg-surface"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div></div>}>
            <Routes>
              <Route path="/" element={<LandingPage />} />
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />
              <Route path="/pricing" element={<Layout><Pricing /></Layout>} />
              <Route path="/legal" element={<Navigate to="/legal/terms" replace />} />
              <Route path="/legal/:policyId" element={<Layout><LegalPage /></Layout>} />

              <Route element={<ProtectedRoute />}>
                <Route path="/dashboard" element={<Layout><Dashboard /></Layout>} />
                <Route path="/profile" element={<Layout><Profile /></Layout>} />
                <Route path="/scans/new" element={<Layout><NewScan /></Layout>} />
                <Route path="/scans/history" element={<Layout><ReportsHistory /></Layout>} />
                <Route path="/scans/results" element={<Layout><ScanResults /></Layout>} />
                <Route path="/settings" element={<Layout><AlertSettingsPage /></Layout>} />
                <Route path="/help" element={<Layout><Help /></Layout>} />
                <Route path="/admin" element={<ProtectedRoute requiredRole={['admin', 'super_admin']}><Layout><SuperAdminPanel /></Layout></ProtectedRoute>} />
                <Route path="/super-admin" element={<ProtectedRoute requiredRole="super_admin"><Layout><SuperAdminPanel /></Layout></ProtectedRoute>} />
                <Route path="/support" element={<ProtectedRoute requiredRole={['support_engineer', 'admin', 'super_admin']}><Layout><SupportEngineerPanel /></Layout></ProtectedRoute>} />
                <Route path="/support-engineer" element={<Navigate to="/support" replace />} />
                <Route path="/organization" element={<Layout><OrganizationPage /></Layout>} />
                <Route path="/super-admin/logs" element={<ProtectedRoute requiredRole={['super_admin', 'admin', 'support_engineer']}><Layout><LogsAndThreats /></Layout></ProtectedRoute>} />
              </Route>

              <Route path="/larshield-superadmin" element={<SuperAdminLogin />} />

              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </Suspense>
        </AuthProvider>
      </ErrorBoundary>
    </Router>
  );
}

export default App;
