import { Suspense } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './components/AuthContext';
import { ProtectedRoute } from './components/ProtectedRoute';
import { Layout } from './components/Layout';
import { ErrorBoundary } from './components/ErrorBoundary';
import { Toaster } from 'react-hot-toast';

import { LandingPage } from './pages/LandingPage';
import { Login } from './pages/Login';
import { Register } from './pages/Register';
import { Dashboard } from './pages/Dashboard';
import { NewScan } from './pages/NewScan';
import { ScanResults } from './pages/ScanResults';
import { AlertSettingsPage } from './pages/Settings';
import { ReportsHistory } from './pages/ReportsHistory';
import Pricing from './pages/Pricing';
import { SuperAdminLogin } from './pages/SuperAdminLogin';
import SuperAdminPanel from './pages/SuperAdminPanel';
import SupportEngineerPanel from './pages/SupportEngineerPanel';
import { OrganizationPage } from './pages/OrganizationPage';
import LogsAndThreats from './pages/LogsAndThreats';
import Profile from './pages/Profile';
import { Help } from './pages/Help';
import { LegalPage } from './pages/LegalPage';

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
                <Route path="/dashboard/new-scan" element={<Navigate to="/scans/new" replace />} />
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
