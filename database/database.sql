-- ====================================================================
-- LarShield Master Production Database SQL Script
-- Includes: Complete Table Schemas, Constraints, Indexes & Seed Data
-- Database Engine: PostgreSQL / Universal SQL
-- Generated: 2026-08-30
-- ====================================================================

SET statement_timeout = 0;
SET lock_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

-- ====================================================================
-- SECTION 1: DROP TABLES (Clean Re-initialization if needed)
-- ====================================================================
DROP TABLE IF EXISTS public.reports CASCADE;
DROP TABLE IF EXISTS public.vulnerabilities CASCADE;
DROP TABLE IF EXISTS public.scheduled_scans CASCADE;
DROP TABLE IF EXISTS public.scans CASCADE;
DROP TABLE IF EXISTS public.alert_settings CASCADE;
DROP TABLE IF EXISTS public.organization_scan_quotas CASCADE;
DROP TABLE IF EXISTS public.payments CASCADE;
DROP TABLE IF EXISTS public.audit_logs CASCADE;
DROP TABLE IF EXISTS public.email_logs CASCADE;
DROP TABLE IF EXISTS public.users CASCADE;
DROP TABLE IF EXISTS public.roles CASCADE;
DROP TABLE IF EXISTS public.organizations CASCADE;
DROP TABLE IF EXISTS public.subscription_tiers CASCADE;
DROP TABLE IF EXISTS public.demo_bookings CASCADE;

-- ====================================================================
-- SECTION 2: CREATE TABLE SCHEMAS
-- ====================================================================

-- 1. Subscription Tiers
CREATE TABLE public.subscription_tiers (
    id character varying(50) NOT NULL PRIMARY KEY,
    name character varying(100) NOT NULL,
    monthly_price integer DEFAULT 0 NOT NULL,
    yearly_price integer DEFAULT 0 NOT NULL
);

-- 2. Organizations
CREATE TABLE public.organizations (
    id character varying(36) NOT NULL PRIMARY KEY,
    name character varying(150) NOT NULL,
    subscription_tier character varying(50) DEFAULT 'free'::character varying NOT NULL REFERENCES public.subscription_tiers(id),
    status character varying(50) DEFAULT 'active'::character varying,
    api_key character varying(100) UNIQUE,
    webhook_url character varying(500),
    report_logo_url character varying(500),
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);

-- 3. Roles
CREATE TABLE public.roles (
    id character varying(36) NOT NULL PRIMARY KEY,
    name character varying(50) NOT NULL UNIQUE
);

-- 4. Users (Includes Policy Acceptance & Security Fields)
CREATE TABLE public.users (
    id character varying(36) NOT NULL PRIMARY KEY,
    email character varying(120) NOT NULL UNIQUE,
    password_hash character varying(128) NOT NULL,
    first_name character varying(100),
    last_name character varying(100),
    role character varying(50) DEFAULT 'org_admin'::character varying NOT NULL,
    org_id character varying(36) REFERENCES public.organizations(id) ON DELETE SET NULL,
    failed_login_attempts integer DEFAULT 0,
    locked_until timestamp without time zone,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    
    -- Terms of Service & Privacy Policy Agreement Tracking
    terms_accepted_at timestamp without time zone,
    privacy_policy_agreed_at timestamp without time zone,
    policy_version_agreed character varying(20) DEFAULT 'v1.0'::character varying,
    
    -- Security & Authentication Metadata
    mfa_enabled boolean DEFAULT false,
    mfa_secret character varying(100),
    reset_token character varying(255),
    reset_token_expires timestamp without time zone,
    email_verified boolean DEFAULT false
);

-- 5. Alert Settings
CREATE TABLE public.alert_settings (
    id character varying(36) NOT NULL PRIMARY KEY,
    user_id character varying(36) NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    email_notifications boolean DEFAULT true,
    webhook_url character varying(500),
    severity_threshold character varying(50) DEFAULT 'Medium'::character varying
);

-- 6. Organization Scan Quotas
CREATE TABLE public.organization_scan_quotas (
    id character varying(36) NOT NULL PRIMARY KEY,
    org_id character varying(36) NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    scan_type character varying(50) NOT NULL,
    allocated_count integer DEFAULT 0 NOT NULL,
    used_count integer DEFAULT 0 NOT NULL,
    CONSTRAINT uix_org_scan_type UNIQUE (org_id, scan_type)
);

-- 7. Scans
CREATE TABLE public.scans (
    id character varying(36) NOT NULL PRIMARY KEY,
    org_id character varying(36) NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    user_id character varying(36) NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    target_url character varying(500) NOT NULL,
    scan_type character varying(50) DEFAULT 'Full'::character varying NOT NULL,
    status character varying(50) DEFAULT 'queued'::character varying NOT NULL,
    security_score integer,
    started_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    completed_at timestamp without time zone,
    auth_headers json,
    scan_options json,
    ssl_info json,
    
    -- Diagnostics & Summary Metrics
    duration_seconds integer,
    error_message text,
    critical_count integer DEFAULT 0,
    high_count integer DEFAULT 0,
    medium_count integer DEFAULT 0,
    low_count integer DEFAULT 0
);

-- 8. Vulnerabilities
CREATE TABLE public.vulnerabilities (
    id character varying(36) NOT NULL PRIMARY KEY,
    scan_id character varying(36) NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    title character varying(200) NOT NULL,
    severity character varying(50) NOT NULL,
    category character varying(100) NOT NULL,
    description text NOT NULL,
    remediation text NOT NULL,
    cvss_score double precision NOT NULL,
    detected_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    evidence text,
    payload text,
    request_details text,
    response_details text,
    is_false_positive boolean DEFAULT false,
    cwe_ids json,
    owasp_category character varying(100),
    exploit_poc json,
    remediation_code text,
    
    -- Lifecycle Tracking
    status character varying(50) DEFAULT 'open'::character varying NOT NULL,
    remediated_at timestamp without time zone,
    remediated_by character varying(36)
);

-- 9. Scheduled Scans
CREATE TABLE public.scheduled_scans (
    id character varying(36) NOT NULL PRIMARY KEY,
    org_id character varying(36) NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    user_id character varying(36) NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    target_url character varying(500) NOT NULL,
    scan_type character varying(50) DEFAULT 'Full'::character varying NOT NULL,
    frequency character varying(50) DEFAULT 'daily'::character varying NOT NULL,
    schedule_time character varying(5),
    day_of_week character varying(20),
    day_of_month integer,
    specific_date character varying(20),
    is_active boolean DEFAULT true,
    auth_headers json,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    last_run_at timestamp without time zone
);

-- 10. Payments
CREATE TABLE public.payments (
    id character varying(36) NOT NULL PRIMARY KEY,
    org_id character varying(36) REFERENCES public.organizations(id) ON DELETE CASCADE,
    user_id character varying(36) NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    razorpay_payment_id character varying(100) UNIQUE,
    razorpay_order_id character varying(100),
    stripe_session_id character varying(100) UNIQUE,
    stripe_payment_id character varying(100) UNIQUE,
    tier_id character varying(50) NOT NULL,
    amount integer NOT NULL,
    currency character varying(10) DEFAULT 'USD'::character varying,
    status character varying(50) DEFAULT 'successful'::character varying,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);

-- 11. Audit Logs
CREATE TABLE public.audit_logs (
    id character varying(36) NOT NULL PRIMARY KEY,
    admin_id character varying(36) NOT NULL,
    action character varying(255) NOT NULL,
    target_id character varying(100),
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);

-- 12. Demo Bookings
CREATE TABLE public.demo_bookings (
    id character varying(36) NOT NULL PRIMARY KEY,
    email character varying(255) NOT NULL,
    company_size character varying(100) NOT NULL,
    meeting_date character varying(100) NOT NULL,
    meeting_time character varying(50) NOT NULL,
    status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);

-- 13. Email Logs
CREATE TABLE public.email_logs (
    id character varying(36) NOT NULL PRIMARY KEY,
    recipient character varying(255) NOT NULL,
    subject character varying(255) NOT NULL,
    status character varying(50) DEFAULT 'sent'::character varying NOT NULL,
    error_message text,
    sent_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);

-- 14. Generated Reports
CREATE TABLE public.reports (
    id character varying(36) NOT NULL PRIMARY KEY,
    scan_id character varying(36) NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    org_id character varying(36) NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    report_type character varying(50) NOT NULL,
    file_path character varying(500),
    generated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);

-- ====================================================================
-- SECTION 3: PERFORMANCE INDEXES
-- ====================================================================
CREATE INDEX idx_users_org_id ON public.users(org_id);

CREATE INDEX idx_scans_org_id ON public.scans(org_id);
CREATE INDEX idx_scans_user_id ON public.scans(user_id);
CREATE INDEX idx_scans_status ON public.scans(status);

CREATE INDEX idx_vulnerabilities_scan_id ON public.vulnerabilities(scan_id);
CREATE INDEX idx_vulnerabilities_severity ON public.vulnerabilities(severity);
CREATE INDEX idx_vulnerabilities_status ON public.vulnerabilities(status);

CREATE INDEX idx_payments_org_id ON public.payments(org_id);
CREATE INDEX idx_payments_user_id ON public.payments(user_id);

CREATE INDEX idx_scheduled_scans_is_active ON public.scheduled_scans(is_active);

CREATE INDEX idx_reports_scan_id ON public.reports(scan_id);
CREATE INDEX idx_reports_org_id ON public.reports(org_id);

-- ====================================================================
-- SECTION 4: DEFAULT SEED DATA (System Initial Data)
-- ====================================================================

-- Insert Subscription Tiers
INSERT INTO public.subscription_tiers (id, name, monthly_price, yearly_price) VALUES
('free', 'Free Tier Plan', 0, 0),
('pro', 'Pro Security Plan', 49, 490),
('enterprise', 'Enterprise Shield Plan', 199, 1990)
ON CONFLICT (id) DO NOTHING;

-- Insert Predefined Roles
INSERT INTO public.roles (id, name) VALUES
('role-001', 'super_admin'),
('role-002', 'org_admin'),
('role-003', 'soc_analyst'),
('role-004', 'support_engineer'),
('role-005', 'executive'),
('role-006', 'read_only')
ON CONFLICT (name) DO NOTHING;

-- Insert Default Global Organization
INSERT INTO public.organizations (id, name, subscription_tier, status, api_key, created_at) VALUES
('org-default-001', 'LarShield Security Enterprise', 'enterprise', 'active', 'larshield_live_api_key_883920193847', CURRENT_TIMESTAMP)
ON CONFLICT (id) DO NOTHING;

-- Insert Default Administrator User (Email: admin@larshield.com)
-- Password Hash corresponds to standard hashed credential
INSERT INTO public.users (
    id, email, password_hash, first_name, last_name, role, org_id, 
    terms_accepted_at, privacy_policy_agreed_at, policy_version_agreed, email_verified
) VALUES (
    'user-admin-001', 
    'admin@larshield.com', 
    '$2b$12$eImiTXuWVxfM37uY4JANjO5E/0w5/qO1F1kR04.3jF96Wd58e3.6u', -- Bcrypt Hash for admin
    'System', 
    'Admin', 
    'org_admin', 
    'org-default-001',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP,
    'v1.0',
    true
)
ON CONFLICT (email) DO NOTHING;

-- Insert Default Alert Settings for Admin User
INSERT INTO public.alert_settings (id, user_id, email_notifications, severity_threshold) VALUES
('alert-admin-001', 'user-admin-001', true, 'Medium')
ON CONFLICT (id) DO NOTHING;

-- Insert Default Organization Quotas
INSERT INTO public.organization_scan_quotas (id, org_id, scan_type, allocated_count, used_count) VALUES
('quota-001', 'org-default-001', 'Full', 1000, 0),
('quota-002', 'org-default-001', 'Port', 5000, 0),
('quota-003', 'org-default-001', 'SSL', 5000, 0),
('quota-004', 'org-default-001', 'OWASP', 2000, 0)
ON CONFLICT (org_id, scan_type) DO NOTHING;

-- End of Database Initialization Script
