--
-- PostgreSQL database dump (Upgraded & Production-Ready for LarShield)
-- Dumped with full Policy Consent tracking, Vulnerability Lifecycle Management,
-- Scan Metrics, Foreign Key Cascades, Indexes, and System Seed Data.
--

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';
SET default_table_access_method = heap;

-- --------------------------------------------------------
-- Name: subscription_tiers; Type: TABLE; Schema: public; Owner: postgres
-- --------------------------------------------------------
CREATE TABLE public.subscription_tiers (
    id character varying(50) NOT NULL,
    name character varying(100) NOT NULL,
    monthly_price integer DEFAULT 0 NOT NULL,
    yearly_price integer DEFAULT 0 NOT NULL
);

ALTER TABLE public.subscription_tiers OWNER TO postgres;

-- --------------------------------------------------------
-- Name: organizations; Type: TABLE; Schema: public; Owner: postgres
-- --------------------------------------------------------
CREATE TABLE public.organizations (
    id character varying(36) NOT NULL,
    name character varying(150) NOT NULL,
    subscription_tier character varying(50) DEFAULT 'free'::character varying NOT NULL,
    status character varying(50) DEFAULT 'active'::character varying,
    api_key character varying(100),
    webhook_url character varying(500),
    report_logo_url character varying(500),
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE public.organizations OWNER TO postgres;

-- --------------------------------------------------------
-- Name: roles; Type: TABLE; Schema: public; Owner: postgres
-- --------------------------------------------------------
CREATE TABLE public.roles (
    id character varying(36) NOT NULL,
    name character varying(50) NOT NULL
);

ALTER TABLE public.roles OWNER TO postgres;

-- --------------------------------------------------------
-- Name: users; Type: TABLE; Schema: public; Owner: postgres
-- --------------------------------------------------------
CREATE TABLE public.users (
    id character varying(36) NOT NULL,
    email character varying(120) NOT NULL,
    password_hash character varying(128) NOT NULL,
    first_name character varying(100),
    last_name character varying(100),
    role character varying(50) DEFAULT 'org_admin'::character varying NOT NULL,
    org_id character varying(36),
    failed_login_attempts integer DEFAULT 0,
    locked_until timestamp without time zone,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    
    -- Added Policy Consent & Agreement Fields
    terms_accepted_at timestamp without time zone,
    privacy_policy_agreed_at timestamp without time zone,
    policy_version_agreed character varying(20) DEFAULT 'v1.0'::character varying,
    
    -- Added Security & MFA Metadata
    mfa_enabled boolean DEFAULT false,
    mfa_secret character varying(100),
    reset_token character varying(255),
    reset_token_expires timestamp without time zone,
    email_verified boolean DEFAULT false
);

ALTER TABLE public.users OWNER TO postgres;

-- --------------------------------------------------------
-- Name: alert_settings; Type: TABLE; Schema: public; Owner: postgres
-- --------------------------------------------------------
CREATE TABLE public.alert_settings (
    id character varying(36) NOT NULL,
    user_id character varying(36) NOT NULL,
    email_notifications boolean DEFAULT true,
    webhook_url character varying(500),
    severity_threshold character varying(50) DEFAULT 'Medium'::character varying
);

ALTER TABLE public.alert_settings OWNER TO postgres;

-- --------------------------------------------------------
-- Name: organization_scan_quotas; Type: TABLE; Schema: public; Owner: postgres
-- --------------------------------------------------------
CREATE TABLE public.organization_scan_quotas (
    id character varying(36) NOT NULL,
    org_id character varying(36) NOT NULL,
    scan_type character varying(50) NOT NULL,
    allocated_count integer DEFAULT 0 NOT NULL,
    used_count integer DEFAULT 0 NOT NULL
);

ALTER TABLE public.organization_scan_quotas OWNER TO postgres;

-- --------------------------------------------------------
-- Name: scans; Type: TABLE; Schema: public; Owner: postgres
-- --------------------------------------------------------
CREATE TABLE public.scans (
    id character varying(36) NOT NULL,
    org_id character varying(36) NOT NULL,
    user_id character varying(36) NOT NULL,
    target_url character varying(500) NOT NULL,
    scan_type character varying(50) DEFAULT 'Full'::character varying NOT NULL,
    status character varying(50) DEFAULT 'queued'::character varying NOT NULL,
    security_score integer,
    started_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    completed_at timestamp without time zone,
    auth_headers json,
    scan_options json,
    ssl_info json,
    
    -- Added Diagnostics & Pre-aggregated Metrics
    duration_seconds integer,
    error_message text,
    critical_count integer DEFAULT 0,
    high_count integer DEFAULT 0,
    medium_count integer DEFAULT 0,
    low_count integer DEFAULT 0
);

ALTER TABLE public.scans OWNER TO postgres;

-- --------------------------------------------------------
-- Name: vulnerabilities; Type: TABLE; Schema: public; Owner: postgres
-- --------------------------------------------------------
CREATE TABLE public.vulnerabilities (
    id character varying(36) NOT NULL,
    scan_id character varying(36) NOT NULL,
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
    
    -- Added Lifecycle Status Tracking
    status character varying(50) DEFAULT 'open'::character varying NOT NULL,
    remediated_at timestamp without time zone,
    remediated_by character varying(36)
);

ALTER TABLE public.vulnerabilities OWNER TO postgres;

-- --------------------------------------------------------
-- Name: scheduled_scans; Type: TABLE; Schema: public; Owner: postgres
-- --------------------------------------------------------
CREATE TABLE public.scheduled_scans (
    id character varying(36) NOT NULL,
    org_id character varying(36) NOT NULL,
    user_id character varying(36) NOT NULL,
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

ALTER TABLE public.scheduled_scans OWNER TO postgres;

-- --------------------------------------------------------
-- Name: payments; Type: TABLE; Schema: public; Owner: postgres
-- --------------------------------------------------------
CREATE TABLE public.payments (
    id character varying(36) NOT NULL,
    org_id character varying(36),
    user_id character varying(36) NOT NULL,
    razorpay_payment_id character varying(100),
    razorpay_order_id character varying(100),
    stripe_session_id character varying(100),
    stripe_payment_id character varying(100),
    tier_id character varying(50) NOT NULL,
    amount integer NOT NULL,
    currency character varying(10) DEFAULT 'USD'::character varying,
    status character varying(50) DEFAULT 'successful'::character varying,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE public.payments OWNER TO postgres;

-- --------------------------------------------------------
-- Name: audit_logs; Type: TABLE; Schema: public; Owner: postgres
-- --------------------------------------------------------
CREATE TABLE public.audit_logs (
    id character varying(36) NOT NULL,
    admin_id character varying(36) NOT NULL,
    action character varying(255) NOT NULL,
    target_id character varying(100),
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE public.audit_logs OWNER TO postgres;

-- --------------------------------------------------------
-- Name: demo_bookings; Type: TABLE; Schema: public; Owner: postgres
-- --------------------------------------------------------
CREATE TABLE public.demo_bookings (
    id character varying(36) NOT NULL,
    email character varying(255) NOT NULL,
    company_size character varying(100) NOT NULL,
    meeting_date character varying(100) NOT NULL,
    meeting_time character varying(50) NOT NULL,
    status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE public.demo_bookings OWNER TO postgres;

-- --------------------------------------------------------
-- Name: email_logs; Type: TABLE; Schema: public; Owner: postgres
-- --------------------------------------------------------
CREATE TABLE public.email_logs (
    id character varying(36) NOT NULL,
    recipient character varying(255) NOT NULL,
    subject character varying(255) NOT NULL,
    status character varying(50) DEFAULT 'sent'::character varying NOT NULL,
    error_message text,
    sent_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE public.email_logs OWNER TO postgres;

-- --------------------------------------------------------
-- Name: reports; Type: TABLE; Schema: public; Owner: postgres
-- --------------------------------------------------------
CREATE TABLE public.reports (
    id character varying(36) NOT NULL,
    scan_id character varying(36) NOT NULL,
    org_id character varying(36) NOT NULL,
    report_type character varying(50) NOT NULL,
    file_path character varying(500),
    generated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE public.reports OWNER TO postgres;

-- --------------------------------------------------------
-- Primary Keys & Unique Constraints
-- --------------------------------------------------------
ALTER TABLE ONLY public.subscription_tiers ADD CONSTRAINT subscription_tiers_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.organizations ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.organizations ADD CONSTRAINT organizations_api_key_key UNIQUE (api_key);

ALTER TABLE ONLY public.roles ADD CONSTRAINT roles_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.roles ADD CONSTRAINT roles_name_key UNIQUE (name);

ALTER TABLE ONLY public.users ADD CONSTRAINT users_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.users ADD CONSTRAINT users_email_key UNIQUE (email);

ALTER TABLE ONLY public.alert_settings ADD CONSTRAINT alert_settings_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.organization_scan_quotas ADD CONSTRAINT organization_scan_quotas_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.organization_scan_quotas ADD CONSTRAINT uix_org_scan_type UNIQUE (org_id, scan_type);

ALTER TABLE ONLY public.scans ADD CONSTRAINT scans_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.vulnerabilities ADD CONSTRAINT vulnerabilities_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.scheduled_scans ADD CONSTRAINT scheduled_scans_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.payments ADD CONSTRAINT payments_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.payments ADD CONSTRAINT payments_razorpay_payment_id_key UNIQUE (razorpay_payment_id);
ALTER TABLE ONLY public.payments ADD CONSTRAINT payments_stripe_payment_id_key UNIQUE (stripe_payment_id);
ALTER TABLE ONLY public.payments ADD CONSTRAINT payments_stripe_session_id_key UNIQUE (stripe_session_id);

ALTER TABLE ONLY public.audit_logs ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.demo_bookings ADD CONSTRAINT demo_bookings_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.email_logs ADD CONSTRAINT email_logs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.reports ADD CONSTRAINT reports_pkey PRIMARY KEY (id);

-- --------------------------------------------------------
-- Foreign Key Constraints with ON DELETE CASCADE / SET NULL
-- --------------------------------------------------------
ALTER TABLE ONLY public.organizations 
    ADD CONSTRAINT organizations_subscription_tier_fkey FOREIGN KEY (subscription_tier) REFERENCES public.subscription_tiers(id);

ALTER TABLE ONLY public.users 
    ADD CONSTRAINT users_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.alert_settings 
    ADD CONSTRAINT alert_settings_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.organization_scan_quotas 
    ADD CONSTRAINT organization_scan_quotas_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.payments 
    ADD CONSTRAINT payments_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE,
    ADD CONSTRAINT payments_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.scans 
    ADD CONSTRAINT scans_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE,
    ADD CONSTRAINT scans_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.scheduled_scans 
    ADD CONSTRAINT scheduled_scans_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE,
    ADD CONSTRAINT scheduled_scans_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.vulnerabilities 
    ADD CONSTRAINT vulnerabilities_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.reports 
    ADD CONSTRAINT reports_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE CASCADE,
    ADD CONSTRAINT reports_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

-- --------------------------------------------------------
-- Indexes for High-Performance Queries
-- --------------------------------------------------------
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

-- --------------------------------------------------------
-- Seed Data: Subscription Tiers, System Roles, Default Org, Admin User
-- --------------------------------------------------------
INSERT INTO public.subscription_tiers (id, name, monthly_price, yearly_price) VALUES
('free', 'Free Tier Plan', 0, 0),
('pro', 'Pro Security Plan', 49, 490),
('enterprise', 'Enterprise Shield Plan', 199, 1990)
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.roles (id, name) VALUES
('role-001', 'super_admin'),
('role-002', 'org_admin'),
('role-003', 'soc_analyst'),
('role-004', 'support_engineer'),
('role-005', 'executive'),
('role-006', 'read_only')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.organizations (id, name, subscription_tier, status, api_key, created_at) VALUES
('org-default-001', 'LarShield Security Enterprise', 'enterprise', 'active', 'larshield_live_api_key_883920193847', CURRENT_TIMESTAMP)
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.users (
    id, email, password_hash, first_name, last_name, role, org_id, 
    terms_accepted_at, privacy_policy_agreed_at, policy_version_agreed, email_verified
) VALUES (
    'user-admin-001', 
    'admin@larshield.com', 
    '$2b$12$eImiTXuWVxfM37uY4JANjO5E/0w5/qO1F1kR04.3jF96Wd58e3.6u',
    'System', 
    'Admin', 
    'org_admin', 
    'org-default-001',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP,
    'v1.0',
    true
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.alert_settings (id, user_id, email_notifications, severity_threshold) VALUES
('alert-admin-001', 'user-admin-001', true, 'Medium')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.organization_scan_quotas (id, org_id, scan_type, allocated_count, used_count) VALUES
('quota-001', 'org-default-001', 'Full', 1000, 0),
('quota-002', 'org-default-001', 'Port', 5000, 0),
('quota-003', 'org-default-001', 'SSL', 5000, 0),
('quota-004', 'org-default-001', 'OWASP', 2000, 0)
ON CONFLICT (id) DO NOTHING;
