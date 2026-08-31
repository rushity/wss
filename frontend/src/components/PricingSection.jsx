/* eslint-disable react-hooks/exhaustive-deps, react-hooks/set-state-in-effect, react-hooks/immutability */
import React, { useState, useEffect } from 'react';
import { useAuth } from './AuthContext';
import { useNavigate } from 'react-router-dom';
import {
  Shield,
  Zap,
  Check,
  Target,
  ArrowRight,
  Briefcase
} from 'lucide-react';

export default function PricingSection({ embedded = false, hideCurrentPlan = false }) {
  const { user, token, refreshAccessToken } = useAuth();
  const navigate = useNavigate();
  const [loadingPlan, setLoadingPlan] = useState(null);
  const [paymentSuccess, setPaymentSuccess] = useState(false);
  const [paymentError, setPaymentError] = useState(null);
  const [dynamicPrices, setDynamicPrices] = useState({});

  useEffect(() => {
    // Fetch dynamic prices from backend
    fetch('/api/billing/tiers')
      .then(res => res.json())
      .then(data => {
        const prices = {};
        data.forEach(t => { prices[t.id] = (t.monthly_price / 100).toFixed(2); });
        setDynamicPrices(prices);
      })
      .catch(err => console.error("Failed to load dynamic prices", err));
    const urlParams = new URLSearchParams(window.location.search);
    const sessionId = urlParams.get('session_id');
    const canceled = urlParams.get('canceled');
    const tierId = urlParams.get('tier_id');

    if (sessionId && token) {
      verifyStripePayment(sessionId, tierId);
    } else if (canceled) {
      setPaymentError("Payment was canceled.");
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  }, [token]);

  const verifyStripePayment = async (sessionId, tierId) => {
    try {
      let res = await fetch('/api/billing/verify-payment', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ session_id: sessionId, tier_id: tierId })
      });

      if (res.status === 401) {
        // Token likely expired while user was on Stripe checkout
        const newToken = await refreshAccessToken();
        if (newToken) {
          res = await fetch('/api/billing/verify-payment', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${newToken}`
            },
            body: JSON.stringify({ session_id: sessionId, tier_id: tierId })
          });
        }
      }

      const data = await res.json();
      if (data.status === 'success') {
        setPaymentSuccess(true);
        setTimeout(() => {
          window.history.replaceState({}, document.title, window.location.pathname);
          window.location.reload();
        }, 4000);
      } else {
        setPaymentError("Payment verification failed: " + (data.message || 'Unknown Error') + ". Please contact our support team at support@larshield.com for assistance.");
        window.history.replaceState({}, document.title, window.location.pathname);
      }
    } catch (err) {
      console.error(err);
      setPaymentError("Error verifying payment. Please reach out to our technical team at support@larshield.com.");
    }
  };

  const handleSubscribe = async (priceId) => {
    if (priceId === 'enterprise') {
      window.location.href = "#booking";
      return;
    }

    if (!user) {
      navigate('/login');
      return;
    }

    setLoadingPlan(priceId);
    try {
      const res = await fetch('/api/billing/create-checkout-session', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ price_id: priceId, billing_cycle: 'monthly' })
      });

      const orderData = await res.json();
      if (!orderData.checkout_url) {
        setPaymentError("Failed to create order: " + (orderData.message || 'Unknown error') + ". Please contact our support team at support@larshield.com.");
        setLoadingPlan(null);
        return;
      }

      window.location.href = orderData.checkout_url;

    } catch (err) {
      console.error(err);
      setPaymentError("An error occurred during checkout initialization. Please reach out to our technical team at support@larshield.com.");
      setLoadingPlan(null);
    }
  };

  const plans = [
    {
      id: 'quick',
      name: "Quick Scan",
      icon: <Zap className="w-8 h-8 text-primary" />,
      price: dynamicPrices['quick'] || 4.99,
      description: "Essential reconnaissance & basic security health checks.",
      scanners: "13 Security Modules",
      features: [
        "3 Scans for 1 Target Website",
        "Fast Recon (Headers, Nmap Quick, WHOIS, WAF)",
        "DNS Security & SSL/TLS Audit",
        "Cookies, CSP & Clickjacking Checks",
        "Git Repository Exposure Detection",
        "Instant PDF Report Export"
      ],
      popular: false
    },
    {
      id: 'advanced',
      name: "Advanced Scan",
      icon: <Shield className="w-8 h-8 text-primary" />,
      price: dynamicPrices['advanced'] || 44.99,
      description: "Core vulnerability auditing & deep path analysis.",
      scanners: "36 Security Modules",
      popular: false,
      features: [
        "3 Scans for 1 Target Website",
        "Everything in Quick Scan",
        "Subdomain Discovery (Subfinder, Amass, crt.sh)",
        "XSS, SQL Injection & Path Traversal Fuzzing",
        "REST API, Cloud Bucket & Secrets Leak Scan",
        "CVE Database & Nikto Web Server Engine",
        "AI Remediation & Strategy Generator"
      ]
    },
    {
      id: 'deep',
      name: "Deep Scan",
      icon: <Target className="w-8 h-8 text-primary" />,
      price: dynamicPrices['deep'] || 99.99,
      description: "Exhaustive threat inspection & active DAST attack simulation.",
      scanners: "89 Security Modules",
      popular: true,
      features: [
        "3 Scans for 1 Target Website",
        "Everything in Advanced Scan",
        "Full 65535-Port Nmap with NSE Vulnerability Scripts",
        "Nuclei Scanner Engine (Critical/High/Med/Low)",
        "OWASP ZAP DAST Engine (Active Attack Mode)",
        "XXE, SSTI, IDOR, GraphQL & Business Logic Flaws",
        "HTTP/2 Desync, JS Supply Chain & SAML/OAuth Bypasses"
      ]
    },
    {
      id: 'enterprise',
      name: "Custom Solutions",
      icon: <Briefcase className="w-8 h-8 text-primary" />,
      price: "Custom",
      description: "Tailored VAPT services and dedicated security infrastructure.",
      scanners: "Expert Manual VAPT",
      popular: false,
      features: [
        "Everything in Deep Scan",
        "Quarterly Manual VAPT",
        "Dedicated Security Architect",
        "Custom Compliance Reporting",
        "On-Premise Deployment Options",
        "1-Hour SLA"
      ]
    }
  ];

  return (
    <div className={`${embedded ? 'py-8' : 'py-12'} bg-surface-container-lowest text-on-surface px-4 sm:px-6 relative overflow-hidden border-b border-outline-variant/30`}>

      {paymentError && (
        <div className="fixed bottom-10 left-1/2 -translate-x-1/2 z-[100] flex items-center bg-error text-on-error px-md py-sm rounded-lg shadow-xl animate-fade-in gap-sm border border-on-error/20">
          <span className="material-symbols-outlined">error</span>
          <span className="font-bold text-[14px]">{paymentError}</span>
          <button onClick={() => setPaymentError(null)} className="ml-md text-on-error/80 hover:text-on-error bg-transparent border-0 cursor-pointer p-0 flex items-center">
            <span className="material-symbols-outlined text-[18px]">close</span>
          </button>
        </div>
      )}

      {paymentSuccess && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-surface-container-lowest/80 backdrop-blur-sm animate-fade-in">
          <div className="bg-surface-container border border-outline-variant rounded-2xl p-xl shadow-2xl max-w-sm w-full text-center flex flex-col items-center transform animate-scale-up">
            <div className="w-20 h-20 bg-emerald-500/20 text-emerald-500 rounded-full flex items-center justify-center mb-md shadow-sm border border-emerald-500/30">
              <span className="material-symbols-outlined text-[48px] animate-pulse">check_circle</span>
            </div>
            <h2 className="font-headline-md font-bold text-on-surface mb-sm">Upgrade Successful!</h2>
            <p className="font-body-md text-on-surface-variant mb-lg">Your payment was verified. We are unlocking your scan package...</p>
            <div className="w-full bg-surface-container-highest rounded-full h-1.5 overflow-hidden">
              <div className="bg-emerald-500 h-full animate-[progress_4s_ease-in-out_forwards]"></div>
            </div>
          </div>
        </div>
      )}
      {/* Background Soft Gradients (Adapted to Light Theme) */}
      <div className="absolute top-0 left-1/4 w-[500px] h-[500px] bg-primary/5 rounded-full blur-[100px] -z-10 pointer-events-none"></div>
      <div className="absolute bottom-0 right-1/4 w-[600px] h-[600px] bg-secondary/5 rounded-full blur-[100px] -z-10 pointer-events-none"></div>

      <div className="max-w-[1400px] mx-auto">
        <div className="text-center mb-10 relative">
          <div className="inline-flex items-center space-x-2 bg-surface-container-low border border-outline-variant/60 rounded-full px-4 py-1 mb-4 shadow-sm">
            <Shield className="w-3.5 h-3.5 text-primary" />
            <span className="font-label-sm text-on-surface font-bold tracking-wider uppercase text-[10px]">LarShield Target Scan Packages</span>
          </div>
          <h1 className="font-display-lg text-3xl md:text-4xl font-extrabold text-on-surface mb-4 tracking-tight">
            Single Domain Scan Packages
          </h1>
          <p className="font-body-md text-base text-on-surface-variant max-w-2xl mx-auto mb-4 leading-relaxed">
            Purchase a plan once and perform up to <strong className="text-on-surface font-extrabold">3 complete scans</strong> on the same target website.
          </p>

          <div className="inline-flex items-center gap-xs bg-primary/10 text-primary border border-primary/20 rounded-full px-4 py-1.5 text-xs font-bold shadow-sm">
            <span className="material-symbols-outlined text-[16px]">verified</span>
            1 Plan Purchase = 3 Scans Allowed for 1 Target Website
          </div>
        </div>

        {/* Pricing Cards */}
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 w-full mx-auto z-10 relative">
          {plans.map((plan) => {
            const isCurrentPlan = hideCurrentPlan ? false : user?.subscription_tier === plan.id;

            return (
              <div
                key={plan.id}
                className={`relative bg-surface-container-lowest rounded-2xl p-6 transition-all duration-300 flex flex-col group border-2 ${plan.popular ? 'border-primary shadow-xl scale-[1.02]' : 'border-outline-variant/50 shadow-sm hover:border-primary/50 hover:-translate-y-1 hover:shadow-lg'}`}
              >
                {plan.popular && (
                  <div className="absolute -top-3.5 left-1/2 -translate-x-1/2 bg-primary text-on-primary px-4 py-1 rounded-full font-label-sm text-[10px] font-extrabold uppercase tracking-wider shadow-sm whitespace-nowrap">
                    Recommended
                  </div>
                )}

                <div className="mb-4 flex flex-col gap-xs">
                  <div className="w-10 h-10 rounded-xl flex items-center justify-center mb-1 transition-transform duration-300 bg-primary/10">
                    {React.cloneElement(plan.icon, { className: "w-5 h-5 text-primary" })}
                  </div>
                  <h3 className="font-headline-md text-lg font-extrabold text-on-surface">{plan.name}</h3>
                  <p className="font-body-sm text-on-surface-variant text-[12.5px] leading-snug min-h-[36px]">{plan.description}</p>
                </div>

                <div className="mb-4 flex items-baseline border-b border-outline-variant/40 pb-4">
                  <span className="font-display-lg text-3xl lg:text-4xl font-extrabold text-on-surface tracking-tight">
                    {plan.price === 'Custom' ? 'Custom' : `$${plan.price}`}
                  </span>
                  {/* Removed / month per user request */}
                </div>

                <div className="mb-4">
                  <div className="inline-block bg-surface-container-low rounded-md px-2.5 py-0.5 font-label-sm text-[10px] font-bold text-primary uppercase tracking-wider border border-primary/10">
                    {plan.scanners}
                  </div>
                </div>

                <ul className="space-y-2 mb-6 flex-1">
                  {plan.features.map((feature, idx) => (
                    <li key={idx} className="flex items-start">
                      <Check className="w-4 h-4 mr-2.5 shrink-0 mt-0.5 text-primary" strokeWidth={3} />
                      <span className="font-body-sm text-on-surface text-[12.5px] leading-snug font-medium">{feature}</span>
                    </li>
                  ))}
                </ul>

                <button
                  onClick={() => handleSubscribe(plan.id)}
                  disabled={loadingPlan === plan.id || isCurrentPlan}
                  className={`w-full py-2.5 rounded-lg font-label-md text-sm transition-all duration-300 flex items-center justify-center font-bold border-0 cursor-pointer ${isCurrentPlan
                      ? 'bg-surface-container-highest text-on-surface-variant cursor-not-allowed opacity-80'
                      : 'bg-primary text-on-primary shadow-md hover:opacity-90 hover:shadow-lg active:scale-[0.98]'
                    }`}
                >
                  {loadingPlan === plan.id ? (
                    <span className="flex items-center gap-xs"><span className="material-symbols-outlined animate-spin text-[18px]">sync</span> Processing...</span>
                  ) : isCurrentPlan ? 'Current Plan' : plan.id === 'enterprise' ? 'Contact Sales' : 'Get Started'}
                  {!isCurrentPlan && loadingPlan !== plan.id && <ArrowRight className="w-4 h-4 ml-2 opacity-70" />}
                </button>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
