import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import PricingSection from '../components/PricingSection';
import { useAuth } from '../components/AuthContext';
import toast from 'react-hot-toast';

// Helper function to generate 16 consecutive calendar days starting from today
const generateDynamicDays = () => {
  const daysArray = [];
  const weekdays = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  const months = [
    'January', 'February', 'March', 'April', 'May', 'June',
    'July', 'August', 'September', 'October', 'November', 'December'
  ];

  const today = new Date();

  let addedDays = 0;
  while (addedDays < 2) {
    today.setDate(today.getDate() + 1);
    if (today.getDay() !== 0 && today.getDay() !== 6) {
      addedDays++;
    }
  }

  for (let i = 0; i < 16; i++) {
    const futureDate = new Date(today);
    futureDate.setDate(today.getDate() + i);

    const dayName = weekdays[futureDate.getDay()].charAt(0);
    const dateNum = String(futureDate.getDate()).padStart(2, '0');
    const monthName = months[futureDate.getMonth()];
    const year = futureDate.getFullYear();

    daysArray.push({
      day: dayName,
      date: dateNum,
      month: monthName,
      year: year
    });
  }
  return daysArray;
};

export const LandingPage = () => {
  // Calendar Days Dataset (Starts from today)
  const allDays = generateDynamicDays();

  // Calendar Booking States
  const [calendarOffset, setCalendarOffset] = useState(0);
  const [selectedDate, setSelectedDate] = useState(allDays[0].date);
  const [selectedTime, setSelectedTime] = useState('10:30 AM');
  const [useManualTime, setUseManualTime] = useState(false);
  const [customTime, setCustomTime] = useState('10:30');
  const [bookingEmail, setBookingEmail] = useState('');
  const [companySize, setCompanySize] = useState('Company Size: 500+ employees');
  const [bookingSuccess, setBookingSuccess] = useState(false);
  const [bookingError, setBookingError] = useState('');

  const navigate = useNavigate();
  const { login, user } = useAuth();
  const [activeFaq, setActiveFaq] = useState(null);
  const [legalModal, setLegalModal] = useState(null);

  const [activeTab, setActiveTab] = useState('Security Score');

  const calendarDays = calendarOffset === 0 ? allDays.slice(0, 8) : allDays.slice(8, 16);

  const timeSlots = [
    '09:00 AM', '10:00 AM', '11:00 AM',
    '04:00 PM', '05:00 PM', '06:00 PM',
    '09:30 PM', '10:30 PM', '11:30 PM'
  ];

  const handleBooking = async (e) => {
    e.preventDefault();
    setBookingError('');

    if (!bookingEmail) {
      setBookingError('Please enter a valid work email.');
      return;
    }
    if (!bookingEmail.includes('@') || bookingEmail.length < 5) {
      setBookingError('Invalid email syntax. Please check.');
      return;
    }

    try {
      const response = await fetch('/api/demo/book', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          email: bookingEmail,
          company_size: companySize,
          meeting_date: `${selectedMonth} ${selectedDate}, ${selectedYear}`,
          meeting_time: selectedTime
        })
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(data.message || 'Failed to book demo');
      }

      setBookingSuccess(true);
    } catch (err) {
      setBookingError(err.message || 'Failed to book demo. Please try again later.');
    }
  };

  const resetBooking = () => {
    setBookingEmail('');
    setBookingSuccess(false);
    setBookingError('');
  };

  const handleNextWeek = () => {
    setCalendarOffset(1);
    setSelectedDate(allDays[8].date);
  };

  const handlePrevWeek = () => {
    setCalendarOffset(0);
    setSelectedDate(allDays[0].date);
  };

  const selectedDayObject = allDays.find(d => d.date === selectedDate) || allDays[0];
  const selectedMonth = selectedDayObject ? selectedDayObject.month : 'June';
  const selectedYear = selectedDayObject ? selectedDayObject.year : '2026';

  const faqItems = [
    {
      q: "How does the LarShield autonomous vulnerability crawler operate?",
      a: "LarShield dynamically maps your entire cloud perimeter. By simulating browser behaviors, active DNS crawls, HTTP header inspections, and secure fuzzer injections, we expose structural security gaps and logic flaws."
    },
    {
      q: "Is it safe to run dynamic scanning on live production servers?",
      a: "Absolutely. Our standard scans are meticulously structured to avoid service disruption. They use non-destructive payloads designed only to flag vulnerabilities, without corrupting database states or degrading host performance."
    },
    {
      q: "Can I export detailed reports mapped to security standards?",
      a: "Yes. Every scan session yields a comprehensive diagnostic report. You can instantly export PDF threat assessments mapped to OWASP Top 10 guidelines and CWE classifications, complete with remediation code patches."
    },
    {
      q: "Do you provide remediation support and patches?",
      a: "Yes, our comprehensive reports include actionable remediation steps, code snippets, and configuration guides to help your engineering team fix vulnerabilities efficiently."
    },
    {
      q: "How long does a typical penetration testing engagement take?",
      a: "Depending on the scope and complexity of the application, an automated scan completes in minutes to hours, while a deep-dive manual VAPT engagement typically takes 1 to 2 weeks."
    },
    {
      q: "Are the reports accepted by compliance auditors and enterprise clients?",
      a: "Absolutely. Our reports are mapped to industry standards like OWASP, ISO 27001, SOC 2, and PCI DSS, making them widely accepted by third-party auditors and enterprise procurement teams."
    }
  ];

  const tabs = ['Security Score', 'Assets', 'Vulnerabilities', 'AI Insights', 'Compliance', 'Reports'];

  return (
    <div className="bg-surface text-on-surface font-body-md min-h-screen flex flex-col selection:bg-primary/10">

      {/* TopNavBar */}
      <header className="fixed top-0 w-full z-50 border-b border-outline-variant glass-header shadow-sm transition-all duration-300">
        <div className="flex justify-between items-center h-16 px-gutter max-w-container-max mx-auto">
          <div className="flex items-center gap-lg">
            <div className="font-headline-md text-headline-md font-bold text-on-surface flex items-center gap-sm">
              <div className="w-8 h-8 flex items-center justify-center">
                <img src="/logo.png" alt="LarShield Logo" className="w-full h-full object-contain" />
              </div>
              <span className="tracking-tight font-display font-bold text-[16px] brand-gradient">LarShield</span>
            </div>
            <nav className="hidden lg:flex gap-md ml-xl">
              <a className="font-body-md text-body-md text-on-surface-variant hover:text-primary px-sm py-[6px] rounded-lg hover:bg-surface-container-low transition-all duration-200" href="#modules" style={{ textDecoration: 'none' }}>Modules</a>
              <a className="font-body-md text-body-md text-on-surface-variant hover:text-primary px-sm py-[6px] rounded-lg hover:bg-surface-container-low transition-all duration-200" href="#vapt" style={{ textDecoration: 'none' }}>VAPT</a>
              <a className="font-body-md text-body-md text-on-surface-variant hover:text-primary px-sm py-[6px] rounded-lg hover:bg-surface-container-low transition-all duration-200" href="#coverage" style={{ textDecoration: 'none' }}>Capabilities</a>
              <a className="font-body-md text-body-md text-on-surface-variant hover:text-primary px-sm py-[6px] rounded-lg hover:bg-surface-container-low transition-all duration-200" href="#reports" style={{ textDecoration: 'none' }}>Reports</a>
              <a className="font-body-md text-body-md text-on-surface-variant hover:text-primary px-sm py-[6px] rounded-lg hover:bg-surface-container-low transition-all duration-200" href="#profiles" style={{ textDecoration: 'none' }}>Pricing</a>
            </nav>
          </div>
          <div className="flex items-center gap-md">
            <div className="hidden md:flex items-center gap-sm mr-md">
              <Link className="font-label-md text-label-md text-on-surface-variant hover:text-primary px-sm transition-colors duration-200" to="/login" style={{ textDecoration: 'none' }}>Log In</Link>
            </div>
            <a href="#booking" className="bg-primary text-on-primary font-label-md text-label-md px-md py-sm rounded-lg hover:brightness-110 active:scale-[0.98] transition-all font-bold shadow-md shadow-primary/20" style={{ textDecoration: 'none' }}>
              Book a Demo
            </a>
          </div>
        </div>
      </header>

      <main className="flex-grow pt-16 relative">

        {/* Soft atmospheric gradient vector circles */}
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full max-w-container-max h-[700px] overflow-hidden -z-10 pointer-events-none opacity-50">
          <div className="absolute top-[-200px] left-[20%] w-[600px] h-[600px] bg-[radial-gradient(circle,rgba(0,74,198,0.07)_0%,transparent_70%)] rounded-full blur-3xl"></div>
          <div className="absolute top-[100px] right-[10%] w-[500px] h-[500px] bg-[radial-gradient(circle,rgba(37,99,235,0.05)_0%,transparent_70%)] rounded-full blur-3xl"></div>
        </div>

        {/* Hero Section */}
        <section className="px-gutter max-w-container-max mx-auto py-2xl md:py-[120px]">
          <div className="flex flex-col lg:flex-row items-center gap-xl lg:gap-2xl">
            {/* Left Content */}
            <div className="flex-1 flex flex-col items-center lg:items-start text-center lg:text-left z-10">
              <span className="bg-primary/10 text-primary font-bold px-sm py-[4px] rounded-full text-[12px] uppercase tracking-wider mb-md border border-primary/20">
                Next-Gen Security Platform
              </span>
              <h1 className="font-display-lg text-display-lg text-on-surface mb-lg leading-[1.15] font-extrabold tracking-tight text-[36px] md:text-[52px]">
                One Platform to <br className="hidden lg:block" /> Scan, Monitor &amp; Protect
              </h1>
              <p className="font-body-lg text-body-lg text-on-surface-variant max-w-[600px] mb-xl text-[15px] md:text-[18px] leading-relaxed">
                Identify vulnerabilities, continuously monitor your digital assets, manage compliance, and strengthen your organization's security with automated scanning and expert-led VAPT services.
              </p>
              <div className="flex flex-col sm:flex-row items-center justify-center lg:justify-start gap-md w-full">
                <Link to="/register" className="bg-primary text-on-primary h-[54px] px-xl w-full sm:w-auto flex items-center justify-center gap-sm font-bold rounded-lg shadow-md shadow-primary/20 hover:brightness-110 active:scale-[0.98] transition-all" style={{ textDecoration: 'none' }}>
                  Start Free Scan
                </Link>
                <a href="#booking" className="bg-surface-container-lowest border border-outline-variant text-on-surface h-[54px] px-xl w-full sm:w-auto flex items-center justify-center gap-sm font-bold rounded-lg hover:bg-surface-container-low active:scale-[0.98] transition-all" style={{ textDecoration: 'none' }}>
                  Book Live Demo
                </a>
              </div>
            </div>

            {/* Right Laptop */}
            <div className="flex-1 w-full max-w-[700px] lg:max-w-none perspective-1000 mt-xl lg:mt-0 relative z-10">
              <div className="relative w-full mx-auto px-md lg:px-0">
                <div className="relative rounded-t-2xl md:rounded-t-3xl border-[6px] md:border-[8px] border-surface-container-highest bg-[#0B0C10] shadow-2xl overflow-hidden aspect-[16/10] flex flex-col justify-between">
                  {/* Fake Browser Top Bar */}
                  <div className="h-7 md:h-9 bg-surface-container-highest w-full border-b border-outline-variant/30 flex items-center px-sm gap-2 shrink-0">
                    <div className="w-10"></div> {/* Spacer for perfect centering */}
                    <div className="mx-auto bg-surface-container-low h-5 md:h-6 rounded-md w-[60%] flex items-center justify-center text-[10px] text-on-surface-variant font-mono shadow-inner border border-outline-variant/30 font-semibold tracking-wide">
                      <span className="material-symbols-outlined text-[12px] mr-1 text-green-500">lock</span> app.larshield.com
                    </div>
                    <div className="w-10"></div> {/* Spacer for perfect centering */}
                  </div>

                  {/* Image Container */}
                  <div className="flex-grow w-full flex items-center justify-center bg-surface-container-lowest overflow-hidden">
                    <img src="/dashboard-preview.png" alt="LarShield Dashboard" className="w-full h-auto object-contain" />
                  </div>

                  {/* Bottom Status Bar */}
                  <div className="h-6 md:h-8 bg-surface-container-highest border-t border-outline-variant/30 w-full flex items-center px-md justify-between shrink-0 overflow-hidden">
                    <div className="flex items-center gap-xs">
                      <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
                      <span className="text-[9px] md:text-[10px] font-mono text-green-500 font-bold uppercase tracking-widest mt-0.5">Live Telemetry Active</span>
                    </div>
                    <div className="hidden sm:flex items-center gap-sm">
                      <span className="text-[9px] font-mono text-on-surface-variant font-bold">ENGINE: NEURAL-V3</span>
                      <span className="text-[9px] font-mono text-on-surface-variant font-bold">MODE: AUTONOMOUS</span>
                    </div>
                  </div>
                </div>
                <div className="relative h-4 md:h-6 bg-surface-container-highest rounded-b-lg md:rounded-b-xl shadow-xl w-[105%] md:w-[110%] -ml-[2.5%] md:-ml-[5%] flex items-center justify-center">
                  <div className="w-20 md:w-32 h-1 bg-outline-variant rounded-full mt-[-6px] md:mt-[-8px]"></div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Statistics Section */}
        <section className="py-xl md:py-2xl bg-surface-container-lowest border-y border-outline-variant/60">
          <div className="max-w-container-max mx-auto px-gutter text-center">
            <h2 className="font-headline-lg text-[24px] md:text-[32px] font-extrabold mb-xl">Platform Metrics That Matter</h2>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-md md:gap-lg">

              <div className="flex flex-col items-center justify-center p-md text-center">
                <span className="font-display-lg text-[32px] md:text-[40px] font-extrabold text-primary tracking-tight">1500+</span>
                <span className="font-label-md text-on-surface-variant font-bold uppercase tracking-wider text-[11px] mt-2">Security Checks</span>
              </div>

              <div className="flex flex-col items-center justify-center p-md text-center">
                <span className="font-display-lg text-[32px] md:text-[40px] font-extrabold text-primary tracking-tight">83+</span>
                <span className="font-label-md text-on-surface-variant font-bold uppercase tracking-wider text-[11px] mt-2">Vulnerability Scanners</span>
              </div>

              <div className="flex flex-col items-center justify-center p-md text-center">
                <span className="material-symbols-outlined text-[40px] md:text-[48px] text-primary mb-2">policy</span>
                <span className="font-label-md text-on-surface-variant font-bold uppercase tracking-wider text-[11px]">OWASP Top 10 Coverage</span>
              </div>

              <div className="flex flex-col items-center justify-center p-md text-center">
                <span className="material-symbols-outlined text-[40px] md:text-[48px] text-primary mb-2">api</span>
                <span className="font-label-md text-on-surface-variant font-bold uppercase tracking-wider text-[11px]">API Security Testing</span>
              </div>

              <div className="flex flex-col items-center justify-center p-md text-center">
                <span className="material-symbols-outlined text-[40px] md:text-[48px] text-primary mb-2">smart_toy</span>
                <span className="font-label-md text-on-surface-variant font-bold uppercase tracking-wider text-[11px]">AI Risk Scoring</span>
              </div>

              <div className="flex flex-col items-center justify-center p-md text-center">
                <span className="material-symbols-outlined text-[40px] md:text-[48px] text-primary mb-2">map</span>
                <span className="font-label-md text-on-surface-variant font-bold uppercase tracking-wider text-[11px]">CVSS v3.1 Mapping</span>
              </div>

            </div>
          </div>
        </section>

        {/* Why LarShield */}
        <section className="py-xl md:py-2xl bg-surface relative">
          <div className="max-w-container-max mx-auto px-gutter text-center">
            <h2 className="font-headline-lg text-[28px] md:text-[36px] font-extrabold mb-xl">Why LarShield?</h2>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-lg">

              <div className="bg-surface-container-lowest border border-outline-variant/80 p-lg rounded-2xl shadow-sm hover:shadow-md hover:border-primary/40 transition-all duration-300 text-left">
                <div className="w-12 h-12 bg-primary/10 rounded-xl flex items-center justify-center mb-md">
                  <span className="material-symbols-outlined text-primary text-[24px]">psychology</span>
                </div>
                <h4 className="font-headline-md text-on-surface font-bold text-[18px] mb-xs">AI Powered</h4>
                <p className="font-body-sm text-on-surface-variant text-[13px] leading-relaxed">
                  AI-based vulnerability prioritization focusing on exploitable risks rather than noise.
                </p>
              </div>

              <div className="bg-surface-container-lowest border border-outline-variant/80 p-lg rounded-2xl shadow-sm hover:shadow-md hover:border-primary/40 transition-all duration-300 text-left">
                <div className="w-12 h-12 bg-blue-500/10 rounded-xl flex items-center justify-center mb-md">
                  <span className="material-symbols-outlined text-blue-600 text-[24px]">troubleshoot</span>
                </div>
                <h4 className="font-headline-md text-on-surface font-bold text-[18px] mb-xs">Continuous Monitoring</h4>
                <p className="font-body-sm text-on-surface-variant text-[13px] leading-relaxed">
                  24×7 active attack surface monitoring preventing drifts in infrastructure security.
                </p>
              </div>

              <div className="bg-surface-container-lowest border border-outline-variant/80 p-lg rounded-2xl shadow-sm hover:shadow-md hover:border-primary/40 transition-all duration-300 text-left">
                <div className="w-12 h-12 bg-green-500/10 rounded-xl flex items-center justify-center mb-md">
                  <span className="material-symbols-outlined text-green-600 text-[24px]">admin_panel_settings</span>
                </div>
                <h4 className="font-headline-md text-on-surface font-bold text-[18px] mb-xs">Expert VAPT</h4>
                <p className="font-body-sm text-on-surface-variant text-[13px] leading-relaxed">
                  Manual penetration testing powered by security experts to uncover advanced business logic flaws.
                </p>
              </div>

              <div className="bg-surface-container-lowest border border-outline-variant/80 p-lg rounded-2xl shadow-sm hover:shadow-md hover:border-primary/40 transition-all duration-300 text-left">
                <div className="w-12 h-12 bg-purple-500/10 rounded-xl flex items-center justify-center mb-md">
                  <span className="material-symbols-outlined text-purple-600 text-[24px]">verified_user</span>
                </div>
                <h4 className="font-headline-md text-on-surface font-bold text-[18px] mb-xs">Compliance Ready</h4>
                <p className="font-body-sm text-on-surface-variant text-[13px] leading-relaxed">
                  Built-in mappings for SOC2, ISO27001, CERT-In, and PCI DSS compliance reporting.
                </p>
              </div>

            </div>
          </div>
        </section>

        {/* Platform Modules (Replacing How It Works / Feature Cards) */}
        <section id="modules" className="py-xl md:py-2xl bg-surface-container-lowest border-t border-outline-variant/50 relative">
          <div className="max-w-container-max mx-auto px-gutter">
            <div className="text-center mb-xl">
              <h2 className="font-headline-lg text-[28px] md:text-[36px] font-extrabold mb-md">Scanner Coverage</h2>
              <p className="font-body-md text-on-surface-variant max-w-[700px] mx-auto">A unified suite designed to secure every layer of your modern stack.</p>
            </div>

            <div className="flex flex-wrap justify-center items-center gap-sm md:gap-lg mt-xl">

              <div className="group px-md py-sm rounded-full bg-surface-container-lowest border border-outline-variant/80 shadow-sm hover:shadow-md hover:border-primary/50 transition-all duration-300 flex items-center gap-xs cursor-default">
                <span className="material-symbols-outlined text-blue-600 text-[18px]">language</span>
                <span className="font-bold text-[13px] md:text-[14px] text-on-surface tracking-tight">Web</span>
              </div>

              <div className="group px-md py-sm rounded-full bg-surface-container-lowest border border-outline-variant/80 shadow-sm hover:shadow-md hover:border-primary/50 transition-all duration-300 flex items-center gap-xs cursor-default">
                <span className="material-symbols-outlined text-indigo-600 text-[18px]">lock_person</span>
                <span className="font-bold text-[13px] md:text-[14px] text-on-surface tracking-tight">Authentication</span>
              </div>

              <div className="group px-md py-sm rounded-full bg-surface-container-lowest border border-outline-variant/80 shadow-sm hover:shadow-md hover:border-primary/50 transition-all duration-300 flex items-center gap-xs cursor-default">
                <span className="material-symbols-outlined text-purple-600 text-[18px]">api</span>
                <span className="font-bold text-[13px] md:text-[14px] text-on-surface tracking-tight">API</span>
              </div>

              <div className="group px-md py-sm rounded-full bg-surface-container-lowest border border-outline-variant/80 shadow-sm hover:shadow-md hover:border-primary/50 transition-all duration-300 flex items-center gap-xs cursor-default">
                <span className="material-symbols-outlined text-emerald-600 text-[18px]">dns</span>
                <span className="font-bold text-[13px] md:text-[14px] text-on-surface tracking-tight">Infrastructure</span>
              </div>

              <div className="group px-md py-sm rounded-full bg-surface-container-lowest border border-outline-variant/80 shadow-sm hover:shadow-md hover:border-primary/50 transition-all duration-300 flex items-center gap-xs cursor-default">
                <span className="material-symbols-outlined text-sky-600 text-[18px]">cloud</span>
                <span className="font-bold text-[13px] md:text-[14px] text-on-surface tracking-tight">Cloud</span>
              </div>

              <div className="group px-md py-sm rounded-full bg-surface-container-lowest border border-outline-variant/80 shadow-sm hover:shadow-md hover:border-primary/50 transition-all duration-300 flex items-center gap-xs cursor-default">
                <span className="material-symbols-outlined text-teal-600 text-[18px]">policy</span>
                <span className="font-bold text-[13px] md:text-[14px] text-on-surface tracking-tight">Compliance</span>
              </div>

            </div>
          </div>
        </section>

        {/* Downloadable Deliverables */}
        <section id="reports" className="py-xl md:py-2xl bg-surface relative border-t border-outline-variant/50">
          <div className="max-w-container-max mx-auto px-gutter text-center">
            <h2 className="font-headline-lg text-[28px] md:text-[36px] font-extrabold mb-md">Downloadable Deliverables</h2>
            <p className="font-body-md text-on-surface-variant max-w-[700px] mx-auto mb-xl">Explore our comprehensive sample reports to understand the depth and clarity of our assessments.</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-md">
              {[
                { title: 'Web Application PenTest', file: '/reports/Deep_Scan_Report.pdf', downloadName: 'LarShield_Web Application PenTest Demo Report.pdf', available: true },
                { title: 'API Security Assessment', file: '/reports/API_Security_Assessment_Methodology.pdf', downloadName: 'LarShield_API Security Assessment Demo Report.pdf', available: true },
                { title: 'Mobile App PenTest', file: '/reports/Mobile_App_Penetration_Testing_Guide_2026.pdf', downloadName: 'LarShield_Mobile App PenTest Demo Report.pdf', available: true },
                { title: 'Cloud Security Review', file: null, available: false },
                { title: 'Network Vulnerability Scan', file: null, available: false },
                { title: 'Compliance Audit Report', file: null, available: false }
              ].map((report, idx) => (
                <div key={idx} className={`bg-surface-container-lowest border border-outline-variant p-md rounded-xl flex items-center justify-between transition-all ${report.available ? 'hover:border-primary/50 hover:shadow-md' : 'opacity-70'}`}>
                  <div className="flex items-center gap-sm text-left">
                    <span className={`material-symbols-outlined text-[28px] ${report.available ? 'text-red-500' : 'text-outline-variant'}`}>picture_as_pdf</span>
                    <span className="font-bold text-[14px] text-on-surface">{report.title}</span>
                  </div>
                  {report.available ? (
                    <a href={report.file} target="_blank" rel="noopener noreferrer" className="text-primary hover:bg-primary/10 p-2 rounded-lg transition-colors flex items-center" style={{ textDecoration: 'none' }} download={report.downloadName}>
                      <span className="material-symbols-outlined">download</span>
                    </a>
                  ) : (
                    <span className="text-[10px] font-bold text-on-surface-variant bg-surface-container-high px-2 py-1 rounded-md uppercase tracking-wider">
                      Upcoming
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        </section>



        {/* VAPT Services */}
        <section id="vapt" className="py-xl md:py-2xl bg-surface-container-lowest border-t border-outline-variant/50">
          <div className="max-w-container-max mx-auto px-gutter flex flex-col md:flex-row items-center gap-2xl">
            <div className="flex-1 text-center md:text-left">
              <h2 className="font-headline-lg text-[28px] md:text-[36px] font-extrabold mb-md text-on-surface">Professional Security Services</h2>
              <p className="font-body-md text-on-surface-variant text-[16px] leading-relaxed mb-lg">
                Go beyond automated scanning with our expert-led manual penetration testing and compliance consulting services.
              </p>
              <a href="#booking" className="bg-primary text-white px-xl py-sm rounded-lg font-bold hover:brightness-110 transition-all shadow-md">
                Schedule a Consultation
              </a>
            </div>

            <div className="flex-1 w-full bg-surface-container-low p-xl rounded-2xl border border-outline-variant/60 shadow-lg">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-y-md gap-x-lg text-left">

                <div className="flex items-center gap-sm font-bold text-[14px] text-on-surface">
                  <span className="material-symbols-outlined text-green-500 text-[20px]">check_circle</span> Web Application VAPT
                </div>
                <div className="flex items-center gap-sm font-bold text-[14px] text-on-surface">
                  <span className="material-symbols-outlined text-green-500 text-[20px]">check_circle</span> Source Code Review
                </div>
                <div className="flex items-center gap-sm font-bold text-[14px] text-on-surface">
                  <span className="material-symbols-outlined text-green-500 text-[20px]">check_circle</span> Mobile Application VAPT
                </div>
                <div className="flex items-center gap-sm font-bold text-[14px] text-on-surface">
                  <span className="material-symbols-outlined text-green-500 text-[20px]">check_circle</span> Wireless Assessment
                </div>
                <div className="flex items-center gap-sm font-bold text-[14px] text-on-surface">
                  <span className="material-symbols-outlined text-green-500 text-[20px]">check_circle</span> API VAPT
                </div>
                <div className="flex items-center gap-sm font-bold text-[14px] text-on-surface">
                  <span className="material-symbols-outlined text-green-500 text-[20px]">check_circle</span> Active Directory Assessment
                </div>
                <div className="flex items-center gap-sm font-bold text-[14px] text-on-surface">
                  <span className="material-symbols-outlined text-green-500 text-[20px]">check_circle</span> Network VAPT
                </div>
                <div className="flex items-center gap-sm font-bold text-[14px] text-on-surface">
                  <span className="material-symbols-outlined text-green-500 text-[20px]">check_circle</span> Secure Configuration Review
                </div>
                <div className="flex items-center gap-sm font-bold text-[14px] text-on-surface">
                  <span className="material-symbols-outlined text-green-500 text-[20px]">check_circle</span> Cloud Security Assessment
                </div>
                <div className="flex items-center gap-sm font-bold text-[14px] text-on-surface">
                  <span className="material-symbols-outlined text-green-500 text-[20px]">check_circle</span> Compliance Consulting
                </div>

              </div>
            </div>
          </div>
        </section>

        {/* Compliance Section */}
        <section className="bg-surface py-xl border-y border-outline-variant/50">
          <div className="max-w-container-max mx-auto px-gutter text-center">
            <h3 className="font-headline-sm text-on-surface-variant font-bold uppercase tracking-widest text-[12px] mb-lg">
              Helping organizations prepare for leading security and compliance frameworks
            </h3>
            <div className="flex flex-wrap justify-center items-center gap-xl md:gap-2xl font-display-lg text-[20px] md:text-[24px] font-extrabold text-on-surface opacity-80">
              <span className="flex items-center gap-xs"><span className="material-symbols-outlined text-primary text-[28px]">verified</span> ISO 27001</span>
              <span className="flex items-center gap-xs"><span className="material-symbols-outlined text-primary text-[28px]">shield</span> SOC 2</span>
              <span className="flex items-center gap-xs"><span className="material-symbols-outlined text-primary text-[28px]">gpp_good</span> CERT-In</span>
              <span className="flex items-center gap-xs"><span className="material-symbols-outlined text-primary text-[28px]">security</span> OWASP</span>
              <span className="flex items-center gap-xs"><span className="material-symbols-outlined text-primary text-[28px]">credit_card</span> PCI DSS</span>
              <span className="flex items-center gap-xs"><span className="material-symbols-outlined text-primary text-[28px]">fact_check</span> NIST</span>
              <span className="flex items-center gap-xs"><span className="material-symbols-outlined text-primary text-[28px]">settings_suggest</span> CIS Controls</span>
            </div>
          </div>
        </section>





        {/* Scanning Profiles & Coverage Section */}
        <section id="profiles" className="bg-[#0B0C10] border-t border-b border-outline-variant/50">
          <PricingSection embedded={true} hideCurrentPlan={true} />
        </section>

        {/* Demo Booking Section */}
        <section id="booking" className="bg-primary text-on-primary py-xl md:py-2.5xl overflow-hidden relative">
          <div className="absolute inset-0 opacity-10">
            <svg className="h-full w-full" fill="none" preserveAspectRatio="none" viewBox="0 0 100 100">
              <path d="M0 100 L100 0 L100 100 Z" fill="currentColor" />
            </svg>
          </div>
          <div className="max-w-container-max mx-auto px-gutter relative z-10 flex flex-col lg:flex-row items-center gap-2xl">

            {/* Left Content */}
            <div className="flex-1 text-center lg:text-left">
              <h2 className="font-display-lg text-[32px] md:text-[44px] text-white leading-tight mb-lg font-extrabold tracking-tight">
                Ready to Secure Your Organization at Scale?
              </h2>
              <p className="font-body-lg text-primary-fixed mb-xl opacity-90 leading-relaxed text-[15px] md:text-[17px]">
                Schedule a personalized 1:1 demo with our security architects to see how LarShield can integrate into your existing SOC and CI/CD pipelines.
              </p>
              <div className="flex flex-col sm:flex-row gap-lg justify-center lg:justify-start">
                <div className="flex items-center gap-sm justify-center sm:justify-start">
                  <span className="material-symbols-outlined bg-white/10 p-1.5 rounded-lg border border-white/10">schedule</span>
                  <span className="font-body-md font-semibold text-[14.5px]">15 min discovery call</span>
                </div>
                <div className="flex items-center gap-sm justify-center sm:justify-start">
                  <span className="material-symbols-outlined bg-white/10 p-1.5 rounded-lg border border-white/10">analytics</span>
                  <span className="font-body-md font-semibold text-[14.5px]">Custom vulnerability assessment</span>
                </div>
              </div>
            </div>

            {/* Right Interactive Scheduler Widget */}
            <div className="flex-grow-0 shrink-0 w-full max-w-[380px] self-center">
              <div className="bg-surface-container-low p-md rounded-2xl shadow-2xl text-on-surface text-left border border-primary/20">

                {bookingSuccess ? (
                  /* Success Booking State Box */
                  <div className="py-lg flex flex-col items-center justify-center text-center gap-sm animate-fade-in">
                    <div className="h-14 w-14 rounded-full bg-green-500/10 border border-green-500/20 flex items-center justify-center text-green-600 mb-xs">
                      <span className="material-symbols-outlined text-[32px]" style={{ fontVariationSettings: "'FILL' 1" }}>check_circle</span>
                    </div>
                    <h3 className="font-headline-md text-on-surface font-extrabold text-[18px] tracking-tight">Booking Confirmed!</h3>
                    <p className="font-body-md text-on-surface-variant text-[12.5px] leading-relaxed">
                      Your personalized 1:1 security walk-through has been successfully scheduled.
                    </p>

                    <div className="w-full bg-white border border-outline-variant p-sm rounded-xl text-left text-body-sm text-on-surface-variant flex flex-col gap-xs mt-xs font-semibold text-[12px]">
                      <div className="flex justify-between border-b border-outline-variant/30 pb-xs">
                        <span>Meeting Slot:</span>
                        <span className="text-on-surface font-bold">{selectedMonth} {selectedDate}, {selectedYear}</span>
                      </div>
                      <div className="flex justify-between border-b border-outline-variant/30 py-xs">
                        <span>Assigned Time:</span>
                        <span className="text-on-surface font-bold">{selectedTime}</span>
                      </div>
                      <div className="flex justify-between border-b border-outline-variant/30 py-xs">
                        <span>Invited Host:</span>
                        <span className="text-primary truncate max-w-[150px] font-bold">{bookingEmail}</span>
                      </div>
                      <div className="flex justify-between pt-xs">
                        <span>Org Scale:</span>
                        <span className="text-on-surface font-bold">{companySize.split(': ')[1] || '500+ employees'}</span>
                      </div>
                    </div>

                    <button
                      onClick={resetBooking}
                      className="mt-sm bg-primary text-white py-sm px-lg rounded-lg font-label-md hover:brightness-110 active:scale-[0.98] transition-all shadow-md shadow-primary/20 border-0 cursor-pointer font-bold text-[13px]"
                    >
                      Book Another Slot
                    </button>
                  </div>
                ) : (
                  /* Active Scheduler form */
                  <form onSubmit={handleBooking}>

                    {/* Header */}
                    <div className="mb-md border-b border-outline-variant pb-xs flex justify-between items-center">
                      <div>
                        <h4 className="font-headline-md text-[15px] font-extrabold text-on-surface m-0 tracking-tight">Select a Time</h4>
                        <p className="font-body-sm text-body-sm text-on-surface-variant m-0 mt-[2px] text-[11px]">Choose date &amp; meeting time</p>
                      </div>
                      <div className="flex items-center gap-xs">
                        <span className="text-[10px] font-extrabold text-primary bg-primary/20 border border-primary/30 px-2 py-0.5 rounded uppercase tracking-wider">
                          {selectedMonth} {selectedYear}
                        </span>
                      </div>
                    </div>

                    {bookingError && (
                      <div className="flex gap-sm bg-error-container border border-error rounded-lg p-xs font-body-sm text-body-sm text-on-error-container mb-md text-[12px]">
                        <span className="material-symbols-outlined text-error text-[18px]">warning</span>
                        <div>{bookingError}</div>
                      </div>
                    )}

                    {/* Dates slider */}
                    <div className="relative mb-md flex items-center justify-between border border-primary/10 rounded-xl p-xs bg-white">

                      {calendarOffset === 1 ? (
                        <button
                          type="button"
                          onClick={handlePrevWeek}
                          className="h-7 w-7 rounded-full border border-outline-variant/80 flex items-center justify-center bg-surface-container-low hover:bg-surface-container-high cursor-pointer transition-all shadow-sm shrink-0 active:scale-95 animate-fade-in"
                        >
                          <span className="material-symbols-outlined text-on-surface text-[15px]">chevron_left</span>
                        </button>
                      ) : (
                        <div className="w-7 shrink-0"></div>
                      )}

                      <div className="flex overflow-x-auto gap-xs pb-0.5 scrollbar-none scroll-smooth flex-grow justify-center mx-0.5">
                        {calendarDays.map((day) => {
                          const isSelected = selectedDate === day.date;
                          return (
                            <div
                              key={day.date}
                              onClick={() => setSelectedDate(day.date)}
                              className="flex flex-col items-center gap-0.5 min-w-[30px] cursor-pointer"
                            >
                              <div className="text-on-surface-variant text-[9.5px] font-bold h-4 flex items-center justify-center">{day.day}</div>
                              <div className={`h-7 w-7 rounded-full flex items-center justify-center text-[11.5px] transition-all font-bold ${isSelected
                                ? 'bg-primary text-white shadow-md shadow-primary/25 scale-105'
                                : 'bg-surface-container-low border border-outline-variant/40 hover:border-primary/40 hover:bg-surface-container-high text-on-surface'
                                }`}>
                                {day.date}
                              </div>
                            </div>
                          );
                        })}
                      </div>

                      {calendarOffset === 0 ? (
                        <button
                          type="button"
                          onClick={handleNextWeek}
                          className="h-7 w-7 rounded-full border border-outline-variant/80 flex items-center justify-center bg-surface-container-low hover:bg-surface-container-high cursor-pointer transition-all shadow-sm shrink-0 active:scale-95"
                        >
                          <span className="material-symbols-outlined text-on-surface text-[15px]">chevron_right</span>
                        </button>
                      ) : (
                        <div className="w-7 shrink-0"></div>
                      )}

                    </div>

                    {/* Time Selection */}
                    <div className="mb-md">
                      <div className="flex justify-between items-center mb-xs">
                        <span className="font-label-sm text-label-sm text-on-surface-variant uppercase tracking-wider font-extrabold text-[9.5px]">Meeting Time:</span>
                        <button
                          type="button"
                          onClick={() => setUseManualTime(!useManualTime)}
                          className="text-[10.5px] text-primary font-bold hover:underline border-0 bg-transparent cursor-pointer flex items-center gap-xs transition-colors duration-150"
                        >
                          <span className="material-symbols-outlined text-[12px]">schedule</span>
                          {useManualTime ? "Use Quick Slots" : "Enter Manual Time"}
                        </button>
                      </div>

                      {useManualTime ? (
                        <div className="flex flex-col gap-xs">
                          <input
                            type="time"
                            value={customTime}
                            onChange={(e) => {
                              setCustomTime(e.target.value);
                              const [hoursStr, minutesStr] = e.target.value.split(':');
                              if (hoursStr && minutesStr) {
                                let hours = parseInt(hoursStr);
                                const ampm = hours >= 12 ? 'PM' : 'AM';
                                hours = hours % 12;
                                hours = hours ? hours : 12;
                                setSelectedTime(`${hours}:${minutesStr} ${ampm}`);
                              }
                            }}
                            className="w-full border border-outline-variant rounded-lg py-xs px-sm focus:ring-primary focus:border-primary font-body-sm bg-white text-on-surface text-[12.5px]"
                            required
                          />
                        </div>
                      ) : (
                        <div className="grid grid-cols-3 gap-xs">
                          {timeSlots.map((time) => {
                            const isSelected = selectedTime === time;
                            return (
                              <button
                                key={time}
                                type="button"
                                onClick={() => setSelectedTime(time)}
                                className={`py-1.5 text-center text-[10px] font-bold border rounded transition-all cursor-pointer active:scale-95 ${isSelected
                                  ? 'bg-primary border-primary text-white shadow-sm shadow-primary/20 scale-105'
                                  : 'bg-white border-outline-variant/60 text-on-surface-variant hover:bg-surface-container-high'
                                  }`}
                              >
                                {time.split(' ')[0]}
                              </button>
                            );
                          })}
                        </div>
                      )}
                    </div>

                    {/* Inputs */}
                    <div className="space-y-sm mb-md">
                      <input
                        className="w-full border border-outline-variant rounded-lg py-[6px] px-sm focus:ring-primary focus:border-primary font-body-sm bg-white text-on-surface text-[12.5px] transition-all"
                        placeholder="Work Email"
                        required
                        type="email"
                        value={bookingEmail}
                        onChange={(e) => setBookingEmail(e.target.value)}
                      />
                      <select
                        className="w-full border border-outline-variant rounded-lg py-[6px] px-sm focus:ring-primary focus:border-primary font-body-sm bg-white cursor-pointer text-on-surface text-[12.5px] transition-all"
                        value={companySize}
                        onChange={(e) => setCompanySize(e.target.value)}
                      >
                        <option value="Company Size: 500+ employees">Company Size: 500+ employees</option>
                        <option value="Company Size: 100-499 employees">Company Size: 100-499 employees</option>
                        <option value="Company Size: &lt;100 employees">Company Size: &lt;100 employees</option>
                      </select>
                    </div>

                    <button
                      type="submit"
                      className="w-full bg-primary text-white py-sm rounded-lg font-label-md hover:brightness-110 active:scale-[0.99] shadow-md shadow-primary/25 flex items-center justify-center border-0 cursor-pointer font-extrabold text-[13.5px] transition-all"
                    >
                      Confirm Booking
                    </button>
                    <p className="mt-xs text-[10.5px] text-on-surface-variant text-center leading-relaxed font-semibold">
                      No credit card required. Private POC environment included.
                    </p>

                  </form>
                )}

              </div>
            </div>

          </div>
        </section>

        {/* Industries */}
        <section className="bg-surface py-xl border-t border-outline-variant/50">
          <div className="max-w-container-max mx-auto px-gutter text-center">
            <h3 className="font-headline-sm text-on-surface-variant font-bold uppercase tracking-widest text-[14px] mb-lg">
              Trusted Across Industries
            </h3>
            <div className="flex flex-wrap justify-center items-center gap-sm md:gap-md">
              <span className="px-md py-sm bg-surface-container-lowest border border-outline-variant rounded-full font-bold text-[13px] text-on-surface flex items-center gap-xs"><span className="material-symbols-outlined text-[18px]">account_balance</span> Banking</span>
              <span className="px-md py-sm bg-surface-container-lowest border border-outline-variant rounded-full font-bold text-[13px] text-on-surface flex items-center gap-xs"><span className="material-symbols-outlined text-[18px]">account_balance_wallet</span> Government</span>
              <span className="px-md py-sm bg-surface-container-lowest border border-outline-variant rounded-full font-bold text-[13px] text-on-surface flex items-center gap-xs"><span className="material-symbols-outlined text-[18px]">local_hospital</span> Healthcare</span>
              <span className="px-md py-sm bg-surface-container-lowest border border-outline-variant rounded-full font-bold text-[13px] text-on-surface flex items-center gap-xs"><span className="material-symbols-outlined text-[18px]">precision_manufacturing</span> Manufacturing</span>
              <span className="px-md py-sm bg-surface-container-lowest border border-outline-variant rounded-full font-bold text-[13px] text-on-surface flex items-center gap-xs"><span className="material-symbols-outlined text-[18px]">cloud</span> SaaS</span>
              <span className="px-md py-sm bg-surface-container-lowest border border-outline-variant rounded-full font-bold text-[13px] text-on-surface flex items-center gap-xs"><span className="material-symbols-outlined text-[18px]">school</span> Education</span>
              <span className="px-md py-sm bg-surface-container-lowest border border-outline-variant rounded-full font-bold text-[13px] text-on-surface flex items-center gap-xs"><span className="material-symbols-outlined text-[18px]">local_shipping</span> Logistics</span>
              <span className="px-md py-sm bg-surface-container-lowest border border-outline-variant rounded-full font-bold text-[13px] text-on-surface flex items-center gap-xs"><span className="material-symbols-outlined text-[18px]">sailing</span> Ports &amp; Maritime</span>
              <span className="px-md py-sm bg-surface-container-lowest border border-outline-variant rounded-full font-bold text-[13px] text-on-surface flex items-center gap-xs"><span className="material-symbols-outlined text-[18px]">storefront</span> Retail</span>
            </div>
          </div>
        </section>

        {/* Frequently Asked Questions */}
        <section className="px-gutter max-w-4xl mx-auto mt-md mb-md py-lg border-t border-outline-variant/60 relative">
          <div className="text-center mb-lg">
            <h2 className="font-headline-lg text-headline-lg text-on-surface mb-md font-extrabold text-[26px] md:text-[32px] tracking-tight">Frequently Asked Questions</h2>
            <p className="font-body-md text-on-surface-variant text-[14px] md:text-[16px]">Everything you need to know about our active scanning and scheduling protocols.</p>
          </div>
          <div className="space-y-md">
            {faqItems.map((item, index) => {
              const isOpen = activeFaq === index;
              return (
                <div key={index} className="bg-surface-container-lowest border border-outline-variant rounded-xl overflow-hidden shadow-sm transition-all duration-300">
                  <button
                    onClick={() => setActiveFaq(isOpen ? null : index)}
                    aria-expanded={isOpen}
                    aria-controls={`faq-answer-${index}`}
                    className="w-full px-lg py-md flex justify-between items-center text-left font-bold text-on-surface text-[14.5px] hover:bg-surface-container-low border-0 bg-transparent cursor-pointer transition-colors"
                  >
                    <span>{item.q}</span>
                    <span className={`material-symbols-outlined transform transition-transform duration-300 ${isOpen ? 'rotate-180 text-primary' : 'text-on-surface-variant'}`} aria-hidden="true">
                      keyboard_arrow_down
                    </span>
                  </button>
                  <div id={`faq-answer-${index}`} className={`transition-all duration-300 overflow-hidden ${isOpen ? 'max-h-[200px] border-t border-outline-variant/40' : 'max-h-0'
                    }`}>
                    <div className="p-lg text-[13.5px] text-on-surface-variant leading-relaxed text-left bg-surface-container-low/20">
                      {item.a}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </section>

      </main>

      {/* Detailed Footer */}
      <footer className="w-full py-lg bg-surface-container-highest border-t border-outline-variant">
        <div className="max-w-container-max mx-auto px-gutter grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-lg mb-lg text-left">

          <div className="col-span-1 lg:col-span-2">
            <div className="font-label-md text-label-md font-bold text-on-surface flex items-center gap-sm mb-sm">
              <div className="w-8 h-8 flex items-center justify-center">
                <img src="/logo.png" alt="LarShield Logo" className="w-full h-full object-contain" />
              </div>
              <span className="font-display font-extrabold text-[18px] brand-gradient">LarShield</span>
            </div>
            <p className="text-on-surface-variant font-body-sm mb-md max-w-[280px] leading-relaxed text-[13px]">Automating world-class security intelligence for modern engineering and security teams across the globe.</p>
            <div className="flex gap-xs">
              <a aria-label="Website Link" className="text-on-surface-variant hover:text-primary hover:bg-primary/10 p-2 rounded-lg border border-transparent hover:border-primary/20 transition-all duration-200" href="#"><span className="material-symbols-outlined text-[20px]" aria-hidden="true">public</span></a>
              <a aria-label="Email Address" className="text-on-surface-variant hover:text-primary hover:bg-primary/10 p-2 rounded-lg border border-transparent hover:border-primary/20 transition-all duration-200" href="#"><span className="material-symbols-outlined text-[20px]" aria-hidden="true">alternate_email</span></a>
              <a aria-label="RSS Feed" className="text-on-surface-variant hover:text-primary hover:bg-primary/10 p-2 rounded-lg border border-transparent hover:border-primary/20 transition-all duration-200" href="#"><span className="material-symbols-outlined text-[20px]" aria-hidden="true">rss_feed</span></a>
            </div>
          </div>

          <div>
            <h5 className="font-label-md text-on-surface font-extrabold mb-md text-[11px] uppercase tracking-wider">Platform</h5>
            <nav className="flex flex-col gap-sm">
              <a className="font-body-sm text-[13px] text-on-surface-variant hover:text-primary transition-colors" href="#">Features</a>
              <a className="font-body-sm text-[13px] text-on-surface-variant hover:text-primary transition-colors" href="#">Dashboard</a>
              <a className="font-body-sm text-[13px] text-on-surface-variant hover:text-primary transition-colors" href="#">Reports</a>
            </nav>
          </div>

          <div>
            <h5 className="font-label-md text-on-surface font-extrabold mb-md text-[11px] uppercase tracking-wider">Security Services</h5>
            <nav className="flex flex-col gap-sm">
              <a className="font-body-sm text-[13px] text-on-surface-variant hover:text-primary transition-colors" href="#">Web VAPT</a>
              <a className="font-body-sm text-[13px] text-on-surface-variant hover:text-primary transition-colors" href="#">Mobile VAPT</a>
              <a className="font-body-sm text-[13px] text-on-surface-variant hover:text-primary transition-colors" href="#">API VAPT</a>
              <a className="font-body-sm text-[13px] text-on-surface-variant hover:text-primary transition-colors" href="#">Network VAPT</a>
              <a className="font-body-sm text-[13px] text-on-surface-variant hover:text-primary transition-colors" href="#">Cloud Security</a>
            </nav>
          </div>


          <div>
            <h5 className="font-label-md text-on-surface font-extrabold mb-md text-[11px] uppercase tracking-wider">Resources</h5>
            <nav className="flex flex-col gap-sm">
              <a className="font-body-sm text-[13px] text-on-surface-variant hover:text-primary transition-colors" href="#">Documentation</a>
              <a className="font-body-sm text-[13px] text-on-surface-variant hover:text-primary transition-colors" href="#">Knowledge Base</a>
              <a className="font-body-sm text-[13px] text-on-surface-variant hover:text-primary transition-colors" href="#">Security Blog</a>
              <a className="font-body-sm text-[13px] text-on-surface-variant hover:text-primary transition-colors" href="#">CVE Database</a>
              <a className="font-body-sm text-[13px] text-on-surface-variant hover:text-primary transition-colors" href="#">Release Notes</a>
            </nav>
          </div>

          <div>
            <h5 className="font-label-md text-on-surface font-extrabold mb-md text-[11px] uppercase tracking-wider">Company</h5>
            <nav className="flex flex-col gap-sm">
              <a className="font-body-sm text-[13px] text-on-surface-variant hover:text-primary transition-colors" href="#">About</a>
              <a className="font-body-sm text-[13px] text-on-surface-variant hover:text-primary transition-colors" href="#">Contact</a>
              <a className="font-body-sm text-[13px] text-on-surface-variant hover:text-primary transition-colors" href="#">Careers</a>
              <a className="font-body-sm text-[13px] text-on-surface-variant hover:text-primary transition-colors" href="#">Partners</a>
            </nav>
          </div>

        </div>

        <div className="max-w-container-max mx-auto px-gutter pt-xl border-t border-outline-variant/60 flex flex-col md:flex-row justify-between items-center gap-lg">
          <div className="flex gap-lg flex-wrap justify-center text-[12px]">
            <button onClick={() => setLegalModal('privacy')} className="font-body-sm text-body-sm text-on-surface-variant hover:text-primary transition-colors bg-transparent border-0 cursor-pointer p-0">Privacy Policy</button>
            <button onClick={() => setLegalModal('terms')} className="font-body-sm text-body-sm text-on-surface-variant hover:text-primary transition-colors bg-transparent border-0 cursor-pointer p-0">Terms of Service</button>
            <button onClick={() => setLegalModal('status')} className="font-body-sm text-body-sm text-on-surface-variant hover:text-primary transition-colors bg-transparent border-0 cursor-pointer p-0">System Status</button>
            <button onClick={() => setLegalModal('cookies')} className="font-body-sm text-body-sm text-on-surface-variant hover:text-primary transition-colors bg-transparent border-0 cursor-pointer p-0">Cookie Policy</button>
          </div>
          <div className="font-body-sm text-body-sm text-on-surface-variant text-[12px]">
            © 2026 LarShield. All rights reserved.
          </div>
        </div>
      </footer>

      {/* Legal Policies Modal */}
      {legalModal && (
        <div className="fixed inset-0 z-[9999] flex items-center justify-center p-4">
          <div 
            className="fixed inset-0 bg-black/60 backdrop-blur-sm transition-opacity"
            onClick={() => setLegalModal(null)}
          />
          
          <div className="bg-surface-container-lowest border border-outline-variant shadow-2xl rounded-2xl w-full max-w-2xl relative z-10 animate-fade-in flex flex-col max-h-[90vh] overflow-hidden">
            
            {/* Header */}
            <div className="flex justify-between items-center px-xl py-lg border-b border-outline-variant bg-surface-container-low/40">
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined text-primary text-[24px]">gavel</span>
                <h3 className="font-headline-sm font-bold text-on-surface text-[18px]">Legal Policies</h3>
              </div>
              <button 
                onClick={() => setLegalModal(null)}
                className="text-on-surface-variant hover:text-on-surface hover:bg-surface-container p-2 rounded-full transition-colors border-0 bg-transparent cursor-pointer flex items-center justify-center"
                title="Close"
              >
                <span className="material-symbols-outlined text-[20px]">close</span>
              </button>
            </div>

            {/* Policy Tab Switcher */}
            <div className="flex border-b border-outline-variant bg-surface-container-lowest px-xl overflow-x-auto">
              <button
                onClick={() => setLegalModal('privacy')}
                className={`py-md px-md text-[13px] font-bold border-b-2 transition-all cursor-pointer bg-transparent border-0 whitespace-nowrap ${
                  legalModal === 'privacy' 
                    ? 'border-primary text-primary' 
                    : 'border-transparent text-on-surface-variant hover:text-on-surface'
                }`}
              >
                Privacy Policy
              </button>
              <button
                onClick={() => setLegalModal('terms')}
                className={`py-md px-md text-[13px] font-bold border-b-2 transition-all cursor-pointer bg-transparent border-0 whitespace-nowrap ${
                  legalModal === 'terms' 
                    ? 'border-primary text-primary' 
                    : 'border-transparent text-on-surface-variant hover:text-on-surface'
                }`}
              >
                Terms of Service
              </button>
              <button
                onClick={() => setLegalModal('status')}
                className={`py-md px-md text-[13px] font-bold border-b-2 transition-all cursor-pointer bg-transparent border-0 whitespace-nowrap ${
                  legalModal === 'status' 
                    ? 'border-primary text-primary' 
                    : 'border-transparent text-on-surface-variant hover:text-on-surface'
                }`}
              >
                System Status
              </button>
              <button
                onClick={() => setLegalModal('cookies')}
                className={`py-md px-md text-[13px] font-bold border-b-2 transition-all cursor-pointer bg-transparent border-0 whitespace-nowrap ${
                  legalModal === 'cookies' 
                    ? 'border-primary text-primary' 
                    : 'border-transparent text-on-surface-variant hover:text-on-surface'
                }`}
              >
                Cookie Policy
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-xl overflow-y-auto max-h-[60vh] text-left">
              {legalModal === 'privacy' && (
                <div>
                  <h3 className="text-[20px] font-extrabold text-on-surface mb-1">Privacy Policy</h3>
                  <p className="text-[12px] font-bold text-primary mb-lg">Effective Date: August 15, 2026</p>
                  
                  <p className="text-[13.5px] text-on-surface-variant leading-relaxed mb-lg">
                    This Privacy Policy describes how Larshield ("we", "us", or "our") collects, uses, and shares your personal information. We are committed to complying with global data protection laws including the GDPR, CCPA, and India's DPDP Act.
                  </p>

                  <div className="space-y-md text-[13.5px] text-on-surface-variant">
                    <div>
                      <h4 className="font-bold text-on-surface text-[14px]">1. Information We Collect</h4>
                      <p className="mt-1"><strong>Account Data:</strong> Email address, name, billing information, and organization details.</p>
                      <p className="mt-1"><strong>Scan Data:</strong> Target URLs, scan configurations, identified vulnerabilities, and generated PDF reports.</p>
                      <p className="mt-1"><strong>Audit Logs:</strong> Origin IP addresses, access timestamps, and API request logs for security and compliance monitoring.</p>
                    </div>

                    <div>
                      <h4 className="font-bold text-on-surface text-[14px]">2. How We Use Your Information</h4>
                      <p className="mt-1">We use your data strictly to provide, maintain, and improve the Service, process payments, and ensure legal compliance. We do not sell your personal data or scan results to third parties.</p>
                    </div>

                    <div>
                      <h4 className="font-bold text-on-surface text-[14px]">3. Data Security</h4>
                      <p className="mt-1">Scan results and user data are encrypted at rest (AES-256) and in transit (TLS 1.3). We enforce strict role-based access controls internally. However, no internet transmission is entirely secure, and you use the Service at your own risk.</p>
                    </div>

                    <div>
                      <h4 className="font-bold text-on-surface text-[14px]">4. Your Rights (GDPR &amp; CCPA)</h4>
                      <p className="mt-1">Depending on your jurisdiction, you have the right to access, correct, delete, or restrict the processing of your personal data. You can request a complete data export or account deletion by contacting info@larxius.com.</p>
                    </div>
                  </div>
                </div>
              )}

              {legalModal === 'terms' && (
                <div>
                  <h3 className="text-[20px] font-extrabold text-on-surface mb-1">Terms of Service</h3>
                  <p className="text-[12px] font-bold text-primary mb-lg">Effective Date: August 15, 2026</p>

                  <div className="space-y-md text-[13.5px] text-on-surface-variant">
                    <div>
                      <h4 className="font-bold text-on-surface text-[14px]">1. Acceptance of Terms</h4>
                      <p className="mt-1">By accessing or using the Larshield platform (the "Service"), you agree to be bound by these Terms of Service. If you do not agree, you may not access the Service.</p>
                    </div>

                    <div>
                      <h4 className="font-bold text-on-surface text-[14px]">2. Description of Service</h4>
                      <p className="mt-1">Larshield provides automated vulnerability scanning, active penetration testing, and security posture management tools. The Service actively probes designated targets to identify security flaws, misconfigurations, and compliance violations.</p>
                    </div>

                    <div>
                      <h4 className="font-bold text-on-surface text-[14px]">3. Authorization and Legal Use</h4>
                      <p className="mt-1">You explicitly certify that you possess full, legally verifiable authorization from the system owner to conduct active security assessments against any target URL you submit. Unauthorized scanning is illegal and strictly prohibited. You assume all liability for damages resulting from unauthorized use of the Service.</p>
                    </div>

                    <div>
                      <h4 className="font-bold text-on-surface text-[14px]">4. Limitation of Liability</h4>
                      <p className="mt-1">Larshield is provided "AS IS". Vulnerability scanning can cause unintended disruptions, including data loss or system crashes. To the maximum extent permitted by law, Larshield shall not be liable for any direct, indirect, incidental, special, or consequential damages resulting from the use or inability to use the Service.</p>
                    </div>

                    <div>
                      <h4 className="font-bold text-on-surface text-[14px]">5. Termination</h4>
                      <p className="mt-1">We reserve the right to suspend or terminate your account immediately, without prior notice or liability, for any reason, including without limitation if you breach the Terms, particularly regarding unauthorized target scanning.</p>
                    </div>
                  </div>
                </div>
              )}

              {legalModal === 'status' && (
                <div>
                  <h3 className="text-[20px] font-extrabold text-on-surface mb-1">System Status</h3>
                  <p className="text-[12px] font-bold text-primary mb-lg">Effective Date: August 15, 2026</p>

                  <div className="space-y-md text-[13.5px] text-on-surface-variant">
                    <div>
                      <h4 className="font-bold text-on-surface text-[14px]">1. Uptime Commitment</h4>
                      <p className="mt-1">LarShield maintains a 99.9% uptime SLA for all scanning and reporting APIs. Maintenance windows are announced 7 days in advance.</p>
                    </div>

                    <div>
                      <h4 className="font-bold text-on-surface text-[14px]">2. Current Status</h4>
                      <div className="mt-2 p-md bg-green-500/10 border border-green-500/30 rounded-xl flex items-center gap-md text-green-600 dark:text-green-400">
                        <span className="w-3 h-3 rounded-full bg-green-500 shrink-0 animate-pulse"></span>
                        <span className="font-bold text-[13.5px]">All systems are currently operational and operating at optimal performance levels.</span>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {legalModal === 'cookies' && (
                <div>
                  <h3 className="text-[20px] font-extrabold text-on-surface mb-1">Cookie Policy</h3>
                  <p className="text-[12px] font-bold text-primary mb-lg">Effective Date: August 15, 2026</p>

                  <div className="space-y-md text-[13.5px] text-on-surface-variant">
                    <div>
                      <h4 className="font-bold text-on-surface text-[14px]">1. Essential Cookies</h4>
                      <p className="mt-1">We use strictly necessary cookies to maintain your session and ensure secure authentication. These cannot be disabled.</p>
                    </div>

                    <div>
                      <h4 className="font-bold text-on-surface text-[14px]">2. Analytics Cookies</h4>
                      <p className="mt-1">We optionally collect telemetry data to improve platform performance. You can opt-out at any time via your account settings.</p>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="flex justify-end p-xl border-t border-outline-variant bg-surface-container-low/40">
              <button
                onClick={() => setLegalModal(null)}
                className="bg-primary text-white font-bold py-2.5 px-6 rounded-xl hover:brightness-110 active:scale-95 transition-all text-sm border-0 cursor-pointer shadow-md shadow-primary/20"
              >
                I Understand
              </button>
            </div>

          </div>
        </div>
      )}
    </div>
  );
};
