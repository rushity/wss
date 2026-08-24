import React from 'react';
import { useParams, useNavigate } from 'react-router-dom';

export const LEGAL_POLICIES = {
  terms: {
    id: 'terms',
    title: 'Terms of Service',
    effectiveDate: 'August 15, 2026',
    sections: [
      {
        number: '1',
        title: 'Acceptance of Terms',
        content: 'By accessing or using the Larshield platform (the "Service"), you agree to be bound by these Terms of Service. If you do not agree, you may not access the Service.'
      },
      {
        number: '2',
        title: 'Description of Service',
        content: 'Larshield provides automated vulnerability scanning, active penetration testing, and security posture management tools. The Service actively probes designated targets to identify security flaws, misconfigurations, and compliance violations.'
      },
      {
        number: '3',
        title: 'Authorization and Legal Use',
        content: 'You explicitly certify that you possess full, legally verifiable authorization from the system owner to conduct active security assessments against any target URL you submit. Unauthorized scanning is illegal and strictly prohibited. You assume all liability for damages resulting from unauthorized use of the Service.'
      },
      {
        number: '4',
        title: 'Limitation of Liability',
        content: 'Larshield is provided "AS IS". Vulnerability scanning can cause unintended disruptions, including data loss or system crashes. To the maximum extent permitted by law, Larshield shall not be liable for any direct, indirect, incidental, special, or consequential damages resulting from the use or inability to use the Service.'
      },
      {
        number: '5',
        title: 'Termination',
        content: 'We reserve the right to suspend or terminate your account immediately, without prior notice or liability, for any reason, including without limitation if you breach the Terms, particularly regarding unauthorized target scanning.'
      }
    ]
  },
  privacy: {
    id: 'privacy',
    title: 'Privacy Policy',
    effectiveDate: 'August 15, 2026',
    intro: 'This Privacy Policy describes how Larshield ("we", "us", or "our") collects, uses, and shares your personal information. We are committed to complying with global data protection laws including the GDPR, CCPA, and India\'s DPDP Act.',
    sections: [
      {
        number: '1',
        title: 'Information We Collect',
        content: '',
        bullets: [
          { label: 'Account Data', text: 'Email address, name, billing information, and organization details.' },
          { label: 'Scan Data', text: 'Target URLs, scan configurations, identified vulnerabilities, and generated PDF reports.' },
          { label: 'Audit Logs', text: 'Origin IP addresses, access timestamps, and API request logs for security and compliance monitoring.' }
        ]
      },
      {
        number: '2',
        title: 'How We Use Your Information',
        content: 'We use your data strictly to provide, maintain, and improve the Service, process payments, and ensure legal compliance. We do not sell your personal data or scan results to third parties.'
      },
      {
        number: '3',
        title: 'Data Security',
        content: 'Scan results and user data are encrypted at rest (AES-256) and in transit (TLS 1.3). We enforce strict role-based access controls internally. However, no internet transmission is entirely secure, and you use the Service at your own risk.'
      },
      {
        number: '4',
        title: 'Your Rights (GDPR & CCPA)',
        content: 'Depending on your jurisdiction, you have the right to access, correct, delete, or restrict the processing of your personal data. You can request a complete data export or account deletion by contacting legal@larshield.com.'
      }
    ]
  },
  aup: {
    id: 'aup',
    title: 'Acceptable Use Policy',
    subtitle: '(Rules of Engagement)',
    effectiveDate: 'August 15, 2026',
    intro: 'This Acceptable Use Policy (AUP) sets the rules of engagement for utilizing the Larshield platform. Violating this policy will result in immediate account termination and potential legal referral.',
    sections: [
      {
        number: '1',
        title: 'Prohibited Activities',
        content: '',
        bullets: [
          { label: 'Unauthorized Scanning', text: 'Scanning infrastructure, applications, or networks that you do not own or lack explicit, documented consent to test.' },
          { label: 'Denial of Service (DoS/DDoS)', text: 'Utilizing Larshield\'s infrastructure to intentionally flood, exhaust, or deny access to a target system.' },
          { label: 'Destructive Payloads', text: 'Modifying, deleting, or exfiltrating data from a target system beyond what is strictly necessary to demonstrate a proof-of-concept for a vulnerability.' },
          { label: 'Government & Healthcare Infrastructure', text: 'You may not scan government, military, emergency services, or critical healthcare infrastructure without verifying compliance with local regulations.' }
        ]
      },
      {
        number: '2',
        title: 'Abuse Prevention and Monitoring',
        content: 'Larshield implements automated heuristics to detect abuse. We reserve the right to instantly halt any active scan that triggers abuse thresholds, resembles a DoS attack, or targets known blacklisted domains.'
      }
    ]
  },
  dpa: {
    id: 'dpa',
    title: 'Data Processing Agreement (DPA)',
    effectiveDate: 'August 15, 2026',
    intro: 'This DPA forms part of the Terms of Service. It outlines our responsibilities when processing Personal Data on behalf of our enterprise customers as a "Data Processor" under the GDPR and equivalent laws.',
    sections: [
      {
        number: '1',
        title: 'Processing Scope',
        content: 'Larshield processes data solely for the purpose of executing automated security scans and generating vulnerability reports as instructed by the customer (the "Data Controller").'
      },
      {
        number: '2',
        title: 'Sub-processors',
        content: 'We utilize trusted sub-processors (e.g., Supabase for database hosting, AWS/GCP for compute resources). We ensure all sub-processors are bound by equally stringent data protection obligations.'
      },
      {
        number: '3',
        title: 'Breach Notification',
        content: 'In the event of a confirmed security breach affecting customer data, Larshield will notify affected customers without undue delay, and in any event within 72 hours of becoming aware of the breach, providing necessary details for regulatory reporting.'
      }
    ]
  },
  vdp: {
    id: 'vdp',
    title: 'Vulnerability Disclosure Policy',
    effectiveDate: 'August 15, 2026',
    intro: 'Larshield is committed to ensuring the security of our platform. We welcome and support the efforts of the independent security research community to help us improve.',
    sections: [
      {
        number: '1',
        title: 'Safe Harbor',
        content: 'We consider security research conducted under this policy to be authorized. We will not initiate legal action or law enforcement investigation against researchers who adhere to these guidelines.'
      },
      {
        number: '2',
        title: 'Guidelines',
        content: '',
        bullets: [
          { text: 'Make every effort to avoid privacy violations, degradation of user experience, or disruption to production systems.' },
          { text: 'Perform research only within the scope set out below; refrain from testing physical security, social engineering, or third-party applications.' },
          { text: 'Do not exploit a vulnerability further than necessary to establish its existence. Do not exfiltrate data.' }
        ]
      },
      {
        number: '3',
        title: 'Scope & Reporting',
        content: '',
        bullets: [
          { label: 'In Scope', text: '*.larshield.com, api.larshield.com' },
          { label: 'Out of Scope', text: 'Third-party services, DoS/DDoS attacks, Spam/Social Engineering.' }
        ],
        footerNote: 'If you believe you\'ve found a security vulnerability in Larshield, please report it to security@larshield.com. We ask for 90 days to remediate before public disclosure.'
      }
    ]
  }
};

export const LegalPage = () => {
  const { policyId } = useParams();
  const navigate = useNavigate();

  React.useEffect(() => {
    window.scrollTo(0, 0);
    const mainElement = document.querySelector('main');
    if (mainElement) mainElement.scrollTop = 0;
  }, [policyId]);

  let currentKey = (policyId || 'terms').toLowerCase();
  if (currentKey === 'tos') currentKey = 'terms';
  if (!LEGAL_POLICIES[currentKey]) currentKey = 'terms';

  const currentPolicy = LEGAL_POLICIES[currentKey];

  const navList = [
    { key: 'terms', label: 'Terms of Service', icon: 'description' },
    { key: 'privacy', label: 'Privacy Policy', icon: 'verified_user' },
    { key: 'aup', label: 'Acceptable Use Policy', icon: 'rule' },
    { key: 'dpa', label: 'Data Processing Agreement', icon: 'database' },
    { key: 'vdp', label: 'Vulnerability Disclosure', icon: 'bug_report' },
  ];

  return (
    <div className="max-w-6xl mx-auto w-full animate-fade-in py-sm">
      {/* Back Button */}
      <button
        onClick={() => navigate(-1)}
        className="inline-flex items-center gap-xs text-on-surface-variant hover:text-primary transition-colors mb-md cursor-pointer border-0 bg-transparent font-bold text-sm p-0"
      >
        <span className="material-symbols-outlined text-[20px]">arrow_back</span>
        <span>Back</span>
      </button>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-lg items-start">
        {/* Left Navigation Sidebar */}
        <div className="lg:col-span-3 flex flex-col gap-md">
          <div className="bg-surface border border-outline-variant rounded-xl p-md shadow-sm">
            <h2 className="text-lg font-bold text-on-surface mb-md px-xs">Legal & Compliance</h2>
            <nav className="flex flex-col gap-xs">
              {navList.map((item) => {
                const isActive = currentKey === item.key;
                return (
                  <button
                    key={item.key}
                    onClick={() => navigate(`/legal/${item.key}`)}
                    className={`w-full text-left px-md py-sm rounded-lg flex items-center gap-sm transition-all border-0 cursor-pointer text-body-md ${
                      isActive
                        ? 'bg-primary/10 text-primary font-bold border-l-4 border-primary'
                        : 'text-on-surface-variant hover:bg-surface-container hover:text-on-surface bg-transparent'
                    }`}
                  >
                    <span className={`material-symbols-outlined text-[20px] ${isActive ? 'text-primary' : 'text-outline'}`}>
                      {item.icon}
                    </span>
                    <span>{item.label}</span>
                  </button>
                );
              })}
            </nav>
          </div>

          {/* Legal Support Card */}
          <div className="bg-surface-container-low border border-outline-variant rounded-xl p-md shadow-sm">
            <h4 className="font-bold text-on-surface text-sm mb-xs">Need Legal Support?</h4>
            <p className="text-xs text-on-surface-variant mb-xs leading-relaxed">
              If you have questions about our policies, GDPR requests, or data handling, please contact:
            </p>
            <a
              href="mailto:legal@larshield.com"
              className="text-xs font-bold text-primary hover:underline block"
            >
              legal@larshield.com
            </a>
          </div>
        </div>

        {/* Right Policy Document Content */}
        <div className="lg:col-span-9">
          <div className="bg-surface border border-outline-variant rounded-xl p-lg md:p-xl shadow-sm min-h-[550px]">
            <h1 className="text-2xl font-bold text-on-surface mb-xs">
              {currentPolicy.title} {currentPolicy.subtitle && <span className="text-on-surface-variant text-base font-normal">{currentPolicy.subtitle}</span>}
            </h1>
            <p className="text-sm text-on-surface-variant mb-lg font-medium border-b border-outline-variant/40 pb-md">
              Effective Date: {currentPolicy.effectiveDate}
            </p>

            {currentPolicy.intro && (
              <p className="text-on-surface-variant font-body-md leading-relaxed mb-lg">
                {currentPolicy.intro}
              </p>
            )}

            <div className="flex flex-col gap-lg">
              {currentPolicy.sections.map((section) => (
                <div key={section.number} className="flex flex-col gap-xs">
                  <h3 className="text-base font-bold text-on-surface m-0">
                    {section.number}. {section.title}
                  </h3>
                  {section.content && (
                    <p className="text-on-surface-variant font-body-md leading-relaxed m-0">
                      {section.content}
                    </p>
                  )}
                  {section.bullets && (
                    <ul className="list-disc pl-md text-on-surface-variant space-y-xs my-xs font-body-md">
                      {section.bullets.map((bullet, idx) => (
                        <li key={idx} className="leading-relaxed">
                          {bullet.label && <strong className="text-on-surface">{bullet.label}: </strong>}
                          <span>{bullet.text}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                  {section.footerNote && (
                    <p className="text-on-surface-variant font-body-md leading-relaxed mt-sm italic">
                      {section.footerNote}
                    </p>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LegalPage;
