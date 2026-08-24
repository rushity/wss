import React, { useState } from 'react';
import { Link } from 'react-router-dom';

export const Help = () => {
  const [activeFaq, setActiveFaq] = useState(null);

  const faqs = [
    {
      question: "How do I start a new security scan?",
      answer: "You can start a new scan by navigating to the 'New Scan' page from the sidebar. Select your target application, choose the appropriate scan intensity (Quick, Advanced, or Deep), and click 'Start Scan'. The process will begin immediately."
    },
    {
      question: "What is the difference between Quick, Advanced, and Deep scans?",
      answer: "Quick scans focus on basic security controls, SSL/TLS configurations, and surface-level misconfigurations. Advanced scans run targeted security scripts against common web vulnerabilities like the OWASP Top 10. Deep scans use our complete arsenal of fuzzers and deep-crawling tools for exhaustive analysis."
    },
    {
      question: "How do I download a PDF report of my scan results?",
      answer: "Navigate to the 'Reports' section in the sidebar. Find your completed scan in the history list, and click the 'Download PDF' button. You can also view the interactive report directly in the dashboard before downloading."
    },
    {
      question: "Why am I getting false positives in Single Page Applications (SPAs)?",
      answer: "SPAs often handle routing dynamically on the client side, which can trick traditional scanners into thinking non-existent pages are real (Soft 404s). LarShield uses advanced baseline fingerprinting to minimize these, but if you notice recurring issues, please contact support."
    },
    {
      question: "How is the Security Risk Score calculated?",
      answer: `This assessment utilizes an enterprise CVSS-weighted, category-capped vulnerability risk scoring algorithm. The score calculation is fully deterministic, auditable, and reproducible.

1. Severity Base Weights & Formula
Deduction per Finding = Severity Base Weight × [0.2 + 0.8 × (CVSS / 10)] × Confidence Multiplier

• Critical: 25.0 pts (CVSS Scaling Range: 0.20 - 1.00x) - Immediate threat to core business logic or full system compromise.
• High: 12.0 pts (CVSS Scaling Range: 0.20 - 1.00x) - Direct threat to application confidentiality or integrity.
• Medium: 4.0 pts (CVSS Scaling Range: 0.20 - 1.00x) - Indirect threat or security control misconfiguration.
• Low: 1.5 pts (CVSS Scaling Range: 0.20 - 1.00x) - Minor hardening flaw or minimal impact finding.
• Informational: 0.0 pts (CVSS Scaling Range: 0.00x) - Best practice advisory or design note.

2. Category Deduction Caps
To prevent non-exploitable misconfigurations from disproportionately penalizing the overall score, category deduction caps are enforced:
• Security Headers: 15.0 pts max (Capped)
• SSL/TLS Configuration: 15.0 pts max (Capped)
• HTTP Method Tampering: 12.0 pts max (Capped & Root-Cause Deduped)
• Cookie Security: 10.0 pts max (Capped)
• DNS Security: 10.0 pts max (Capped)
• Compliance Framework Signals: 0.0 pts (Unlinked — Reported Separately)

3. Graduated Confidence Multipliers & Posture Floor
• Confirmed / High: 1.00x Multiplier. Floor: 75 / 100 (Grade C) if 0 Critical & 0 Highs (≤ 15 Mediums).
• Likely: 0.60x Multiplier. Floor: 60 / 100 (Grade D) if 0 Critical & 0 Highs (> 15 Mediums).
• Medium: 0.50x Multiplier. Floor: 55 / 100 (Grade D) if 0 Criticals (≤ 15 Mediums).
• Low / Unconfirmed: 0.20x Multiplier. No Floor (Grade F) if 1+ Critical Vulnerability.

4. Worked Calculation Examples
Example 1: Application with 15 Missing Security Headers (Capped Deduction)
• Raw calculation: 15 × [4.0 × (0.2 + 0.8 × 0.53) × 1.0] = 37.4 pts.
• Category Cap applied: Security Headers deduction is capped at 15.0 pts max.
• Posture Floor rule: No Critical/High findings → Score = 100 - 15 = 85 / 100 (Grade B — Good).

Example 2: Audit with 1 High, 5 Mediums, and 1 Low Finding
• High (No Brute-Force, CVSS 7.5): 12.0 × (0.2 + 0.8 × 0.75) × 1.0 = 9.6 pts.
• Mediums (CORS, Cookie, DNS): Sum of capped category deductions = 15.8 pts.
• Low (Server Header): 1.5 × (0.2 + 0.8 × 0.31) × 1.0 = 0.7 pts.
• Total Deduction = 26.1 pts → Score = 100 - 26.1 = 74 / 100 (Grade C — Fair).

Example 3: Application with Critical Blind SQL Injection (CVSS 9.8)
• Critical (Blind SQLi, CVSS 9.8): 25.0 × (0.2 + 0.8 × 0.98) × 1.0 = 24.6 pts.
• High (Auth Bypass, CVSS 8.1): 12.0 × (0.2 + 0.8 × 0.81) × 1.0 = 10.2 pts.
• Total Deduction = 34.8 pts → Posture Floor Disabled (Critical Present).
• Final Score = 100 - 34.8 = 65 / 100 (Grade D — Poor).`
    },
    {
      question: "Privacy Policy & Data Handling",
      answer: `We are fully committed to protecting your data and privacy. We align our data collection and handling procedures with global standards, including GDPR, CCPA, and India's DPDP Act.

• Data Encryption: All vulnerability scan data is encrypted at rest (AES-256) and in transit (TLS 1.3).
• Audit Logs: To prevent abuse, we retain metadata regarding IP origins, target configurations, and timestamped actions.
• Third-Party Sharing: We do not sell or share your data with third parties for marketing purposes. Data is only shared with essential infrastructure providers or law enforcement if legally compelled.`,
      linkText: "Read our full Privacy Policy",
      linkUrl: "/legal/privacy"
    }
  ];

  return (
    <div className="max-w-4xl mx-auto w-full animate-fade-in">
      <div className="mb-xl text-center pt-lg">
        <h1 className="text-3xl font-bold text-on-surface mb-sm">How can we help you?</h1>
        <p className="text-on-surface-variant font-body-lg max-w-2xl mx-auto">
          Search our knowledge base or browse the frequently asked questions below to find the answers you need to secure your infrastructure.
        </p>
      </div>

      <div className="bg-surface-container-low border border-outline-variant rounded-xl p-md md:p-xl mb-xl shadow-sm">
        <div className="flex items-center gap-sm border border-outline-variant bg-surface rounded-lg px-md py-sm mb-lg shadow-inner focus-within:border-primary focus-within:ring-1 focus-within:ring-primary transition-all">
          <span className="material-symbols-outlined text-outline">search</span>
          <input 
            type="text" 
            placeholder="Search for articles, guides, or troubleshooting steps..." 
            className="w-full bg-transparent border-none outline-none text-on-surface font-body-md placeholder:text-outline"
          />
        </div>

        <h2 className="text-xl font-bold text-on-surface mb-md">Frequently Asked Questions</h2>
        <div className="flex flex-col gap-sm">
          {faqs.map((faq, index) => (
            <div 
              key={index} 
              className={`border rounded-lg overflow-hidden transition-all duration-200 ${activeFaq === index ? 'border-primary bg-primary/5' : 'border-outline-variant bg-surface hover:border-outline'}`}
            >
              <button 
                onClick={() => setActiveFaq(activeFaq === index ? null : index)}
                className="w-full text-left px-md py-md flex items-center justify-between focus:outline-none cursor-pointer border-0 bg-transparent"
              >
                <span className="font-label-lg font-bold text-on-surface pr-sm">{faq.question}</span>
                <span className="material-symbols-outlined text-on-surface-variant transition-transform duration-200" style={{ transform: activeFaq === index ? 'rotate(180deg)' : 'rotate(0deg)' }}>
                  expand_more
                </span>
              </button>
              
              <div 
                className={`px-md overflow-hidden transition-all duration-300 ease-in-out ${activeFaq === index ? 'max-h-[2000px] pb-md opacity-100' : 'max-h-0 opacity-0'}`}
              >
                <div className="border-t border-outline-variant/30 pt-sm">
                  <p className="text-on-surface-variant font-body-md leading-relaxed m-0 whitespace-pre-line">
                    {faq.answer}
                  </p>
                  {faq.linkUrl && (
                    <Link 
                      to={faq.linkUrl} 
                      className="inline-flex items-center gap-xs mt-md text-primary font-bold hover:underline font-label-md"
                    >
                      {faq.linkText} <span className="material-symbols-outlined text-sm">arrow_forward</span>
                    </Link>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
