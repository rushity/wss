import { useState } from 'react';
import { Link } from 'react-router-dom';

export const Help = () => {
  const [activeFaq, setActiveFaq] = useState(null);

  const toggleFaq = (index) => {
    setActiveFaq(activeFaq === index ? null : index);
  };

  return (
    <div className="max-w-6xl mx-auto w-full animate-fade-in py-md">
      <div className="mb-xl text-center pt-sm">
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

          {/* FAQ 1 */}
          <div className={`border rounded-lg overflow-hidden transition-all duration-200 ${activeFaq === 0 ? 'border-primary bg-primary/5' : 'border-outline-variant bg-surface hover:border-outline'}`}>
            <button 
              onClick={() => toggleFaq(0)}
              className="w-full text-left px-md py-md flex items-center justify-between focus:outline-none cursor-pointer border-0 bg-transparent"
            >
              <span className="font-label-lg font-bold text-on-surface pr-sm">How do I start a new security scan?</span>
              <span className="material-symbols-outlined text-on-surface-variant transition-transform duration-200" style={{ transform: activeFaq === 0 ? 'rotate(180deg)' : 'rotate(0deg)' }}>
                expand_more
              </span>
            </button>
            <div className={`px-md overflow-hidden transition-all duration-300 ease-in-out ${activeFaq === 0 ? 'max-h-[500px] pb-md opacity-100' : 'max-h-0 opacity-0'}`}>
              <p className="text-on-surface-variant font-body-md leading-relaxed m-0 border-t border-outline-variant/30 pt-sm">
                You can start a new scan by navigating to the 'New Scan' page from the sidebar. Select your target application, choose the appropriate scan intensity (Quick, Advanced, or Deep), and click 'Start Scan'. The process will begin immediately.
              </p>
            </div>
          </div>

          {/* FAQ 2 */}
          <div className={`border rounded-lg overflow-hidden transition-all duration-200 ${activeFaq === 1 ? 'border-primary bg-primary/5' : 'border-outline-variant bg-surface hover:border-outline'}`}>
            <button 
              onClick={() => toggleFaq(1)}
              className="w-full text-left px-md py-md flex items-center justify-between focus:outline-none cursor-pointer border-0 bg-transparent"
            >
              <span className="font-label-lg font-bold text-on-surface pr-sm">What is the difference between Quick, Advanced, and Deep scans?</span>
              <span className="material-symbols-outlined text-on-surface-variant transition-transform duration-200" style={{ transform: activeFaq === 1 ? 'rotate(180deg)' : 'rotate(0deg)' }}>
                expand_more
              </span>
            </button>
            <div className={`px-md overflow-hidden transition-all duration-300 ease-in-out ${activeFaq === 1 ? 'max-h-[500px] pb-md opacity-100' : 'max-h-0 opacity-0'}`}>
              <p className="text-on-surface-variant font-body-md leading-relaxed m-0 border-t border-outline-variant/30 pt-sm">
                Quick scans focus on basic security controls, SSL/TLS configurations, and surface-level misconfigurations. Advanced scans run targeted security scripts against common web vulnerabilities like the OWASP Top 10. Deep scans use our complete arsenal of fuzzers and deep-crawling tools for exhaustive analysis.
              </p>
            </div>
          </div>

          {/* FAQ 3 */}
          <div className={`border rounded-lg overflow-hidden transition-all duration-200 ${activeFaq === 2 ? 'border-primary bg-primary/5' : 'border-outline-variant bg-surface hover:border-outline'}`}>
            <button 
              onClick={() => toggleFaq(2)}
              className="w-full text-left px-md py-md flex items-center justify-between focus:outline-none cursor-pointer border-0 bg-transparent"
            >
              <span className="font-label-lg font-bold text-on-surface pr-sm">How do I download a PDF report of my scan results?</span>
              <span className="material-symbols-outlined text-on-surface-variant transition-transform duration-200" style={{ transform: activeFaq === 2 ? 'rotate(180deg)' : 'rotate(0deg)' }}>
                expand_more
              </span>
            </button>
            <div className={`px-md overflow-hidden transition-all duration-300 ease-in-out ${activeFaq === 2 ? 'max-h-[500px] pb-md opacity-100' : 'max-h-0 opacity-0'}`}>
              <p className="text-on-surface-variant font-body-md leading-relaxed m-0 border-t border-outline-variant/30 pt-sm">
                Navigate to the 'Reports' section in the sidebar. Find your completed scan in the history list, and click the 'Download PDF' button. You can also view the interactive report directly in the dashboard before downloading.
              </p>
            </div>
          </div>

          {/* FAQ 4 */}
          <div className={`border rounded-lg overflow-hidden transition-all duration-200 ${activeFaq === 3 ? 'border-primary bg-primary/5' : 'border-outline-variant bg-surface hover:border-outline'}`}>
            <button 
              onClick={() => toggleFaq(3)}
              className="w-full text-left px-md py-md flex items-center justify-between focus:outline-none cursor-pointer border-0 bg-transparent"
            >
              <span className="font-label-lg font-bold text-on-surface pr-sm">Why am I getting false positives in Single Page Applications (SPAs)?</span>
              <span className="material-symbols-outlined text-on-surface-variant transition-transform duration-200" style={{ transform: activeFaq === 3 ? 'rotate(180deg)' : 'rotate(0deg)' }}>
                expand_more
              </span>
            </button>
            <div className={`px-md overflow-hidden transition-all duration-300 ease-in-out ${activeFaq === 3 ? 'max-h-[500px] pb-md opacity-100' : 'max-h-0 opacity-0'}`}>
              <p className="text-on-surface-variant font-body-md leading-relaxed m-0 border-t border-outline-variant/30 pt-sm">
                SPAs often handle routing dynamically on the client side, which can trick traditional scanners into thinking non-existent pages are real (Soft 404s). LarShield uses advanced baseline fingerprinting to minimize these, but if you notice recurring issues, please contact support.
              </p>
            </div>
          </div>

          {/* FAQ 5: How can I manage members in my organization? */}
          <div className={`border rounded-lg overflow-hidden transition-all duration-200 ${activeFaq === 4 ? 'border-primary bg-primary/5' : 'border-outline-variant bg-surface hover:border-outline'}`}>
            <button 
              onClick={() => toggleFaq(4)}
              className="w-full text-left px-md py-md flex items-center justify-between focus:outline-none cursor-pointer border-0 bg-transparent"
            >
              <span className="font-label-lg font-bold text-on-surface pr-sm">How can I manage members in my organization?</span>
              <span className="material-symbols-outlined text-on-surface-variant transition-transform duration-200" style={{ transform: activeFaq === 4 ? 'rotate(180deg)' : 'rotate(0deg)' }}>
                expand_more
              </span>
            </button>
            <div className={`px-md overflow-hidden transition-all duration-300 ease-in-out ${activeFaq === 4 ? 'max-h-[500px] pb-md opacity-100' : 'max-h-0 opacity-0'}`}>
              <p className="text-on-surface-variant font-body-md leading-relaxed m-0 border-t border-outline-variant/30 pt-sm">
                If you are an Organization Admin, go to the 'Organization' settings. From there, you can invite new members via email, manage their roles (e.g., Executive User, Admin), and revoke access if necessary.
              </p>
            </div>
          </div>

          {/* FAQ 6: How is the Security Risk Score calculated? */}
          <div className={`border rounded-lg overflow-hidden transition-all duration-200 ${activeFaq === 5 ? 'border-primary bg-primary/5' : 'border-outline-variant bg-surface hover:border-outline'}`}>
            <button 
              onClick={() => toggleFaq(5)}
              className="w-full text-left px-md py-md flex items-center justify-between focus:outline-none cursor-pointer border-0 bg-transparent"
            >
              <span className="font-label-lg font-bold text-on-surface pr-sm">How is the Security Risk Score calculated?</span>
              <span className="material-symbols-outlined text-on-surface-variant transition-transform duration-200" style={{ transform: activeFaq === 5 ? 'rotate(180deg)' : 'rotate(0deg)' }}>
                expand_more
              </span>
            </button>
            
            <div className={`px-md overflow-hidden transition-all duration-300 ease-in-out ${activeFaq === 5 ? 'max-h-[2500px] pb-md opacity-100' : 'max-h-0 opacity-0'}`}>
              <div className="border-t border-outline-variant/30 pt-md flex flex-col gap-md text-on-surface-variant font-body-md">
                <p className="m-0 leading-relaxed">
                  This assessment utilizes an enterprise CVSS-weighted, category-capped vulnerability risk scoring algorithm. The score calculation is fully deterministic, auditable, and reproducible.
                </p>

                {/* Section 1 */}
                <div>
                  <h4 className="font-bold text-on-surface text-base mb-xs">1. Severity Base Weights & Formula</h4>
                  <p className="m-0 text-sm font-mono text-outline-variant/90 bg-surface border border-outline-variant/40 rounded px-sm py-xs inline-block mb-sm">
                    Deduction per Finding = Severity Base Weight × [0.2 + 0.8 × (CVSS / 10)] × Confidence Multiplier
                  </p>
                  <ul className="list-disc pl-md space-y-xs m-0">
                    <li><strong className="text-on-surface">Critical:</strong> 25.0 pts (CVSS Scaling Range: 0.20 - 1.00x) - Immediate threat to core business logic or full system compromise.</li>
                    <li><strong className="text-on-surface">High:</strong> 12.0 pts (CVSS Scaling Range: 0.20 - 1.00x) - Direct threat to application confidentiality or integrity.</li>
                    <li><strong className="text-on-surface">Medium:</strong> 4.0 pts (CVSS Scaling Range: 0.20 - 1.00x) - Indirect threat or security control misconfiguration.</li>
                    <li><strong className="text-on-surface">Low:</strong> 1.5 pts (CVSS Scaling Range: 0.20 - 1.00x) - Minor hardening flaw or minimal impact finding.</li>
                    <li><strong className="text-on-surface">Informational:</strong> 0.0 pts (CVSS Scaling Range: 0.00x) - Best practice advisory or design note.</li>
                  </ul>
                </div>

                {/* Section 2 */}
                <div>
                  <h4 className="font-bold text-on-surface text-base mb-xs">2. Category Deduction Caps</h4>
                  <p className="m-0 leading-relaxed mb-xs">
                    To prevent non-exploitable misconfigurations from disproportionately penalizing the overall score, category deduction caps are enforced:
                  </p>
                  <ul className="list-disc pl-md space-y-xs m-0">
                    <li><strong className="text-on-surface">Security Headers:</strong> 15.0 pts max (Capped)</li>
                    <li><strong className="text-on-surface">SSL/TLS Configuration:</strong> 15.0 pts max (Capped)</li>
                    <li><strong className="text-on-surface">HTTP Method Tampering:</strong> 12.0 pts max (Capped & Root-Cause Deduped)</li>
                    <li><strong className="text-on-surface">Cookie Security:</strong> 10.0 pts max (Capped)</li>
                    <li><strong className="text-on-surface">DNS Security:</strong> 10.0 pts max (Capped)</li>
                    <li><strong className="text-on-surface">Compliance Framework Signals:</strong> 0.0 pts (Unlinked — Reported Separately)</li>
                  </ul>
                </div>

                {/* Section 3 */}
                <div>
                  <h4 className="font-bold text-on-surface text-base mb-xs">3. Graduated Confidence Multipliers & Posture Floor</h4>
                  <ul className="list-disc pl-md space-y-xs m-0">
                    <li><strong className="text-on-surface">Confirmed / High:</strong> 1.00x Multiplier. Floor: 75 / 100 (Grade C) if 0 Critical & 0 Highs (≤ 15 Mediums).</li>
                    <li><strong className="text-on-surface">Likely:</strong> 0.60x Multiplier. Floor: 60 / 100 (Grade D) if 0 Critical & 0 Highs (&gt; 15 Mediums).</li>
                    <li><strong className="text-on-surface">Medium:</strong> 0.50x Multiplier. Floor: 55 / 100 (Grade D) if 0 Criticals (≤ 15 Mediums).</li>
                    <li><strong className="text-on-surface">Low / Unconfirmed:</strong> 0.20x Multiplier. No Floor (Grade F) if 1+ Critical Vulnerability.</li>
                  </ul>
                </div>

                {/* Section 4: Worked Calculation Examples */}
                <div>
                  <h4 className="font-bold text-on-surface text-base mb-sm">4. Worked Calculation Examples</h4>
                  <div className="flex flex-col gap-sm">

                    {/* Example 1 Card */}
                    <div className="bg-surface border border-outline-variant/60 rounded-lg p-md shadow-xs">
                      <h5 className="font-bold text-on-surface text-sm m-0 mb-xs">Example 1: Application with 15 Missing Security Headers (Capped Deduction)</h5>
                      <p className="text-xs text-on-surface-variant m-0 mb-[2px]">Raw calculation: 15 × [4.0 × (0.2 + 0.8 × 0.53) × 1.0] = 37.4 pts.</p>
                      <p className="text-xs text-on-surface-variant m-0 mb-[2px]">Category Cap applied: Security Headers deduction is capped at <strong>15.0 pts max</strong>.</p>
                      <p className="text-xs text-on-surface-variant m-0">Posture Floor rule: No Critical/High findings → Score = 100 - 15 = <strong>85 / 100 (Grade B — Good)</strong>.</p>
                    </div>

                    {/* Example 2 Card */}
                    <div className="bg-surface border border-outline-variant/60 rounded-lg p-md shadow-xs">
                      <h5 className="font-bold text-on-surface text-sm m-0 mb-xs">Example 2: Audit with 1 High, 5 Mediums, and 1 Low Finding</h5>
                      <p className="text-xs text-on-surface-variant m-0 mb-[2px]">High (No Brute-Force, CVSS 7.5): 12.0 × (0.2 + 0.8 × 0.75) × 1.0 = 9.6 pts.</p>
                      <p className="text-xs text-on-surface-variant m-0 mb-[2px]">Mediums (CORS, Cookie, DNS): Sum of capped category deductions = 15.8 pts.</p>
                      <p className="text-xs text-on-surface-variant m-0 mb-[2px]">Low (Server Header): 1.5 × (0.2 + 0.8 × 0.31) × 1.0 = 0.7 pts.</p>
                      <p className="text-xs text-on-surface-variant m-0">Total Deduction = 26.1 pts → Score = 100 - 26.1 = <strong>74 / 100 (Grade C — Fair)</strong>.</p>
                    </div>

                    {/* Example 3 Card */}
                    <div className="bg-surface border border-outline-variant/60 rounded-lg p-md shadow-xs">
                      <h5 className="font-bold text-on-surface text-sm m-0 mb-xs">Example 3: Application with Critical Blind SQL Injection (CVSS 9.8)</h5>
                      <p className="text-xs text-on-surface-variant m-0 mb-[2px]">Critical (Blind SQLi, CVSS 9.8): 25.0 × (0.2 + 0.8 × 0.98) × 1.0 = 24.6 pts.</p>
                      <p className="text-xs text-on-surface-variant m-0 mb-[2px]">High (Auth Bypass, CVSS 8.1): 12.0 × (0.2 + 0.8 × 0.81) × 1.0 = 10.2 pts.</p>
                      <p className="text-xs text-on-surface-variant m-0 mb-[2px]">Total Deduction = 34.8 pts → Posture Floor Disabled (Critical Present).</p>
                      <p className="text-xs text-on-surface-variant m-0">Final Score = 100 - 34.8 = <strong>65 / 100 (Grade D — Poor)</strong>.</p>
                    </div>

                  </div>
                </div>

              </div>
            </div>
          </div>

          {/* FAQ 7: Privacy Policy & Data Handling */}
          <div className={`border rounded-lg overflow-hidden transition-all duration-200 ${activeFaq === 6 ? 'border-primary bg-primary/5' : 'border-outline-variant bg-surface hover:border-outline'}`}>
            <button 
              onClick={() => toggleFaq(6)}
              className="w-full text-left px-md py-md flex items-center justify-between focus:outline-none cursor-pointer border-0 bg-transparent"
            >
              <span className="font-label-lg font-bold text-on-surface pr-sm">Privacy Policy & Data Handling</span>
              <span className="material-symbols-outlined text-on-surface-variant transition-transform duration-200" style={{ transform: activeFaq === 6 ? 'rotate(180deg)' : 'rotate(0deg)' }}>
                expand_more
              </span>
            </button>
            
            <div className={`px-md overflow-hidden transition-all duration-300 ease-in-out ${activeFaq === 6 ? 'max-h-[500px] pb-md opacity-100' : 'max-h-0 opacity-0'}`}>
              <div className="border-t border-outline-variant/30 pt-sm flex flex-col gap-sm text-on-surface-variant font-body-md">
                <p className="m-0 leading-relaxed">
                  We are fully committed to protecting your data and privacy. We align our data collection and handling procedures with global standards, including GDPR, CCPA, and India's DPDP Act.
                </p>
                <ul className="list-disc pl-md space-y-xs m-0">
                  <li><strong className="text-on-surface">Data Encryption:</strong> All vulnerability scan data is encrypted at rest (AES-256) and in transit (TLS 1.3).</li>
                  <li><strong className="text-on-surface">Audit Logs:</strong> To prevent abuse, we retain metadata regarding IP origins, target configurations, and timestamped actions.</li>
                  <li><strong className="text-on-surface">Third-Party Sharing:</strong> We do not sell or share your data with third parties for marketing purposes. Data is only shared with essential infrastructure providers or law enforcement if legally compelled.</li>
                </ul>
                <div className="pt-xs">
                  <Link 
                    to="/legal/privacy" 
                    className="inline-flex items-center gap-xs text-primary font-bold hover:underline font-label-md"
                  >
                    Read our full Privacy Policy <span className="material-symbols-outlined text-sm">arrow_forward</span>
                  </Link>
                </div>
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
};
