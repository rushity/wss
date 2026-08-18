import React, { useState } from 'react';

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
      question: "How can I manage members in my organization?",
      answer: "If you are an Organization Admin, go to the 'Organization' settings. From there, you can invite new members via email, manage their roles (e.g., Executive User, Admin), and revoke access if necessary."
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
                className={`px-md overflow-hidden transition-all duration-300 ease-in-out ${activeFaq === index ? 'max-h-96 pb-md opacity-100' : 'max-h-0 opacity-0'}`}
              >
                <p className="text-on-surface-variant font-body-md leading-relaxed m-0 border-t border-outline-variant/30 pt-sm">
                  {faq.answer}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-lg mb-xl">
        <div className="bg-surface-container-lowest border border-outline-variant rounded-xl p-lg flex flex-col items-start gap-sm hover:shadow-md transition-shadow">
          <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center text-primary mb-xs">
            <span className="material-symbols-outlined text-[28px]">book</span>
          </div>
          <h3 className="text-lg font-bold text-on-surface m-0">Documentation</h3>
          <p className="text-on-surface-variant font-body-sm mb-md flex-1">
            Dive deep into our API references, detailed scanner methodology, and integration guides.
          </p>
          <button className="text-primary font-label-md font-bold hover:underline bg-transparent border-0 cursor-pointer p-0 flex items-center gap-xs">
            Read Docs <span className="material-symbols-outlined text-sm">arrow_forward</span>
          </button>
        </div>

        <div className="bg-surface-container-lowest border border-outline-variant rounded-xl p-lg flex flex-col items-start gap-sm hover:shadow-md transition-shadow">
          <div className="w-12 h-12 rounded-lg bg-secondary/10 flex items-center justify-center text-secondary mb-xs">
            <span className="material-symbols-outlined text-[28px]">support_agent</span>
          </div>
          <h3 className="text-lg font-bold text-on-surface m-0">Contact Support</h3>
          <p className="text-on-surface-variant font-body-sm mb-md flex-1">
            Can't find what you're looking for? Our security experts are here to help you resolve any issues.
          </p>
          <button className="text-secondary font-label-md font-bold hover:underline bg-transparent border-0 cursor-pointer p-0 flex items-center gap-xs">
            Submit a Ticket <span className="material-symbols-outlined text-sm">arrow_forward</span>
          </button>
        </div>
      </div>
    </div>
  );
};
