import React from 'react';

const CheckIcon = () => (
  <div className="w-6 h-6 rounded-full bg-emerald-500 text-white flex items-center justify-center shadow-sm mx-auto">
    <svg className="w-4 h-4 stroke-[3]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
    </svg>
  </div>
);

const CrossIcon = () => (
  <div className="w-6 h-6 rounded-full bg-red-100 text-red-500 flex items-center justify-center mx-auto">
    <svg className="w-3.5 h-3.5 stroke-[2.5]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
    </svg>
  </div>
);

const HalfIcon = ({ label }) => (
  <div className="flex items-center justify-center gap-1.5 mx-auto">
    <div className="w-5 h-5 rounded-full border-2 border-slate-700 relative overflow-hidden flex items-center justify-start bg-slate-100 shrink-0">
      <div className="w-1/2 h-full bg-slate-800"></div>
    </div>
    {label && <span className="text-[12px] text-on-surface-variant font-medium">({label})</span>}
  </div>
);

export const FeatureComparison = () => {
  const comparisonData = [
    {
      feature: "Real-Time Vulnerability Scanning",
      larshield: "check",
      nessus: "cross",
      openvas: "cross",
      qualys: "cross",
    },
    {
      feature: "Zero-Day Threat Intelligence",
      larshield: "check",
      nessus: "cross",
      openvas: "cross",
      qualys: "half",
      qualysLabel: "Limited",
    },
    {
      feature: "Automated Risk Prioritization (AI)",
      larshield: "check",
      nessus: "half",
      nessusLabel: "Basic",
      openvas: "cross",
      qualys: "check",
    },
    {
      feature: "Web Application Scanning (OWASP Top 10)",
      larshield: "check",
      nessus: "check",
      openvas: "check",
      qualys: "check",
    },
    {
      feature: "API Security Scanning",
      larshield: "check",
      nessus: "cross",
      openvas: "cross",
      qualys: "check",
    },
    {
      feature: "Cloud Security Scanning (AWS, Azure, GCP)",
      larshield: "check",
      nessus: "cross",
      openvas: "cross",
      qualys: "check",
    },
    {
      feature: "Network & Port Scanning",
      larshield: "check",
      nessus: "check",
      openvas: "check",
      qualys: "check",
    },
    {
      feature: "Asset Discovery & Inventory",
      larshield: "check",
      nessus: "check",
      openvas: "check",
      qualys: "check",
    },
    {
      feature: "Real-Time Alerts & Notifications",
      larshield: "check",
      nessus: "cross",
      openvas: "cross",
      qualys: "check",
    },
    {
      feature: "Automated Compliance Reporting",
      larshield: "check",
      nessus: "half",
      nessusLabel: "Limited",
      openvas: "cross",
      qualys: "check",
    },
    {
      feature: "Unified Dashboard",
      larshield: "check",
      nessus: "cross",
      openvas: "cross",
      qualys: "check",
    },
    {
      feature: "Customizable & Flexible Scans",
      larshield: "check",
      nessus: "check",
      openvas: "check",
      qualys: "check",
    },
    {
      feature: "Easy Deployment & Management",
      larshield: "check",
      nessus: "cross",
      openvas: "cross",
      qualys: "check",
    },
    {
      feature: "Affordable & Scalable for Businesses",
      larshield: "check",
      nessus: "cross",
      openvas: "check",
      qualys: "cross",
    },
  ];

  const renderCell = (type, label) => {
    if (type === "check") return <CheckIcon />;
    if (type === "cross") return <CrossIcon />;
    if (type === "half") return <HalfIcon label={label} />;
    return null;
  };

  return (
    <section id="comparison" className="py-xl md:py-2xl bg-surface relative border-t border-outline-variant/50">
      <div className="max-w-container-max mx-auto px-gutter">
        
        {/* Section Header */}
        <div className="text-center mb-xl">
          <span className="bg-primary/10 text-primary font-bold px-sm py-[4px] rounded-full text-[12px] uppercase tracking-wider mb-xs border border-primary/20 inline-block">
            Competitive Advantage
          </span>
          <h2 className="font-headline-lg text-[28px] md:text-[36px] font-extrabold text-on-surface mb-xs tracking-tight">
            How LarShield Compares
          </h2>
          <p className="font-body-md text-on-surface-variant max-w-[680px] mx-auto text-[15px] leading-relaxed">
            See why modern engineering and security teams choose LarShield over legacy vulnerability scanners.
          </p>
        </div>

        {/* Table Container */}
        <div className="bg-surface-container-lowest border border-outline-variant/80 rounded-2xl shadow-xl overflow-hidden">
          <div className="overflow-x-auto custom-scrollbar">
            <table className="w-full text-left border-collapse min-w-[760px]">
              
              {/* Header Row */}
              <thead>
                <tr className="border-b border-outline-variant/80">
                  <th className="py-md px-lg bg-[#0B0C10] text-white font-bold text-[15px] w-[30%]">
                    Feature
                  </th>

                  {/* LarShield Column Header */}
                  <th className="py-md px-md bg-gradient-to-b from-blue-600 to-blue-700 text-white font-bold text-[16px] text-center w-[20%] relative shadow-md">
                    <div className="flex items-center justify-center gap-2">
                      <div className="w-7 h-7 rounded-lg bg-white/10 p-1 flex items-center justify-center border border-white/20">
                        <img src="/logo.png" alt="LarShield" className="w-full h-full object-contain" />
                      </div>
                      <span className="tracking-tight font-display font-extrabold text-[17px] text-white">LarShield</span>
                    </div>
                  </th>

                  {/* Nessus */}
                  <th className="py-md px-md bg-[#0B0C10] text-white font-bold text-[15px] text-center w-[16.66%]">
                    <div className="flex items-center justify-center gap-2">
                      <div className="w-6 h-6 rounded-full bg-emerald-600 text-white font-black text-[12px] flex items-center justify-center shadow-inner">
                        N
                      </div>
                      <span className="font-bold">Nessus</span>
                    </div>
                  </th>

                  {/* OpenVAS */}
                  <th className="py-md px-md bg-[#0B0C10] text-white font-bold text-[15px] text-center w-[16.66%]">
                    <div className="flex items-center justify-center gap-2">
                      <div className="w-6 h-6 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 flex items-center justify-center">
                        <span className="material-symbols-outlined text-[15px]">bug_report</span>
                      </div>
                      <span className="font-bold">OpenVAS</span>
                    </div>
                  </th>

                  {/* Qualys */}
                  <th className="py-md px-md bg-[#0B0C10] text-white font-bold text-[15px] text-center w-[16.66%]">
                    <div className="flex items-center justify-center gap-2">
                      <div className="w-6 h-6 rounded-full bg-red-600 text-white font-bold text-[12px] flex items-center justify-center shadow-inner">
                        Q
                      </div>
                      <span className="font-bold">Qualys</span>
                    </div>
                  </th>
                </tr>
              </thead>

              {/* Table Body */}
              <tbody className="divide-y divide-outline-variant/40 text-[14px]">
                {comparisonData.map((row, idx) => (
                  <tr 
                    key={idx} 
                    className={`${idx % 2 === 0 ? 'bg-surface-container-lowest' : 'bg-surface/40'} hover:bg-surface-container-low/80 transition-colors`}
                  >
                    {/* Feature Name */}
                    <td className="py-3.5 px-lg font-semibold text-on-surface">
                      {row.feature}
                    </td>

                    {/* LarShield Cell (Highlighted Column) */}
                    <td className="py-3.5 px-md text-center bg-blue-50/70 border-x border-blue-100 font-bold">
                      {renderCell(row.larshield)}
                    </td>

                    {/* Nessus Cell */}
                    <td className="py-3.5 px-md text-center">
                      {renderCell(row.nessus, row.nessusLabel)}
                    </td>

                    {/* OpenVAS Cell */}
                    <td className="py-3.5 px-md text-center">
                      {renderCell(row.openvas, row.openvasLabel)}
                    </td>

                    {/* Qualys Cell */}
                    <td className="py-3.5 px-md text-center">
                      {renderCell(row.qualys, row.qualysLabel)}
                    </td>
                  </tr>
                ))}

                {/* Pricing Row */}
                <tr className="bg-surface-container-low font-bold border-t-2 border-outline-variant/60">
                  <td className="py-4 px-lg text-on-surface text-[15px]">
                    Pricing
                  </td>
                  
                  {/* LarShield Pricing */}
                  <td className="py-4 px-md text-center bg-blue-100/60 border-x border-blue-200 text-primary text-[14.5px] font-extrabold">
                    Flexible &amp; Affordable
                  </td>

                  {/* Nessus Pricing */}
                  <td className="py-4 px-md text-center text-on-surface-variant font-medium">
                    Subscription
                  </td>

                  {/* OpenVAS Pricing */}
                  <td className="py-4 px-md text-center text-on-surface-variant font-medium">
                    Free <br className="sm:hidden" />
                    <span className="text-[12px] opacity-80">(Open Source)</span>
                  </td>

                  {/* Qualys Pricing */}
                  <td className="py-4 px-md text-center text-on-surface-variant font-medium">
                    Subscription
                  </td>
                </tr>
              </tbody>

            </table>
          </div>
        </div>

      </div>
    </section>
  );
};

export default FeatureComparison;
