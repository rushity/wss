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
    <section id="comparison" className="py-12 md:py-16 bg-gradient-to-b from-slate-50/50 to-white relative border-t border-slate-200/70">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Section Header */}
        <div className="text-center mb-8">
          <span className="bg-blue-50 text-blue-700 font-bold px-3 py-1 rounded-full text-xs uppercase tracking-wider mb-2 border border-blue-200/60 inline-block">
            Competitive Advantage
          </span>
          <h2 className="text-2xl md:text-3xl font-extrabold text-slate-900 mb-2 tracking-tight">
            How LarShield Compares
          </h2>
          <p className="text-slate-600 max-w-2xl mx-auto text-sm md:text-base leading-relaxed">
            See why modern engineering and security teams choose LarShield over legacy vulnerability scanners.
          </p>
        </div>

        {/* Table Container */}
        <div className="bg-white border border-slate-200 rounded-2xl shadow-xl shadow-slate-200/60 overflow-hidden">
          <div className="overflow-x-auto custom-scrollbar">
            <table className="w-full text-left border-collapse min-w-[680px]">
              
              {/* Header Row */}
              <thead>
                <tr className="border-b border-slate-800">
                  <th className="py-3.5 px-5 bg-slate-900 text-white font-bold text-sm w-[34%]">
                    Feature
                  </th>

                  {/* LarShield Column Header */}
                  <th className="py-3.5 px-4 bg-gradient-to-b from-blue-600 to-blue-700 text-white font-bold text-center w-[20%] relative shadow-md">
                    <div className="flex items-center justify-center gap-2">
                      <div className="w-6 h-6 rounded-md bg-white/15 p-0.5 flex items-center justify-center border border-white/20">
                        <img src="/logo.png" alt="LarShield" className="w-full h-full object-contain" />
                      </div>
                      <span className="tracking-tight font-extrabold text-base text-white">LarShield</span>
                    </div>
                  </th>

                  {/* Nessus */}
                  <th className="py-3.5 px-4 bg-slate-900 text-white font-semibold text-sm text-center w-[15%]">
                    <div className="flex items-center justify-center gap-1.5">
                      <div className="w-5 h-5 rounded-full bg-emerald-600 text-white font-bold text-[11px] flex items-center justify-center shadow-inner">
                        N
                      </div>
                      <span>Nessus</span>
                    </div>
                  </th>

                  {/* OpenVAS */}
                  <th className="py-3.5 px-4 bg-slate-900 text-white font-semibold text-sm text-center w-[15%]">
                    <div className="flex items-center justify-center gap-1.5">
                      <div className="w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 flex items-center justify-center">
                        <span className="material-symbols-outlined text-[13px]">bug_report</span>
                      </div>
                      <span>OpenVAS</span>
                    </div>
                  </th>

                  {/* Qualys */}
                  <th className="py-3.5 px-4 bg-slate-900 text-white font-semibold text-sm text-center w-[16%]">
                    <div className="flex items-center justify-center gap-1.5">
                      <div className="w-5 h-5 rounded-full bg-red-600 text-white font-bold text-[11px] flex items-center justify-center shadow-inner">
                        Q
                      </div>
                      <span>Qualys</span>
                    </div>
                  </th>
                </tr>
              </thead>

              {/* Table Body */}
              <tbody className="divide-y divide-slate-100 text-xs sm:text-sm">
                {comparisonData.map((row, idx) => (
                  <tr 
                    key={idx} 
                    className={`${idx % 2 === 0 ? 'bg-white' : 'bg-slate-50/50'} hover:bg-blue-50/30 transition-colors`}
                  >
                    {/* Feature Name */}
                    <td className="py-2.5 px-5 font-semibold text-slate-800">
                      {row.feature}
                    </td>

                    {/* LarShield Cell (Highlighted Column) */}
                    <td className="py-2.5 px-4 text-center bg-blue-50/60 border-x border-blue-100/80 font-bold">
                      {renderCell(row.larshield)}
                    </td>

                    {/* Nessus Cell */}
                    <td className="py-2.5 px-4 text-center">
                      {renderCell(row.nessus, row.nessusLabel)}
                    </td>

                    {/* OpenVAS Cell */}
                    <td className="py-2.5 px-4 text-center">
                      {renderCell(row.openvas, row.openvasLabel)}
                    </td>

                    {/* Qualys Cell */}
                    <td className="py-2.5 px-4 text-center">
                      {renderCell(row.qualys, row.qualysLabel)}
                    </td>
                  </tr>
                ))}

                {/* Pricing Row */}
                <tr className="bg-slate-100/70 font-bold border-t-2 border-slate-200">
                  <td className="py-3 px-5 text-slate-900 text-sm">
                    Pricing Model
                  </td>
                  
                  {/* LarShield Pricing */}
                  <td className="py-3 px-4 text-center bg-blue-100/70 border-x border-blue-200/80 text-blue-700 text-xs sm:text-sm font-extrabold">
                    Flexible &amp; Affordable
                  </td>

                  {/* Nessus Pricing */}
                  <td className="py-3 px-4 text-center text-slate-600 font-medium text-xs">
                    Subscription
                  </td>

                  {/* OpenVAS Pricing */}
                  <td className="py-3 px-4 text-center text-slate-600 font-medium text-xs">
                    Free <span className="text-[11px] text-slate-500">(Open Source)</span>
                  </td>

                  {/* Qualys Pricing */}
                  <td className="py-3 px-4 text-center text-slate-600 font-medium text-xs">
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
