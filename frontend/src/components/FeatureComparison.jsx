import React from 'react';

const CheckIcon = () => (
  <div className="flex items-center justify-center mx-auto">
    <svg className="w-4 h-4 text-emerald-500 stroke-[3]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
    </svg>
  </div>
);

const CrossIcon = () => (
  <div className="w-5 h-5 rounded-full bg-red-100 text-red-400 flex items-center justify-center mx-auto">
    <svg className="w-3 h-3 stroke-[2.5]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
    </svg>
  </div>
);

const HalfIcon = () => (
  <div className="w-4 h-4 rounded-full bg-[#0B132B] text-white flex items-center justify-center mx-auto text-[9px] font-bold shadow-sm">
    ◐
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
    },
    {
      feature: "Automated Risk Prioritization (AI)",
      larshield: "check",
      nessus: "half",
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

  const renderCell = (type) => {
    if (type === "check") return <CheckIcon />;
    if (type === "cross") return <CrossIcon />;
    if (type === "half") return <HalfIcon />;
    return null;
  };

  return (
    <section id="comparison" className="py-4 md:py-6 bg-slate-50/50 relative border-t border-slate-200/60">
      <div className="max-w-5xl mx-auto px-3 sm:px-6">
        
        {/* Header Text */}
        <div className="text-center mb-3">
          <p className="text-slate-600 max-w-2xl mx-auto text-xs md:text-sm font-medium">
            See how LarShield compares against legacy vulnerability scanners on coverage, automation, and reporting.
          </p>
        </div>

        {/* Comparison Table Card */}
        <div className="bg-white border border-slate-200/80 rounded-2xl shadow-xl overflow-hidden">
          <div className="overflow-x-auto custom-scrollbar">
            <table className="w-full text-left border-collapse min-w-[620px]">
              
              {/* Header Row */}
              <thead>
                <tr className="bg-[#0B132B] text-white">
                  <th className="py-2.5 px-4 font-bold text-xs sm:text-sm w-[30%]">
                    Feature
                  </th>

                  {/* LarShield Column Header */}
                  <th className="py-2.5 px-3 font-extrabold text-xs sm:text-sm text-center w-[20%] bg-[#0B132B] text-sky-400">
                    <div className="flex items-center justify-center gap-1.5">
                      <div className="w-4 h-4 rounded bg-white/15 p-0.5 flex items-center justify-center border border-white/20 shrink-0">
                        <img src="/logo.png" alt="LarShield" className="w-full h-full object-contain" />
                      </div>
                      <span>LarShield</span>
                    </div>
                  </th>

                  {/* Nessus Header */}
                  <th className="py-2.5 px-3 font-bold text-xs sm:text-sm text-center w-[16%] text-slate-100">
                    <div className="flex items-center justify-center gap-1.5">
                      <div className="w-4 h-4 rounded bg-[#00A86B] text-white flex items-center justify-center font-black text-[10px] shadow-sm shrink-0">
                        N
                      </div>
                      <span>Nessus</span>
                    </div>
                  </th>

                  {/* OpenVAS Header */}
                  <th className="py-2.5 px-3 font-bold text-xs sm:text-sm text-center w-[16%] text-slate-100">
                    <div className="flex items-center justify-center gap-1.5">
                      <div className="w-4 h-4 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 flex items-center justify-center shrink-0">
                        <span className="material-symbols-outlined text-[10px]">bug_report</span>
                      </div>
                      <span>OpenVAS</span>
                    </div>
                  </th>

                  {/* Qualys Header */}
                  <th className="py-2.5 px-3 font-bold text-xs sm:text-sm text-center w-[18%] text-slate-100">
                    <div className="flex items-center justify-center gap-1.5">
                      <div className="w-4 h-4 rounded bg-[#ED1C24] text-white flex items-center justify-center font-black text-[10px] shadow-sm shrink-0">
                        Q
                      </div>
                      <span>Qualys</span>
                    </div>
                  </th>
                </tr>
              </thead>

              {/* Table Body */}
              <tbody className="divide-y divide-slate-100 text-xs sm:text-[13px]">
                {comparisonData.map((row, idx) => (
                  <tr 
                    key={idx} 
                    className={`${idx % 2 === 0 ? 'bg-white' : 'bg-slate-50/60'} hover:bg-blue-50/20 transition-colors`}
                  >
                    {/* Feature Name */}
                    <td className="py-2 px-4 font-bold text-slate-800">
                      {row.feature}
                    </td>

                    {/* LarShield Cell (Highlighted Ice-Blue Column) */}
                    <td className="py-2 px-3 text-center bg-[#E0F2FE]/60 border-x border-blue-100/50">
                      {renderCell(row.larshield)}
                    </td>

                    {/* Nessus Cell */}
                    <td className="py-2 px-3 text-center">
                      {renderCell(row.nessus)}
                    </td>

                    {/* OpenVAS Cell */}
                    <td className="py-2 px-3 text-center">
                      {renderCell(row.openvas)}
                    </td>

                    {/* Qualys Cell */}
                    <td className="py-2 px-3 text-center">
                      {renderCell(row.qualys)}
                    </td>
                  </tr>
                ))}

                {/* Pricing Row */}
                <tr className="bg-white font-bold border-t border-slate-200">
                  <td className="py-2.5 px-4 text-slate-900 text-xs sm:text-sm font-bold">
                    Pricing
                  </td>
                  
                  {/* LarShield Pricing */}
                  <td className="py-2.5 px-3 text-center bg-[#E0F2FE]/90 border-x border-blue-100 text-blue-700 text-xs sm:text-[13px] font-extrabold">
                    Affordable &amp; Flexible
                  </td>

                  {/* Nessus Pricing */}
                  <td className="py-2.5 px-3 text-center text-slate-800 font-bold text-xs sm:text-[13px]">
                    Subscription
                  </td>

                  {/* OpenVAS Pricing */}
                  <td className="py-2.5 px-3 text-center text-slate-800 font-bold text-xs sm:text-[13px]">
                    Free (Open Source)
                  </td>

                  {/* Qualys Pricing */}
                  <td className="py-2.5 px-3 text-center text-slate-800 font-bold text-xs sm:text-[13px]">
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



