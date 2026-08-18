import React from 'react';

export const ThreatGauge = ({ score }) => {
  // Score styling color bounds
  let color = 'var(--low)';
  let label = 'SECURE';
  
  if (score < 40) {
    color = 'var(--critical)';
    label = 'CRITICAL RISK';
  } else if (score < 60) {
    color = 'var(--high)';
    label = 'HIGH RISK';
  } else if (score < 80) {
    color = 'var(--medium)';
    label = 'MEDIUM WARNING';
  }

  // Radial calculation (semi circle, SVG path)
  const radius = 80;
  const strokeWidth = 10;
  const normalizedScore = Math.min(100, Math.max(0, score || 0));
  
  // Circumference for a full circle is 2 * pi * r. For semi-circle it's half.
  // We use strokeDasharray to fill the arc.
  const circumference = radius * Math.PI;
  const strokeDashoffset = circumference - (normalizedScore / 100) * circumference;

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: 'var(--space-md)'
    }}>
      <div style={{ position: 'relative', width: '200px', height: '110px' }}>
        <svg width="200" height="110" style={{ transform: 'rotate(180deg)' }}>
          {/* Base Gauge Arch (Unfilled) */}
          <circle
            cx="100"
            cy="10"
            r={radius}
            fill="none"
            stroke="var(--outline-variant)"
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeLinecap="round"
            style={{ transform: 'translate(0, 100px)' }}
          />
          {/* Filled Gauge Arch */}
          <circle
            cx="100"
            cy="10"
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            style={{
              transform: 'translate(0, 100px)',
              transition: 'stroke-dashoffset 1s cubic-bezier(0.4, 0, 0.2, 1), stroke 0.5s ease'
            }}
          />
        </svg>
        
        {/* Score & Label inside circle */}
        <div style={{
          position: 'absolute',
          bottom: '0',
          left: '0',
          right: '0',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center'
        }}>
          <span style={{
            fontSize: '36px',
            fontWeight: 700,
            letterSpacing: '-0.02em',
            color: 'var(--on-surface)',
            lineHeight: '1.0'
          }}>
            {score !== null && score !== undefined ? score : '--'}
          </span>
          <span style={{
            fontSize: '11px',
            fontFamily: 'JetBrains Mono',
            fontWeight: 600,
            color: color,
            marginTop: '4px',
            letterSpacing: '0.05em'
          }}>
            {label}
          </span>
        </div>
      </div>
    </div>
  );
};
