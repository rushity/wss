import { useState } from 'react';
import { Clipboard, Check } from 'lucide-react';

export const CodeBlock = ({ code }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy text', err);
    }
  };

  return (
    <div style={{
      position: 'relative',
      marginTop: 'var(--space-sm)',
      marginBottom: 'var(--space-sm)'
    }}>
      {/* Copy Utility Button */}
      <button
        onClick={handleCopy}
        style={{
          position: 'absolute',
          top: '8px',
          right: '8px',
          backgroundColor: 'rgba(255, 255, 255, 0.1)',
          border: 'none',
          borderRadius: '4px',
          padding: '6px',
          cursor: 'pointer',
          color: 'var(--inverse-on-surface)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          transition: 'background-color 0.2s ease',
        }}
        onMouseEnter={(e) => e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.2)'}
        onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.1)'}
        title="Copy remediation block"
      >
        {copied ? <Check size={14} color="#4caf50" /> : <Clipboard size={14} />}
      </button>

      {/* Technical monospaced text output */}
      <pre style={{
        fontFamily: 'JetBrains Mono, monospace',
        fontSize: '13px',
        backgroundColor: '#020617', // Deep obsidian dark mode code container
        color: '#e2e8f0',
        borderRadius: 'var(--rounded-md)',
        padding: '16px',
        paddingRight: '48px',
        overflowX: 'auto',
        border: '1px solid #1e293b',
        lineHeight: '1.6',
        margin: 0
      }}>
        <code>{code}</code>
      </pre>
    </div>
  );
};
