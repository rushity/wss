import { useWebSocket } from '../hooks/useWebSocket';

export const RealTimeScanProgress = ({ scanId }) => {
  const { isConnected, logs, vulnerabilities, scanProgress } = useWebSocket(scanId);

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'text-red-600 bg-red-50 border-red-200';
      case 'high': return 'text-orange-600 bg-orange-50 border-orange-200';
      case 'medium': return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'low': return 'text-blue-600 bg-blue-50 border-blue-200';
      default: return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getLevelColor = (level) => {
    switch (level?.toUpperCase()) {
      case 'CRITICAL': return 'text-red-600';
      case 'WARNING': return 'text-yellow-600';
      case 'ERROR': return 'text-red-600';
      case 'SUCCESS': return 'text-green-600';
      case 'INFO': return 'text-blue-600';
      default: return 'text-gray-600';
    }
  };

  if (!scanId) {
    return (
      <div className="border border-outline-variant rounded-lg p-md text-center text-on-surface-variant">
        No scan ID provided
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-md">
      {/* Connection Status */}
      <div className="flex items-center gap-sm text-sm">
        <span className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`}></span>
        <span className="text-on-surface-variant">
          {isConnected ? 'Connected' : 'Disconnected'}
        </span>
      </div>

      {/* Vulnerability Feed */}
      {vulnerabilities.length > 0 && (
        <div className="border border-outline-variant rounded-lg p-md bg-surface-container-lowest">
          <h3 className="font-label-md text-label-md text-on-surface uppercase tracking-wider mb-sm">
            Vulnerabilities Found ({vulnerabilities.length})
          </h3>
          <div className="flex flex-col gap-sm max-h-96 overflow-y-auto">
            {vulnerabilities.map((vuln, index) => (
              <div
                key={index}
                className={`border rounded p-sm ${getSeverityColor(vuln.severity)}`}
              >
                <div className="flex justify-between items-start gap-sm">
                  <div className="flex-1">
                    <div className="font-label-sm text-label-sm font-semibold">
                      {vuln.title}
                    </div>
                    <div className="font-body-sm text-body-sm text-on-surface-variant mt-xs">
                      {vuln.category} • CVSS: {vuln.cvss_score}
                    </div>
                    <div className="font-body-sm text-body-sm text-on-surface-variant mt-xs">
                      Scanner: {vuln.scanner_key}
                    </div>
                  </div>
                  <span className={`text-xs font-bold uppercase px-2 py-1 rounded ${getSeverityColor(vuln.severity)}`}>
                    {vuln.severity}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Live Logs */}
      {logs.length > 0 && (
        <div className="border border-outline-variant rounded-lg p-md bg-surface-container-lowest">
          <h3 className="font-label-md text-label-md text-on-surface uppercase tracking-wider mb-sm">
            Live Logs
          </h3>
          <div className="font-body-sm text-body-sm max-h-96 overflow-y-auto bg-surface-container p-sm rounded">
            {logs.map((log, index) => (
              <div key={index} className="mb-xs">
                <span className={`font-bold ${getLevelColor(log.level)}`}>
                  [{log.level}]
                </span>
                <span className="ml-sm text-on-surface-variant">
                  {log.message}
                </span>
                <span className="ml-sm text-outline text-xs">
                  {new Date(log.timestamp).toLocaleTimeString()}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Scan Progress */}
      {Object.keys(scanProgress).length > 0 && (
        <div className="border border-outline-variant rounded-lg p-md bg-surface-container-lowest">
          <h3 className="font-label-md text-label-md text-on-surface uppercase tracking-wider mb-sm">
            Scan Progress
          </h3>
          <div className="grid grid-cols-2 gap-sm">
            {Object.entries(scanProgress).map(([key, value]) => (
              <div key={key} className="flex flex-col">
                <span className="font-body-sm text-body-sm text-on-surface-variant capitalize">
                  {key.replace(/_/g, ' ')}
                </span>
                <span className="font-label-md text-label-md text-on-surface font-semibold">
                  {typeof value === 'number' ? value.toFixed(2) : value}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Empty State */}
      {vulnerabilities.length === 0 && logs.length === 0 && Object.keys(scanProgress).length === 0 && (
        <div className="border border-dashed border-outline-variant rounded-lg p-xl text-center">
          <div className="text-on-surface-variant font-body-md text-body-md">
            Waiting for scan data...
          </div>
          <div className="text-outline text-sm mt-sm">
            Vulnerabilities and logs will appear here as the scan progresses
          </div>
        </div>
      )}
    </div>
  );
};
