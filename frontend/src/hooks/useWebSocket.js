import { useEffect, useRef, useState, useCallback } from 'react';
import { io } from 'socket.io-client';

const WS_URL = import.meta.env.VITE_WS_URL || 'http://localhost:5000';

export const useWebSocket = (scanId = null) => {
  const [isConnected, setIsConnected] = useState(false);
  const [logs, setLogs] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [scanProgress, setScanProgress] = useState({});
  const socketRef = useRef(null);

  useEffect(() => {
    if (!scanId) return;

    const socket = io(WS_URL, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
    });

    socketRef.current = socket;

    socket.on('connect', () => {
      setIsConnected(true);
      console.log('WebSocket connected');
      socket.emit('join_scan', { scan_id: scanId });
    });

    socket.on('disconnect', () => {
      setIsConnected(false);
      console.log('WebSocket disconnected');
    });

    socket.on('joined_scan', (data) => {
      console.log('Joined scan room:', data);
    });

    socket.on('scan_log', (data) => {
      setLogs(prev => [...prev, data]);
    });

    socket.on('vulnerability_found', (data) => {
      setVulnerabilities(prev => [...prev, data]);
    });

    socket.on('scan_progress', (data) => {
      setScanProgress(prev => ({ ...prev, ...data }));
    });

    socket.on('left_scan', (data) => {
      console.log('Left scan room:', data);
    });

    return () => {
      if (socketRef.current) {
        socket.emit('leave_scan', { scan_id: scanId });
        socket.disconnect();
      }
    };
  }, [scanId]);

  const clearLogs = useCallback(() => {
    setLogs([]);
  }, []);

  const clearVulnerabilities = useCallback(() => {
    setVulnerabilities([]);
  }, []);

  return {
    isConnected,
    logs,
    vulnerabilities,
    scanProgress,
    clearLogs,
    clearVulnerabilities,
  };
};
