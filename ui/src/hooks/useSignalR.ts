import { useEffect, useState, useRef } from 'react';
import * as signalR from '@microsoft/signalr';
import type { ThreatAlert, DashboardStats } from '../types/threat';

export const useSignalR = () => {
  const [threats, setThreats] = useState<ThreatAlert[]>([]);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const connectionRef = useRef<signalR.HubConnection | null>(null);

  useEffect(() => {
    const token = localStorage.getItem('vyron_token');
    const hubUrl = import.meta.env.VITE_SIGNALR_URL || '/hubs/threats';

    const connection = new signalR.HubConnectionBuilder()
      .withUrl(hubUrl, {
        accessTokenFactory: () => token || '',
        skipNegotiation: false,
      })
      .withAutomaticReconnect()
      .configureLogging(signalR.LogLevel.Information)
      .build();

    connectionRef.current = connection;

    const startConnection = async () => {
      try {
        await connection.start();
        console.log('✅ SignalR Connected to VYRON Hub');
        setIsConnected(true);

        // Subscribe to all severity levels
        await connection.invoke('SubscribeToSeverity', 'Critical');
        await connection.invoke('SubscribeToSeverity', 'High');
        await connection.invoke('SubscribeToSeverity', 'Medium');
        await connection.invoke('SubscribeToSeverity', 'Low');
      } catch (err) {
        console.error('❌ SignalR Connection Error:', err);
        setIsConnected(false);
      }
    };

    // Handle incoming threats
    connection.on('ReceiveThreat', (threat: ThreatAlert) => {
      console.log('🚨 New Threat:', threat);
      setThreats((prev) => [threat, ...prev].slice(0, 100));

      // Show browser notification for Critical threats
      if (threat.severity === 'Critical' && Notification.permission === 'granted') {
        new Notification('VYRON - Critical Threat Detected', {
          body: `${threat.threatType}: ${threat.description}`,
          icon: '/vyron-logo.png',
          requireInteraction: true,
        });
      }
    });

    // Handle system health updates
    connection.on('ReceiveSystemHealth', (healthStats: DashboardStats) => {
      console.log('📊 Dashboard Stats Update:', healthStats);
      setStats(healthStats);
    });

    connection.onreconnecting(() => {
      console.log('🔄 SignalR Reconnecting...');
      setIsConnected(false);
    });

    connection.onreconnected(() => {
      console.log('✅ SignalR Reconnected');
      setIsConnected(true);
    });

    connection.onclose(() => {
      console.log('❌ SignalR Connection Closed');
      setIsConnected(false);
    });

    startConnection();

    // Request browser notification permission
    if (Notification.permission === 'default') {
      Notification.requestPermission();
    }

    return () => {
      connection.stop();
    };
  }, []);

  return { threats, stats, isConnected, connection: connectionRef.current };
};
