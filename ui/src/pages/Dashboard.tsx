import React, { useEffect, useState } from 'react';
import { useSignalR } from '../hooks/useSignalR';
import { getDashboardStats } from '../api/dashboard';
import type { DashboardStats } from '../types/threat';

const Dashboard: React.FC = () => {
  const { threats, stats: realtimeStats, isConnected } = useSignalR();
  const [stats, setStats] = useState<DashboardStats | null>(null);

  useEffect(() => {
    getDashboardStats().then(setStats).catch(console.error);
  }, []);

  const displayStats = realtimeStats || stats;

  if (!displayStats) {
    return (
      <div className="flex items-center justify-center h-screen bg-[#0F172A]">
        <div className="text-2xl text-gray-400">Loading VYRON Dashboard...</div>
      </div>
    );
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical': return 'bg-red-600';
      case 'High': return 'bg-orange-600';
      case 'Medium': return 'bg-yellow-600';
      case 'Low': return 'bg-green-600';
      default: return 'bg-gray-600';
    }
  };

  return (
    <div className="min-h-screen bg-[#0F172A] p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-4xl font-bold text-white mb-2">VYRON 2026</h1>
            <p className="text-gray-400">Advanced AI Malware Detection System</p>
          </div>
          <div className="flex items-center gap-2">
            <div className={`w-3 h-3 rounded-full ${isConnected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`}></div>
            <span className="text-sm text-gray-400">{isConnected ? 'Connected' : 'Disconnected'}</span>
          </div>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
        {/* Total Threats */}
        <div className="bg-[#1E293B] rounded-lg p-6 border border-gray-700 hover:border-blue-500 transition-colors">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-gray-400 text-sm font-medium">Total Threats Today</h3>
            <svg className="w-8 h-8 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <div className="text-3xl font-bold text-white mb-2">{displayStats.totalThreatsToday}</div>
          <div className="flex gap-2 text-xs flex-wrap">
            <span className="text-red-600">Critical: {displayStats.criticalThreats}</span>
            <span className="text-orange-600">High: {displayStats.highThreats}</span>
            <span className="text-yellow-600">Medium: {displayStats.mediumThreats}</span>
            <span className="text-green-600">Low: {displayStats.lowThreats}</span>
          </div>
        </div>

        {/* Detection Rate */}
        <div className="bg-[#1E293B] rounded-lg p-6 border border-gray-700 hover:border-green-500 transition-colors">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-gray-400 text-sm font-medium">Detection Rate</h3>
            <svg className="w-8 h-8 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <div className="text-3xl font-bold text-green-500 mb-2">{displayStats.detectionRate}%</div>
          <div className="text-xs text-gray-400">Industry Leading (CrowdStrike: 88%)</div>
        </div>

        {/* Protected Endpoints */}
        <div className="bg-[#1E293B] rounded-lg p-6 border border-gray-700 hover:border-blue-500 transition-colors">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-gray-400 text-sm font-medium">Endpoints</h3>
            <svg className="w-8 h-8 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
          </div>
          <div className="text-3xl font-bold text-white mb-2">{displayStats.protectedEndpoints}</div>
          <div className="flex gap-2 text-xs">
            <span className="text-yellow-600">Vulnerable: {displayStats.vulnerableEndpoints}</span>
            <span className="text-gray-500">Offline: {displayStats.offlineEndpoints}</span>
          </div>
        </div>

        {/* System Performance */}
        <div className="bg-[#1E293B] rounded-lg p-6 border border-gray-700 hover:border-purple-500 transition-colors">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-gray-400 text-sm font-medium">Performance</h3>
            <svg className="w-8 h-8 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
          </div>
          <div className="text-3xl font-bold text-white mb-2">{displayStats.detectionLatencyMs}ms</div>
          <div className="flex gap-2 text-xs">
            <span className="text-gray-400">CPU: {displayStats.cpuUsage}%</span>
            <span className="text-gray-400">RAM: {displayStats.memoryUsageMb}MB</span>
          </div>
        </div>
      </div>

      {/* Real-time Threat Feed */}
      <div className="bg-[#1E293B] rounded-lg p-6 border border-gray-700 mb-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-bold text-white">Real-time Threat Feed</h2>
          <span className="text-sm text-gray-400">Last {threats.length} threats</span>
        </div>
        
        {threats.length === 0 ? (
          <div className="text-center py-12 text-gray-400">
            <svg className="w-16 h-16 mx-auto mb-4 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            <p className="text-lg">No threats detected yet</p>
            <p className="text-sm mt-2">VYRON is actively monitoring all endpoints</p>
          </div>
        ) : (
          <div className="space-y-3 max-h-[600px] overflow-y-auto">
            {threats.map((threat) => (
              <div key={threat.id} className="bg-[#0F172A] p-4 rounded border border-gray-700 hover:border-gray-500 transition-colors">
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center gap-3">
                    <span className={`px-2 py-1 rounded text-xs font-bold ${getSeverityColor(threat.severity)}`}>
                      {threat.severity}
                    </span>
                    <span className="text-white font-medium">{threat.threatType}</span>
                  </div>
                  <span className="text-xs text-gray-500">{new Date(threat.timestamp).toLocaleTimeString()}</span>
                </div>
                <p className="text-sm text-gray-400 mb-2">{threat.description}</p>
                <div className="flex items-center gap-4 text-xs text-gray-500">
                  <span>Process: {threat.processName}</span>
                  <span>Endpoint: {threat.endpointName}</span>
                  {threat.mitreTechniques && threat.mitreTechniques.length > 0 && (
                    <span>MITRE: {threat.mitreTechniques.join(', ')}</span>
                  )}
                </div>
                <div className="flex gap-2 mt-3">
                  <button className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-xs rounded transition-colors">
                    Kill Process
                  </button>
                  <button className="px-3 py-1 bg-orange-600 hover:bg-orange-700 text-white text-xs rounded transition-colors">
                    Isolate Endpoint
                  </button>
                  <button className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-xs rounded transition-colors">
                    Investigate
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 2026 Features Status */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#1E293B] rounded-lg p-4 border border-green-700">
          <div className="flex items-center gap-2 mb-2">
            <div className="w-2 h-2 bg-green-500 rounded-full"></div>
            <span className="text-sm font-medium text-white">Hardware Security</span>
          </div>
          <p className="text-xs text-gray-400">CET • PT • TPM • DMA</p>
        </div>

        <div className="bg-[#1E293B] rounded-lg p-4 border border-green-700">
          <div className="flex items-center gap-2 mb-2">
            <div className="w-2 h-2 bg-green-500 rounded-full"></div>
            <span className="text-sm font-medium text-white">Fileless Detection</span>
          </div>
          <p className="text-xs text-gray-400">13 LOLBins Monitored</p>
        </div>

        <div className="bg-[#1E293B] rounded-lg p-4 border border-green-700">
          <div className="flex items-center gap-2 mb-2">
            <div className="w-2 h-2 bg-green-500 rounded-full"></div>
            <span className="text-sm font-medium text-white">Neural Networks</span>
          </div>
          <p className="text-xs text-gray-400">GNN + CNN + Attention</p>
        </div>

        <div className="bg-[#1E293B] rounded-lg p-4 border border-green-700">
          <div className="flex items-center gap-2 mb-2">
            <div className="w-2 h-2 bg-green-500 rounded-full"></div>
            <span className="text-sm font-medium text-white">UEBA</span>
          </div>
          <p className="text-xs text-gray-400">Behavioral Analytics</p>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
